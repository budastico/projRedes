#include "client.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <unistd.h>

#define MAX_UDP_ATTEMPTS 3
#define UDP_TIMEOUT_USEC 500000

// Valida o UID antes de o enviar para o Directory Server.
static bool is_valid_uid(const char *uid) {
    if (strlen(uid) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (!isdigit((unsigned char)uid[i])) {
            return false;
        }
    }
    return true;
}

// Valida a password usada nos comandos que exigem autenticacao.
static bool is_valid_password(const char *password) {
    if (strlen(password) != 8) {
        return false;
    }
    for (int i = 0; i < 8; i++) {
        if (!isalnum((unsigned char)password[i])) {
            return false;
        }
    }
    return true;
}

// Verifica o nome local antes de publicar ou pedir um recurso.
// O protocolo aceita nomes alfanumericos com '+', '-', '_' e '.'.
static bool is_valid_filename(const char *filename) {
    size_t length = strlen(filename);

    if (length == 0 || length > 24) {
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        unsigned char character = (unsigned char)filename[i];
        if (!isalnum(character) && character != '+' && character != '-' &&
            character != '_' && character != '.') {
            return false;
        }
    }

    return true;
}

// Converte a resposta LST numa lista legivel para o utilizador.
static void print_resource_list(const char *response) {
    char list[BUFFER_SIZE];
    snprintf(list, sizeof(list), "%s", response + 7);

    printf("Recursos disponiveis:\n");
    char *filename = strtok(list, " ");
    while (filename != NULL) {
        printf("- %s\n", filename);
        filename = strtok(NULL, " ");
    }
}

static bool configure_address(struct sockaddr_in *address,
                              const ClientState *state) {
    // A configuracao do endereco ficou separada para ser usada por UDP e TCP.
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons((uint16_t)atoi(state->ds_port));

    if (inet_pton(AF_INET, state->ds_ip, &address->sin_addr) != 1) {
        fprintf(stderr, "Erro: endereco IP do DS invalido.\n");
        return false;
    }

    return true;
}

static void print_versions(const char *response) {
    char copy[BUFFER_SIZE];
    snprintf(copy, sizeof(copy), "%s", response);

    char *save_pointer = NULL;
    char *token = strtok_r(copy, " ", &save_pointer);
    char *status = token != NULL ? strtok_r(NULL, " ", &save_pointer) : NULL;

    if (status == NULL || strcmp(status, "OK") != 0) {
        printf("Nao existem versoes disponiveis para este recurso.\n");
        return;
    }

    printf("Versoes disponiveis:\n");
    // Cada versao recebida contem UID, tamanho, label, data e disponibilidade.
    while ((token = strtok_r(NULL, " ", &save_pointer)) != NULL) {
        printf("%s", token);
        token = strtok_r(NULL, " ", &save_pointer);
        if (token == NULL) {
            break;
        }
        printf(" %s", token);
        token = strtok_r(NULL, " ", &save_pointer);
        if (token == NULL) {
            break;
        }
        printf(" %s", token);
        token = strtok_r(NULL, " ", &save_pointer);
        if (token == NULL) {
            break;
        }
        printf(" %s", token);
        token = strtok_r(NULL, " ", &save_pointer);
        if (token == NULL) {
            break;
        }
        printf(" %s\n", token);
    }
}

// Envia o comando UDP e trata a resposta do DS.
static void send_udp_command(const char *message, ClientState *state) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd == -1) {
        perror("Erro a criar socket UDP");
        return;
    }
    // Antes havia apenas uma espera; agora sao feitas tres tentativas de 0.5s.
    struct timeval timeout = {.tv_sec = 0, .tv_usec = UDP_TIMEOUT_USEC};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in ds_address;
    if (!configure_address(&ds_address, state)) {
        close(socket_fd);
        return;
    }

    char response[BUFFER_SIZE]; 
    int response_length = -1;

    // Reenvia a mensagem ate MAX_UDP_ATTEMPTS (3) vezes.
    for (int attempt = 0; attempt < MAX_UDP_ATTEMPTS; attempt++) {
        socklen_t address_length = sizeof(ds_address);
        sendto(socket_fd, message, strlen(message), 0,
               (struct sockaddr *)&ds_address, address_length);

        response_length = recvfrom(socket_fd, response, sizeof(response) - 1, 0,
                                   (struct sockaddr *)&ds_address,
                                   &address_length);
        if (response_length > 0) {
            break;
        }
    }
    // Se nao houver resposta depois das tentativas, considera-se timeout.
    if (response_length <= 0) {
        printf("Erro: Sem resposta do servidor DS (Timeout).\n");
        close(socket_fd);
        return;
    }
    // Remove o '\n' do final da resposta para nao afetar o printf.
    response[response_length] = '\0';
    if (response[response_length - 1] == '\n') {
        response[response_length - 1] = '\0';
    }

    if (strncmp(response, "RLI", 3) == 0) {
        if (strncmp(response + 4, "OK", 2) == 0) {
            printf("Login bem-sucedido.\n");
        } else if (strncmp(response + 4, "REG", 3) == 0) {
            printf("Registado com sucesso.\n");
        } else if (strncmp(response + 4, "NOK", 3) == 0) {
            printf("Password incorreta.\n");
        }
    } else if (strncmp(response, "RLO", 3) == 0) {
        if (strncmp(response + 4, "OK", 2) == 0) {
            printf("Logout bem-sucedido.\n");
        } else if (strncmp(response + 4, "NLG", 3) == 0) {
            printf("Nao tens sessao iniciada.\n");
        } else if (strncmp(response + 4, "WRP", 3) == 0) {
            printf("Password incorreta.\n");
        }
    } else if (strncmp(response, "RUR", 3) == 0) {
        if (strncmp(response + 4, "OK", 2) == 0) {
            printf("Registo cancelado com sucesso.\n");
        } else if (strncmp(response + 4, "NOK", 3) == 0) {
            printf("Nao tens sessao iniciada.\n");
        } else if (strncmp(response + 4, "WRP", 3) == 0) {
            printf("Password incorreta.\n");
        }
    } else if (strncmp(response, "RPB", 3) == 0) {
        if (strncmp(response + 4, "OK", 2) == 0) {
            printf("Recurso publicado com sucesso.\n");
        } else if (strncmp(response + 4, "NLG", 3) == 0) {
            printf("Erro: Nao tens sessao iniciada.\n");
        } else if (strncmp(response + 4, "WRP", 3) == 0) {
            printf("Erro: Password incorreta.\n");
        } else {
            printf("Erro: Nao foi possivel publicar o recurso.\n");
        }
    } else if (strncmp(response, "RRM", 3) == 0) {
        if (strncmp(response + 4, "OK", 2) == 0) {
            printf("Recurso removido com sucesso.\n");
        } else if (strncmp(response + 4, "NLG", 3) == 0) {
            printf("Erro: Nao tens sessao iniciada.\n");
        } else if (strncmp(response + 4, "WRP", 3) == 0) {
            printf("Erro: Password incorreta.\n");
        } else if (strncmp(response + 4, "NOK", 3) == 0) {
            printf("Erro: O recurso nao esta publicado por este utilizador.\n");
        } else {
            printf("Erro: Nao foi possivel remover o recurso.\n");
        }
    } else if (strncmp(response, "RLS OK", 6) == 0) {
        print_resource_list(response);
    } else if (strncmp(response, "RLS NOK", 7) == 0) {
        printf("Nao existem recursos publicados.\n");
    } else {
        printf("Resposta desconhecida do DS: %s\n", response);
    }

    if (strncmp(response, "RLI OK", 6) == 0 ||
        strncmp(response, "RLI REG", 7) == 0) {
        state->is_logged_in = true;
    } else if (strncmp(response, "RLO OK", 6) == 0 ||
               strncmp(response, "RUR OK", 6) == 0) {
        state->is_logged_in = false;
        state->current_uid[0] = '\0';
        state->current_pass[0] = '\0';
    }

    close(socket_fd);
}

static bool receive_tcp_line(int socket_fd, char *buffer, size_t buffer_size) {
    // Le uma resposta TCP ate ao '\n', porque TCP nao preserva fronteiras
    // entre mensagens como acontece com UDP.
    size_t length = 0;

    while (length + 1 < buffer_size) {
        char character;
        ssize_t received = recv(socket_fd, &character, 1, 0);
        if (received == 0) {
            break;
        }
        if (received < 0) {
            return false;
        }
        if (character == '\n') {
            break;
        }
        buffer[length++] = character;
    }

    buffer[length] = '\0';
    return length > 0;
}

// O comando versions usa TCP, ao contrario dos comandos UDP anteriores.
static void handle_versions(const char *filename, ClientState *state) {
    if (!is_valid_filename(filename)) {
        printf("Erro: Nome de ficheiro invalido (maximo 24 caracteres).\n");
        return;
    }

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("Erro a criar socket TCP");
        return;
    }

    struct timeval timeout = {.tv_sec = 0, .tv_usec = UDP_TIMEOUT_USEC};
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in ds_address;
    if (!configure_address(&ds_address, state) ||
        connect(socket_fd, (struct sockaddr *)&ds_address,
                sizeof(ds_address)) == -1) {
        perror("Erro ao ligar ao DS por TCP");
        close(socket_fd);
        return;
    }

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "VRS %s\n", filename);
    if (send(socket_fd, message, strlen(message), 0) < 0) {
        perror("Erro ao enviar pedido de versoes");
        close(socket_fd);
        return;
    }

    char response[BUFFER_SIZE];
    if (!receive_tcp_line(socket_fd, response, sizeof(response))) {
        printf("Erro: Sem resposta do servidor DS (Timeout).\n");
    } else if (strncmp(response, "RVR", 3) == 0) {
        print_versions(response);
    } else {
        printf("Resposta invalida do DS: %s\n", response);
    }

    close(socket_fd);
}

static void handle_login(const char *uid, const char *password,
                         ClientState *state) {
    if (!is_valid_uid(uid)) {
        printf("Erro: UID invalido. Deve ter 6 digitos.\n");
        return;
    }
    if (!is_valid_password(password)) {
        printf("Erro: Password invalida. Deve ter 8 caracteres alfanumericos.\n");
        return;
    }

    // Guarda temporariamente as credenciais para logout e unregister.
    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "LIN %s %s %s\n",
             uid, password, state->peer_port);
    snprintf(state->current_uid, sizeof(state->current_uid), "%s", uid);
    snprintf(state->current_pass, sizeof(state->current_pass), "%s", password);
    send_udp_command(message, state);
}

static void handle_logout(ClientState *state) {
    if (!state->is_logged_in) {
        printf("Erro: Nao tens sessao iniciada.\n");
        return;
    }

    // O DS usa as credenciais guardadas para terminar a sessao atual.
    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "LOU %s %s\n",
             state->current_uid, state->current_pass);
    send_udp_command(message, state);
}

static void handle_unregister(ClientState *state) {
    if (!state->is_logged_in) {
        printf("Erro: Nao tens sessao iniciada para desregistar.\n");
        return;
    }

    // O unregister tambem termina a sessao quando o DS responde OK.
    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "UNR %s %s\n",
             state->current_uid, state->current_pass);
    send_udp_command(message, state);
}

static void handle_publish(const char *filename, const char *label,
                           ClientState *state) {
    if (!state->is_logged_in) {
        printf("Erro: Nao tens sessao iniciada.\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Erro: Nome de ficheiro invalido (maximo 24 caracteres).\n");
        return;
    }

    // O DS guarda apenas os metadados; o ficheiro continua local.
    struct stat file_info;
    if (stat(filename, &file_info) != 0 || !S_ISREG(file_info.st_mode)) {
        printf("Erro: O ficheiro nao existe ou nao e valido.\n");
        return;
    }
    if (file_info.st_size > 10000000) {
        printf("Erro: O ficheiro nao pode exceder 10 MB.\n");
        return;
    }

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "PUB %s %s %s %lld %s\n",
             state->current_uid, state->current_pass, filename,
             (long long)file_info.st_size, label);
    send_udp_command(message, state);
}

static void handle_remove(const char *filename, ClientState *state) {
    if (!state->is_logged_in) {
        printf("Erro: Nao tens sessao iniciada.\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Erro: Nome de ficheiro invalido (maximo 24 caracteres).\n");
        return;
    }

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "REM %s %s %s\n",
             state->current_uid, state->current_pass, filename);
    send_udp_command(message, state);
}

static void handle_list(ClientState *state) {
    // O list nao exige login e apenas pede os nomes conhecidos pelo DS.
    (void)state;
    send_udp_command("LST\n", state);
}

void client_state_init(ClientState *state) {
    // Inicializa o estado e aplica os valores por defeito do enunciado.
    memset(state, 0, sizeof(*state));
    snprintf(state->ds_ip, sizeof(state->ds_ip), "%s", DEFAULT_DS_IP);
    snprintf(state->ds_port, sizeof(state->ds_port), "%s", DEFAULT_DS_PORT);
}

bool parse_arguments(int argc, char *argv[], ClientState *state) {
    // O peer port e obrigatorio; IP e porta do DS podem usar os defaults.
    int option;
    bool has_peer_port = false;

    while ((option = getopt(argc, argv, "m:n:p:")) != -1) {
        switch (option) {
            case 'm':
                snprintf(state->peer_port, sizeof(state->peer_port), "%s", optarg);
                has_peer_port = true;
                break;
            case 'n':
                snprintf(state->ds_ip, sizeof(state->ds_ip), "%s", optarg);
                break;
            case 'p':
                snprintf(state->ds_port, sizeof(state->ds_port), "%s", optarg);
                break;
            default:
                fprintf(stderr, "Uso: %s -m peerport [-n DSIP] [-p DSport]\n",
                        argv[0]);
                return false;
        }
    }

    if (!has_peer_port) {
        fprintf(stderr, "Erro: O argumento -m peerport e obrigatorio!\n");
        return false;
    }

    return true;
}

void process_command(const char *input, ClientState *state) {
    char command[16] = {0};
    char arg1[32] = {0};
    char arg2[32] = {0};
    int parsed = sscanf(input, "%15s %31s %31s", command, arg1, arg2);

    // Antes o main tratava os comandos diretamente; agora esta funcao
    // separa o texto e encaminha cada comando para o respetivo handler.
    if (parsed <= 0) {
        return;
    }

    if (strcmp(command, "login") == 0) {
        if (state->is_logged_in) {
            printf("Erro: Ja tens sessao iniciada. Faz logout primeiro.\n");
            return;
        }
        if (parsed != 3) {
            printf("Erro: Comando login requer UID e password.\n");
            return;
        }
        handle_login(arg1, arg2, state);
    } else if (strcmp(command, "logout") == 0) {
        handle_logout(state);
    } else if (strcmp(command, "unregister") == 0) {
        handle_unregister(state);
    } else if (strcmp(command, "publish") == 0) {
        if (parsed != 3) {
            printf("Erro: Comando publish requer filename e label.\n");
            return;
        }
        handle_publish(arg1, arg2, state);
    } else if (strcmp(command, "remove") == 0) {
        if (parsed != 2) {
            printf("Erro: Comando remove requer filename.\n");
            return;
        }
        handle_remove(arg1, state);
    } else if (strcmp(command, "list") == 0) {
        if (parsed != 1) {
            printf("Erro: Comando list nao requer argumentos.\n");
            return;
        }
        handle_list(state);
    } else if (strcmp(command, "versions") == 0) {
        if (parsed != 2) {
            printf("Erro: Comando versions requer filename.\n");
            return;
        }
        handle_versions(arg1, state);
    } else if (strcmp(command, "exit") == 0) {
        if (state->is_logged_in) {
            printf("Erro: Ainda tens sessao iniciada. Da logout primeiro.\n");
        } else {
            printf("A sair...\n");
            exit(EXIT_SUCCESS);
        }
    } else {
        printf("Comando desconhecido.\n");
    }
}
