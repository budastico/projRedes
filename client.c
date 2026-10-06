#include "client.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>

#define MAX_UDP_ATTEMPTS 3
#define UDP_TIMEOUT_USEC 500000

//verificar UID
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

//verificar password
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

//enviar comando UDP para o DS
static void send_udp_command(const char *message, ClientState *state) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd == -1) {
        perror("Erro a criar socket UDP");
        return;
    }
    // Define o tempo limite para receber a resposta do servidor DS
    struct timeval timeout = {.tv_sec = 0, .tv_usec = UDP_TIMEOUT_USEC};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in ds_address = {0};
    ds_address.sin_family = AF_INET;
    ds_address.sin_port = htons(atoi(state->ds_port));
    if (inet_pton(AF_INET, state->ds_ip, &ds_address.sin_addr) != 1) {
        fprintf(stderr, "Erro: endereço IP do DS inválido.\n");
        close(socket_fd);
        return;
    }

    char response[BUFFER_SIZE]; 
    int response_length = -1;

    //corre o envio e receção de mensagens UDP até MAX_UDP_ATTEMPTS (3) vezes
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
    //timeout se response_length = -1
    if (response_length <= 0) {
        printf("Erro: Sem resposta do servidor DS (Timeout).\n");
        close(socket_fd);
        return;
    }
    //remover o '\n' do final da resposta
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
            printf("Não tens sessão iniciada.\n");
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

static void handle_login(const char *uid, const char *password,
                         ClientState *state) {
    if (!is_valid_uid(uid)) {
        printf("Erro: UID inválido. Deve ter 6 dígitos.\n");
        return;
    }
    if (!is_valid_password(password)) {
        printf("Erro: Password inválida. Deve ter 8 caracteres alfanuméricos.\n");
        return;
    }

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "LIN %s %s %s\n",
             uid, password, state->peer_port);
    snprintf(state->current_uid, sizeof(state->current_uid), "%s", uid);
    snprintf(state->current_pass, sizeof(state->current_pass), "%s", password);
    send_udp_command(message, state);
}

static void handle_logout(ClientState *state) {
    if (!state->is_logged_in) {
        printf("Erro: Não tens sessão iniciada.\n");
        return;
    }

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "LOU %s %s\n",
             state->current_uid, state->current_pass);
    send_udp_command(message, state);
}

static void handle_unregister(ClientState *state) {
    if (!state->is_logged_in) {
        printf("Erro: Não tens sessão iniciada para desregistar.\n");
        return;
    }

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "UNR %s %s\n",
             state->current_uid, state->current_pass);
    send_udp_command(message, state);
}

void client_state_init(ClientState *state) {
    memset(state, 0, sizeof(*state));
    snprintf(state->ds_ip, sizeof(state->ds_ip), "%s", DEFAULT_DS_IP);
    snprintf(state->ds_port, sizeof(state->ds_port), "%s", DEFAULT_DS_PORT);
}

bool parse_arguments(int argc, char *argv[], ClientState *state) {
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
        fprintf(stderr, "Erro: O argumento -m peerport é obrigatório!\n");
        return false;
    }

    return true;
}

void process_command(const char *input, ClientState *state) {
    char command[16] = {0};
    char arg1[32] = {0};
    char arg2[32] = {0};
    int parsed = sscanf(input, "%15s %31s %31s", command, arg1, arg2);

    if (parsed <= 0) {
        return;
    }

    if (strcmp(command, "login") == 0) {
        if (state->is_logged_in) {
            printf("Erro: Já tens sessão iniciada. Faz logout primeiro.\n");
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
    } else if (strcmp(command, "exit") == 0) {
        if (state->is_logged_in) {
            printf("Erro: Ainda tens sessão iniciada. Dá logout primeiro.\n");
        } else {
            printf("A sair...\n");
            exit(EXIT_SUCCESS);
        }
    } else {
        printf("Comando desconhecido.\n");
    }
}
