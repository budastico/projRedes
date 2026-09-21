#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_DS_IP "193.136.138.142"
#define DEFAULT_DS_PORT "59000"
#define BUFFER_SIZE 1024

// Variáveis de estado global da sessão
bool is_logged_in = false;
char current_uid[7] = "";
char current_pass[9] = "";
char peer_port[6] = "";
char ds_ip[16] = DEFAULT_DS_IP;
char ds_port[6] = DEFAULT_DS_PORT;

// Função para validar se UID tem 6 dígitos
bool is_valid_uid(const char *uid) {
    if (strlen(uid) != 6) return false;
    for (int i = 0; i < 6; i++) {
        if (!isdigit(uid[i])) return false;
    }
    return true;
}

// Função para validar se password tem 8 caracteres alfanuméricos
bool is_valid_password(const char *pass) {
    if (strlen(pass) != 8) return false;
    for (int i = 0; i < 8; i++) {
        if (!isalnum(pass[i])) return false;
    }
    return true;
}

// Envia mensagem UDP e espera resposta
void send_udp_command(const char *msg) {
    int fd;
    struct sockaddr_in ds_addr;
    char buffer[BUFFER_SIZE];
    socklen_t addrlen = sizeof(ds_addr);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("Erro a criar socket UDP");
        return;
    }

    // Definir timeout de 3 segundos para o recvfrom não bloquear para sempre
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&ds_addr, 0, sizeof(ds_addr));
    ds_addr.sin_family = AF_INET;
    ds_addr.sin_port = htons(atoi(ds_port));
    inet_pton(AF_INET, ds_ip, &ds_addr.sin_addr);

    sendto(fd, msg, strlen(msg), 0, (struct sockaddr*)&ds_addr, addrlen);
    
    int n = recvfrom(fd, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr*)&ds_addr, &addrlen);
    if (n > 0) {
        buffer[n] = '\0';
        // Limpar o \n do final para não estragar a formatação do printf
        if (buffer[n-1] == '\n') buffer[n-1] = '\0';
        printf("Resposta do Servidor: %s\n", buffer);
        
        // Atualizar estado local com base na resposta
        if (strncmp(buffer, "RLI OK", 6) == 0 || strncmp(buffer, "RLI REG", 7) == 0) {
            is_logged_in = true;
        } else if (strncmp(buffer, "RLO OK", 6) == 0 || strncmp(buffer, "RUR OK", 6) == 0) {
            is_logged_in = false;
            memset(current_uid, 0, sizeof(current_uid));
            memset(current_pass, 0, sizeof(current_pass));
        }
    } else {
        printf("Erro: Sem resposta do servidor DS (Timeout).\n");
    }

    close(fd);
}

int main(int argc, char *argv[]) {
    int opt;
    bool m_flag = false;

    // Parsing da linha de comandos
    while ((opt = getopt(argc, argv, "m:n:p:")) != -1) {
        switch (opt) {
            case 'm':
                strncpy(peer_port, optarg, 5);
                m_flag = true;
                break;
            case 'n':
                strncpy(ds_ip, optarg, 15);
                break;
            case 'p':
                strncpy(ds_port, optarg, 5);
                break;
            default:
                fprintf(stderr, "Uso: %s -m peerport [-n DSIP] [-p DSport]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!m_flag) {
        fprintf(stderr, "Erro: O argumento -m peerport é obrigatório!\n");
        exit(EXIT_FAILURE);
    }

    printf("Iniciado. DS_IP: %s, DS_PORT: %s, Peer_Port: %s\n", ds_ip, ds_port, peer_port);

    char input[BUFFER_SIZE];
    char cmd[16], arg1[32], arg2[32];

    while (1) {
        printf("> ");
        if (fgets(input, sizeof(input), stdin) == NULL) break;

        // Remover newline do input
        input[strcspn(input, "\n")] = 0;
        
        int parsed = sscanf(input, "%s %s %s", cmd, arg1, arg2);

        if (strcmp(cmd, "login") == 0) {
            if (is_logged_in) {
                printf("Erro local: Já tens sessão iniciada. Faz logout primeiro.\n");
                continue;
            }
            if (parsed != 3 || !is_valid_uid(arg1) || !is_valid_password(arg2)) {
                printf("Erro local: Formato inválido. Uso: login <6-digits> <8-alnum>\n");
                continue;
            }
            char msg[BUFFER_SIZE];
            sprintf(msg, "LIN %s %s %s\n", arg1, arg2, peer_port);
            
            // Guardar credenciais temporariamente caso o login tenha sucesso
            strcpy(current_uid, arg1);
            strcpy(current_pass, arg2);
            
            send_udp_command(msg);

        } else if (strcmp(cmd, "logout") == 0) {
            if (!is_logged_in) {
                printf("Erro local: Não tens sessão iniciada.\n");
                continue;
            }
            char msg[BUFFER_SIZE];
            sprintf(msg, "LOU %s %s\n", current_uid, current_pass);
            send_udp_command(msg);

        } else if (strcmp(cmd, "unregister") == 0) {
            if (!is_logged_in) {
                printf("Erro local: Não tens sessão iniciada para desregistar.\n");
                continue;
            }
            char msg[BUFFER_SIZE];
            sprintf(msg, "UNR %s %s\n", current_uid, current_pass);
            send_udp_command(msg);

        } else if (strcmp(cmd, "exit") == 0) {
            if (is_logged_in) {
                printf("Erro local: Ainda tens sessão iniciada. Executa 'logout' primeiro.\n");
            } else {
                printf("A sair...\n");
                exit(EXIT_SUCCESS);
            }
        } else {
            printf("Comando desconhecido ou não suportado na Fase I.\n");
        }
    }
    return 0;
}