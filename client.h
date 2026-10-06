#ifndef CLIENT_H
#define CLIENT_H

#include <stdbool.h>

#define DEFAULT_DS_IP "193.136.138.142"
#define DEFAULT_DS_PORT "59000"
#define BUFFER_SIZE 1024

typedef struct {
    bool is_logged_in;
    char current_uid[7];
    char current_pass[9];
    char peer_port[6];
    char ds_ip[16];
    char ds_port[6];
} ClientState;

void client_state_init(ClientState *state);
bool parse_arguments(int argc, char *argv[], ClientState *state);
void process_command(const char *input, ClientState *state);

#endif
