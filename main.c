#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client.h"

int main(int argc, char *argv[]) {
    ClientState state;
    char input[BUFFER_SIZE];

    client_state_init(&state);

    if (!parse_arguments(argc, argv, &state)) {
        return EXIT_FAILURE;
    }

    printf("Iniciado. DS_IP: %s, DS_PORT: %s, Peer_Port: %s\n",
           state.ds_ip, state.ds_port, state.peer_port);

    while (true) {
        printf("> ");
        if (fgets(input, sizeof(input), stdin) == NULL) {    // lê 1 linha do teclado e guarda-a em input
            break;
        }

        input[strcspn(input, "\n")] = '\0';  // substitui \n por '\0'
        process_command(input, &state);   // analisa comando escrito pelo utilizador e escolhe a operação correspondente
    }

    return EXIT_SUCCESS;
}
