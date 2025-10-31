// AVE CHRISTUS REX!
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define TRY_PORT 3000

struct sockaddr_in *return_partial_struct() {
    struct sockaddr_in *partial_struct = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    if (partial_struct == NULL) {
        perror("malloc() selhal - return_partial_struct");
        exit(EXIT_FAILURE);
    }
    memset(partial_struct, 0, sizeof(struct sockaddr_in));

    partial_struct->sin_family = AF_INET;

    if ( inet_pton(partial_struct->sin_family, "127.0.0.1", partial_struct ) == -1) {
        perror("inet_pton() selhal - return_partial_struct");
        exit(EXIT_FAILURE);
    }

    return partial_struct;
}

void terminate(char *) {

}

int main() {
    // zkouska jestli toto bude fungovat i bez struct
    int socket_com;
    if ( (socket_com = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket() selhal - main");
        exit(EXIT_FAILURE);
    }

    // // me (client) info
    // struct sockaddr_in *result_struct = return_partial_struct();
    // result_struct->sin_port = htons(TRY_PORT);

    // server info
    struct sockaddr_in server_info_to_connect;
    server_info_to_connect.sin_family = AF_INET;
    server_info_to_connect.sin_port = htons(TRY_PORT);
    server_info_to_connect.sin_addr.s_addr = INADDR_ANY;

    // if (inet_pton(server_info_to_connect.sin_family, "127.0.0.1", &server_info_to_connect.sin_addr) == -1) {
    //     perror("inet_pton() selhal - main");
    //     exit(EXIT_FAILURE);
    // }
    // konec server info

    int yes = 1;
    if (setsockopt(socket_com, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &yes, sizeof(int)) == -1) {
        perror("setsockopt() selhal - main");
        exit(EXIT_FAILURE);
    }

    if ((connect(socket_com, (struct sockaddr *)&server_info_to_connect, sizeof(struct sockaddr_in))) == -1) {
        perror("connect() selhal - main");
        exit(EXIT_FAILURE);
    }

    while (1) {
        sleep(3);
        printf("\npripojeno");
        fflush(stdout);
    }
}
// AVE CHRISTUS REX!