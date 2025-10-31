// AVE CHRISTUS REX!
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define TRY_PORT 3000

int main() {
    // me (server) info
    struct sockaddr_in server_info_to_connect;
    server_info_to_connect.sin_family = AF_INET;
    server_info_to_connect.sin_port = htons(TRY_PORT);
    // server_info_to_connect.sin_addr.s_addr = INADDR_ANY; // INADDR_ANY se dava rovnou do toho uint32_t, protoze INADDR_ANY je definovano jako uint32_t
    // inet_pton() se dava do sin_addr, protoze to chceme !struct!, kde je ulozena IP adresa, to je sin.addr
    if (inet_pton(server_info_to_connect.sin_family, "127.0.0.1", &server_info_to_connect.sin_addr) == -1) {
        perror("inet_pton() selhal - main");
        exit(EXIT_FAILURE);
    }

    // zkouska jestli toto bude fungovat i bez struct
    int socket_com;
    if ( (socket_com = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket() selhal - main");
        exit(EXIT_FAILURE);
    }

    if (bind(socket_com, (struct sockaddr *)&server_info_to_connect, sizeof(server_info_to_connect)) == -1) {
        perror("bind() selhal - main");
        exit(EXIT_FAILURE);
    }

    int yes = 1;
    if (setsockopt(socket_com, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &yes, sizeof(int)) == -1) {
        perror("setsockopt() selhal - main");
        exit(EXIT_FAILURE);
    }

    if (listen(socket_com, 5) == -1) {
        perror("listen() selhal - main");
        exit(EXIT_FAILURE);
    }

    int new_socket_com;
    if ( (new_socket_com = accept(socket_com, NULL, NULL)) == -1) {
        perror("accept() selhal - main");
        exit(EXIT_FAILURE);
    }

    while (1) {
        sleep(3);
        printf("\npripojeno");
        fflush(stdout);
    }
}
// AVE CHRISTUS REX!