// AVE CHRISTUS REX
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <ctype.h>
#include <event2/thread.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/tcp.h>

int socketfd;
int com_socket;
struct event_base *evbase;
struct bufferevent *bufevent;

void eventcb(struct bufferevent *bev, short events, void *ptr) {
    if ((BEV_EVENT_READING & events) == BEV_EVENT_READING) {
        printf("\nreading");
        fflush(stdout);
    }
    else if ((BEV_EVENT_WRITING & events) == BEV_EVENT_WRITING) {
        printf("\nwriting");
        fflush(stdout);
    }
    else if ((BEV_EVENT_ERROR & events) == BEV_EVENT_ERROR ) {
        printf("\nerror");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
}

void readcb(struct bufferevent *bufevent, void *ptr) {
    char buf[1024] = {0};

    // size_t bytes_read;
    // while (1) {
    //     bytes_read = bufferevent_read(bufevent, buf, 1024);

    //     if (bytes_read == 0) {
    //         break;
    //     }
    // }

    // printf("\n%s", buf);
    time_t time_seconds = time(NULL);
    printf("\n%ld", time_seconds);
    struct evbuffer *in = bufferevent_get_input(bufevent);
    size_t bytes_read = evbuffer_get_length(in);
    evbuffer_remove(in, buf, bytes_read);
    printf("\n%s", buf);
}

void writecb(struct bufferevent *bufevent, void *ptr) {
    printf("\nvse poslano");
}

void tick_tack(evutil_socket_t fd, short what, void *arg) {
    printf("\nhalohalo");
    fflush(stdout);
}

void *routine(void *) {
    struct event_base *evbase = event_base_new();
    struct bufferevent *bufevent = bufferevent_socket_new(evbase, com_socket, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bufevent, readcb, writecb, eventcb, NULL);
    bufferevent_enable(bufevent, EV_READ | EV_WRITE);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    // struct event_base *new_evbase = event_base_new();
    struct event *new_event = event_new(evbase, -1, EV_TIMEOUT | EV_PERSIST, tick_tack, NULL);
    event_add(new_event, &tv);
    
    event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);
}

void *accept_ftp(void *ptr) {
    com_socket = accept(socketfd, NULL, NULL);
    if (com_socket == -1) {
        perror("accept() selhal - main()");
        exit(EXIT_FAILURE);
    }

    pthread_t thread2;
    if ( pthread_create(&thread2, NULL, routine, NULL) != 0) {
        perror("pthread_create() selhal - accept_ftp");
    }
    // bufferevent_trigger_event(bufevent, EV_WRITE | EV_READ, 0);
}


int main() {
    evthread_use_pthreads();
    
    struct sockaddr_in server_struct = {.sin_family =AF_INET, .sin_port = htons(4000)};
    if ( inet_pton(server_struct.sin_family, "127.0.0.1", &server_struct.sin_addr.s_addr) != 1) {
        perror("inet_pton() selhal - main()");
        exit(EXIT_FAILURE);
    }

    socketfd = socket(server_struct.sin_family, SOCK_STREAM, 0);
    if (socketfd == -1) {
        perror("socket() selhal - main()");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        perror("setsockopt() selhal - main");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(socketfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) == -1) {
        perror("setsockopt() selhal - main");
        exit(EXIT_FAILURE);
    }

    if (bind(socketfd, (struct sockaddr *)&server_struct, sizeof(server_struct)) == -1) {
        perror("bind() selhal - main");
        exit(EXIT_FAILURE);
    }

    if (listen(socketfd, 5) == -1) {
        perror("listen() selhal - main()");
        exit(EXIT_FAILURE);
    }

    pthread_t thread1;
    if ( pthread_create(&thread1, NULL, accept_ftp, NULL) != 0) {
        perror("pthread_create() selhal - main");
    }

    while (1) {
        
    }

    
    return 0;
}
// AVE CHRISTUS REX