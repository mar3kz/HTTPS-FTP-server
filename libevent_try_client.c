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
#include <fcntl.h>
#include <netinet/tcp.h>

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
    printf("readcb\n");
    size_t bytes_read;
    while (1) {
        bytes_read = bufferevent_read(bufevent, buf, 1024);
        printf("/nbytes_read: %zu", bytes_read);
        fflush(stdout);

        if (bytes_read == 0) {
            break;
        }
    }

    printf("\n%s", buf);
}

void writecb(struct bufferevent *bufevent, void *ptr) {
    // printf("\nvse poslano");
}


void *routine(void *ptr) {
    int i = 1;
    time_t time_seconds;
    // while (1) {
    //     sleep(2);
    //     printf("\n%d", i);
    //     fflush(stdout);
    //     time_seconds = time(NULL);
    // sleep(5);
    // bufferevent_lock(bufevent);
    if (bufferevent_write(bufevent, "AVE CHRISTUS REX", strlen("AVE CHRISTUS REX") + 1) == -1) {
        perror("bufferevent_write() selhal - routine()");
        exit(EXIT_FAILURE);
    }
    
        // bufferevent_unlock(bufevent);
    //     printf("\n%ld", time_seconds);
    //     i++;
    // }
    

    if (bufferevent_flush(bufevent, EV_WRITE, BEV_FLUSH | BEV_FINISHED) == -1) {
        perror("bufferevent_flush() selhal - routine");
        exit(EXIT_FAILURE);
    }

    // int i = 0;
    // while (1)
    // {
    //     if (i == 10) {
    //         break;
    //     }
    //     bufferevent_trigger_event(bufevent, EV_WRITE, 0);
    //     i++;
    // }
    

    printf("\nposlano");
    fflush(stdout);
   
}
int main() {
    evthread_use_pthreads();

    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketfd < 0) {
        perror("socket() selhal - main");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_info = {.sin_family=AF_INET, .sin_port=htons(4000)};
    if ( inet_pton(server_info.sin_family, "127.0.0.1", &server_info.sin_addr.s_addr) != 1) {
        perror("inet_pton() selhal - main()");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(socketfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) == -1) {
        perror("setsockopt() selhal - main");
        exit(EXIT_FAILURE);
    }

    evbase = event_base_new();
    bufevent = bufferevent_socket_new(evbase, socketfd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bufevent, readcb, writecb, eventcb, NULL);
    bufferevent_enable(bufevent, EV_READ | EV_WRITE | EV_PERSIST);
   
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    // struct event_base *new_evbase = event_base_new();
    struct event *new_event = event_new(evbase, -1, EV_SIGNAL | EV_PERSIST, NULL, NULL);
    event_add(new_event, NULL);
    // event_del(new_event);

    if (connect(socketfd, (struct sockaddr *)&server_info, sizeof(server_info)) == -1) {
        perror("connect() selhal - main");
        exit(EXIT_FAILURE);
    }

    pthread_t thread1;
    void *(*f_pointer)(void *) = &routine;
    if (pthread_create(&thread1, NULL, f_pointer, NULL) != 0) {
        perror("pthread_create() selhal - main()");
        exit(EXIT_FAILURE);
    }

    event_base_loop(evbase, EVLOOP_NO_EXIT_ON_EMPTY);

}
// AVE CHRISTUS REX