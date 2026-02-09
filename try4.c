#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <event2/event.h>
#include <event2/bufferevent.h>

struct New_Struct {
    char *p;
    struct bufferevent *bufevent;
    struct event_base *evbase;
};
struct New_Struct new_struct;

int main() {
    // new_struct.p = malloc(10);
    // memset(new_struct.p, 0, 10);
    // free(new_struct.p);

    // new_struct.p = malloc(10);
    // memset(new_struct.p, 0, 10);

    // new_struct.evbase = event_base_new();
    // new_struct.bufevent = bufferevent_socket_new(new_struct.evbase, -1, BEV_OPT_CLOSE_ON_FREE);
    // bufferevent_free(new_struct.bufevent);
    // event_base_free(new_struct.evbase);

    // new_struct.evbase = event_base_new();
    // new_struct.bufevent = bufferevent_socket_new(new_struct.evbase, -1, BEV_OPT_CLOSE_ON_FREE);

    char *p = strdup("ahoj");
    printf("value of p: %s, address of p: %p", p, (void *)p);
    fflush(stdout);

    free(p);
    printf("\np freed");
    fflush(stdout);
    
    return 0;
}