#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mqueue.h>
#include <unistd.h>

// message queues jsou urceny pro INTER PROCESS nebo INTER THREAD communication => kdyz se otevre stejna message queue v ruznych procesech/threads, tak se k nim opravdu dostaneme, pokud neunlinknu tu message queue, tak zustane otevrena i kdyz ten proces skonci (nemelo by to tak byt ale prave proto jsem tenhle soubor vytvoril with God's grace abych to zkusil)
int main() {
    mqd_t queue_test;
    if ( (queue_test = mq_open("/test", O_RDWR | O_CREAT, 0777, NULL)) == -1) {
        perror("mq_open() selhal - main");
        exit(EXIT_FAILURE);
    }
    mq_open("/testtest", O_RDWR | O_CREAT, 0777, NULL);

    while(1) {
        sleep(10);
        break;
    }

    // if (mq_unlink("/queue_test") == -1) {
    //     perror("mq_unlink() selhal - main");
    //     exit(EXIT_FAILURE);
    // }

    return 0;
}