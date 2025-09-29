#include <stdio.h>
#include <stdlib.h>
#include <mqueue.h>
#include <string.h>
#include <errno.h>

int main() {
    if (mq_unlink("/control_queue_server") == -1) {
        if (errno == ENOENT) {
            fprintf(stderr, "/control_queue_server neslo unlinkout - neni vytvorena\n");
        }
        else {
            perror("mq_unlink() selhal - /control_queue_server");
            exit(EXIT_FAILURE);
        } 
    }
    if (mq_unlink("/data_queue_server") == -1) {
        if (errno == ENOENT) {
            fprintf(stderr, "/data_queue_server neslo unlinkout - neni vytvorena\n");
        }
        else {
            perror("mq_unlink() selhal - /data_queue_server");
            exit(EXIT_FAILURE);
        }
    }

    if (mq_unlink("/control_queue_client") == -1) {
        if (errno == ENOENT) {
            fprintf(stderr, "/control_queue_client neslo unlinkout - neni vytvorena\n");
        }
        else {
            perror("mq_unlink() selhal - /control_queue_client");
            exit(EXIT_FAILURE);
        } 
    }
    if (mq_unlink("/data_queue_client") == -1) {
        if (errno == ENOENT) {
            fprintf(stderr, "/data_queue_client neslo unlinkout - neni vytvorena\n");
        }
        else {
            perror("mq_unlink() selhal - /data_queue_client");
            exit(EXIT_FAILURE);
        } 
    }

    return 0;
}