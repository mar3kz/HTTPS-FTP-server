#ifndef QUEUES
#define QUEUES

struct mq_attr global_mq_setting;
#define CONTROL_QUEUE_NAME "/control_queue_server"
#define DATA_QUEUE_NAME "/data_queue_server"
int QUEUE_MESSAGE_LEN;

#endif