#ifndef FTP_SERVER
#define FTP_SERVER

typedef enum Ftp_Data_Representation {
    ASCII = 0,
    IMAGE = 1,
} Ftp_Data_Repre;

struct Ftp_Sockets {
    int ftp_control_socket;
    int ftp_control_com;
    int ftp_data_socket;
    int ftp_data_com;
};

// , = inicializace struktur/poli, konec definicde, deklarace, definice struktur/poli = ;

typedef struct Ftp_User_Info {
    char *username;
    char *password;
    char *last_path;
    char *filename_to_save;
    
    struct Ftp_Sockets ftp_sockets_obj;

    mqd_t control_queue;
    mqd_t data_queue;

    struct event_base *evbase_data;
    struct event_base *evbase_control;
    struct bufferevent *bufevent_data;
    struct bufferevent *bufevent_control;

    struct event *event_timeout_control;
    struct event *event_timeout_data;

    struct sockaddr_in server_control_info;
    struct sockaddr_in server_data_info;

    enum Ftp_Data_Representation ftp_data_representation;

    struct timeval timeout_control;
    struct timeval timeout_data;
   

    int user_loggedin; // 1 = TRUE, 0 = FALSE
    int quit_command_now;





    struct timeval new_event_timeout;
} Ftp_User_Info;

struct Ftp_User_Info ftp_user_info = {
    .username = NULL,
    .password = NULL,
    .last_path = NULL,
    .filename_to_save = NULL, 
    
    .ftp_sockets_obj = {
        .ftp_control_socket = -1, 
        .ftp_control_com = -1, 
        .ftp_data_socket = -1, 
        .ftp_data_com = -1
    },

    .control_queue = -1, 
    .data_queue = -1,

    .evbase_control = NULL,
    .bufevent_control = NULL,
    .evbase_data = NULL,
    .bufevent_data = NULL,

    .event_timeout_control = NULL,
    .event_timeout_data = NULL,

    .server_control_info = {0}, // jako memset
    .server_data_info = {0}, // jako memset

    .ftp_data_representation = ASCII,

    .timeout_control = {
        .tv_sec = 5,
        .tv_usec = 0,
    },
    .timeout_data = {
        .tv_sec = 5,
        .tv_usec = 0,
    },
    

    .user_loggedin = 0, 
    .quit_command_now = 0, 
    .ftp_data_representation = ASCII,



    .new_event_timeout = { .tv_sec = 4, .tv_usec = 0, },
}; // defaultni nastaveni uctu

#endif