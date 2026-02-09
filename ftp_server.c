// AVE CHRISTUS REX!
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/select.h>
#include <time.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h> // init nemuze se importovat cela slozka, jen individualni soubory
#include <openssl/crypto.h> // config
#include <openssl/bio.h> // novy zpusob komunikace pres sockety pro SSL/TLS komunikaci, je to vrstva abstrakce
#include <openssl/err.h> // funkce na errory
#include <openssl/crypto.h> // memory leaks
#include <pthread.h>
#include <event2/event.h> // libevent je knihovna, ktera slouzi k tomu, ze kazdy file descriptor/signal apod. kdyz se na nem stane neco noveho, tak nam to da vedet => multisynchronnous
#include <event2/bufferevent.h>
#include <mqueue.h> // pro komunikaci mezi procesy/threads
#include <stdint.h> // uint32_t
#include <event2/thread.h>
#include <event2/bufferevent_ssl.h>
#include <event2/visibility.h>
#include <event2/event-config.h>
#include <event2/util.h>
#include <netinet/tcp.h> // TCP_NODELAY
#include <event2/util.h>
#include <stdarg.h>
#include <event2/buffer.h>
#include <sys/time.h>
#include <pwd.h>
#include <threads.h>
#include <sys/wait.h>
#include <stddef.h>
// #define HTTPS_SERVER kdyby toto tady zustalo, tak by preprocesor udelal .h to, ze uz je to definovane, proto by to vyhodilo mnoho erroru
#include "HEADERS/https_server.h" // od pwd, jinak compiler dependent
#include "HEADERS/https_server.h" // protoze to uz je includenute a vsechno je to zkopirovane z .h do .c, tak toto nema zadnou pridanou hodnotu
#include "HEADERS/accounts.h"
#include "HEADERS/queues.h"
#include "HEADERS/ftp_server.h"
#include "HEADERS/https_server.h"

// !!
// kdy pouzivat setsockopt()?
// protoze volani na funkci socket() vrati descriptor na table file struct file, coz odkazuje na struct sock v kernel memory (toto se vse vytvori), kde jsou veskere informace o tom pripojeni jako port, IP adresa, recv and write buffer apod.
// kdyz skonci proces, vsechny ty descriptory se uzavrou ALE kernel si pamatuje jeste asi 60-120s (2 * Maximum Segment Life - MSL - cas kdyz data od TCP - segment - muze byt "zivy" a povazovan za relevantni, potom se da pouze ignorovat), je to proto, kdyby behem cesty nastaly nejake problemy, tak aby to mohlo dorazit, a tento socket je nastaven do TIME-WAIT a pokud se nekdo chce pripojit na ten socket, endpoint aby to bylo presnejsi IP:port, tak to vyhodi error Transport endpoint is already connected!!

// staci delat jenom ty sockety, na ktere se user ma pripojit, listen sockety
// SO_REUSEADDR je pro znovupouzivani adres (IP adresa:port)
// SO_REUSEPORT je pro vice procesu pouzivani stejneho portu => load balancing

// !!

// event2, protoze to je novejsi verze, kdybych tam dal jenom event, tak
// #include <event.h>
//#include <openssl/ssl/ssl_local.h>

// grep -r "SSL_library_init" /usr/include
/*
/usr/include/openssl/ssl.h:#  define OpenSSL_add_ssl_algorithms()   SSL_library_init()
/usr/include/openssl/ssl.h:#  define SSLeay_add_ssl_algorithms()    SSL_library_init()
/usr/include/openssl/ssl.h:#  define SSL_library_init() OPENSSL_init_ssl(0, NULL)
*/

// openssl -version/openssl --version
// kdyz najdu, ze mi to pise deprecated, tak si proste vygooglim, co to nahradilo, existuje docs.openssl.org
// kdyz najdu, ze je to ve vice souborech, tak si proste jeden vyberu

// !!vetsinou knihovny pracuji jenom s pointery, protoze jsou jednose lehci na manipulaci nez s normalnim objektem!!

/*
gcc -I/opt/openssl/include -L/opt/openssl/lib \
    -Wl,-rpath,/opt/openssl/lib \
    -o ~/Documents/FTP_SERVER/ftp_server ~/Documents/FTP_SERVER/ftp_server.c -lssl -lcrypto
*/


#define BACKLOG 5
#define HEADERLEN 180
#define RESPONSELEN 180 + lengthfile
size_t BUFFER_SIZE = 250;
pthread_t MAX_THREADS = 5;
// int QUEUE_MESSAGE_LEN;
int CONNECTION = 0;
static __thread int CONNECTION_thread; // _Thread_local __thread lokalni promenna pro threads, nesdily se, kazdy thread ma svoji kopii
#define CONTROL_PORT 2100
#define DATA_PORT 2000
// #define CONTROL_QUEUE_NAME "/control_queue_server"
// #define DATA_QUEUE_NAME "/data_queue_server"

// struct User_Data *ACCOUNTS_USER_DATA_ARRAY;
// struct User_Data {
//     char username[10]; // nemuzu pri deklarovani pouzivat uz rovnou definici
//     char password[10];
// };
// struct User_Data user_data = {.username = {0}, .password = {0}};

// TOTO POTOM DAT DO NEJAKE HTTP STRUCT!!
// mimo main nejdou psat vyrazy, jen deklarace
// timeout.tv_sec = x se pocita jako prikaz, takze to nejde
// struct HTTPS_response {
//     char *content;
//     size_t content_length;
//     int communication_socket;
// };

// typedef enum Media_Enum {
//     NONE = -1,
//     HTML = 0,
//     CSS = 1,
//     FAVICON = 2,
//     TXT = 3,
//     PATH = 4,
// } Media_Spec;
// enum Media_Enum Media_spec;

// typedef enum HTML_Enum {
//     // NONE = -1,
//     HTML_FORMULAR_PRIHLASENI = 0,
//     HTML_FORMULAR_TVORBA_UCTU = 1,
//     HTML_FILES_HTML = 2,
//     HTML_INVALID_LOGINS = 3,
//     HTML_ACCOUNT_TAKEN = 4,
//     HTML_UNKNOWN_TYPE = 5,
// } HTML_Spec;
// enum HTML_Enum HTML_spec = HTML_FORMULAR_PRIHLASENI;

// typedef union Html_Path_Union {
//     char *html_file_path;
// } Html_path_union;
// Html_path_union html_path_union;

// typedef enum Account_enum {
//     UNSET = -1,
//     ACCOUNT_EXIST = 0,
//     ACCOUNT_TAKEN = 1,
//     ACCOUNT_INVALID_OR_FREE = 2,
// } Account_Spec;
// Account_Spec Account_spec = UNSET;






// typedef enum Ftp_Data_Representation {
//     ASCII = 0,
//     IMAGE = 1,
// } Ftp_Data_Repre;

// struct Ftp_Sockets {
//     int ftp_control_socket;
//     int ftp_control_com;
//     int ftp_data_socket;
//     int ftp_data_com;
// };

// // , = inicializace struktur/poli, konec definicde, deklarace, definice struktur/poli = ;

// typedef struct Ftp_User_Info {
//     char *username;
//     char *password;
//     char *last_path;
//     char *filename_to_save;
    
//     struct Ftp_Sockets ftp_sockets_obj;

//     mqd_t control_queue;
//     mqd_t data_queue;

//     struct event_base *evbase_data;
//     struct event_base *evbase_control;
//     struct bufferevent *bufevent_data;
//     struct bufferevent *bufevent_control;

//     struct event *event_timeout_control;
//     struct event *event_timeout_data;

//     struct sockaddr_in server_control_info;
//     struct sockaddr_in server_data_info;

//     enum Ftp_Data_Representation ftp_data_representation;

//     struct timeval timeout_control;
//     struct timeval timeout_data;
   

//     int user_loggedin; // 1 = TRUE, 0 = FALSE
//     int quit_command_now;
// } Ftp_User_Info;

// struct Ftp_User_Info ftp_user_info = {
//     .username = NULL,
//     .password = NULL,
//     .last_path = NULL,
//     .filename_to_save = NULL, 
    
//     .ftp_sockets_obj = {
//         .ftp_control_socket = -1, 
//         .ftp_control_com = -1, 
//         .ftp_data_socket = -1, 
//         .ftp_data_com = -1
//     },

//     .control_queue = -1, 
//     .data_queue = -1,

//     .evbase_control = NULL,
//     .bufevent_control = NULL,
//     .evbase_data = NULL,
//     .bufevent_data = NULL,

//     .event_timeout_control = NULL,
//     .event_timeout_data = NULL,

//     .server_control_info = {0}, // jako memset
//     .server_data_info = {0}, // jako memset

//     .ftp_data_representation = ASCII,

//     .timeout_control = {
//         .tv_sec = 5,
//         .tv_usec = 0,
//     },
//     .timeout_data = {
//         .tv_sec = 5,
//         .tv_usec = 0,
//     },
    

//     .user_loggedin = 0, 
//     .quit_command_now = 0, 
//     .ftp_data_representation = ASCII,
// }; // defaultni nastaveni uctu

// struct linger so_linger = {.l_onoff = 1, .l_linger = 3}; // pocka se az se poslou vsechny datam, 3 sekundy

// struct Handling_response_struct {
    // int httpcomsocket;
    // // pthread_t threadID; // zbytecne, protoze samo vlakno muze udelat pthread_self()
    // int connection;
// };

// pthread_t *ARRAYTHREAD; // globalni pole - neni soucasti struct
// pole struktur je lepsi na cache a pro procesor, pole pointeru je horsi pro razeni struktur apod. a je to narocnejsi na CPU
// typedef struct HTTPS_Global_Info {
//     struct HTTPS_Thread_Specific *THREADSPECIFIC_ARRAY;
//     int *COMSOCKARRAY; // potom soucasti struct
//     SSL **SSL_CONNECTIONS_ARRAY; // potom soucasti struct
//     struct event_base **EVENT_CONTEXT;
// } HTTPS_Global_info;
// struct HTTPS_Global_Info HTTPS_global_info;

// typedef struct HTTPS_Thread_Specific {
//     int connection;
//     int comsocket;
//     pthread_t thread_id;
//     SSL *specific_ssl_connection;
// } HTTPS_Thread_specific;
// struct HTTPS_Thread_Specific *HTTPS_thread_specific;

// struct mq_attr global_mq_setting;

// global variable so the values will change with every thread, thanks to repetitive calling in main()
// struct Thread_info {
//     SSL **ssl_array_tf; // NESMIM ZAPOMENOUT TO INICIALIZOVAT!! toto je jakoby jenom jako sablona a kazda instance se musi alokovat samostatne
//     int *communication_array_tf; // ulozi se to do BSS segmetu, protoze to je jenom deklarovane, ale ne inicializovane, pokud ta struct obsahuje
//     int connection_tf; // jenom samostatne promenne staci to alokovat "staticky" jenom struct x y; pokud ale obsahuje pointery (pole) apod. tak ty musim alokovat zvlast!!
// };
// struct Thread_info thread_info;

// "private" struct to group information needed to send data/serve each connection and then passing it on the private stack, so the values will not change
// threads share a lot of things but they have its ID, stack, signal mask (collection of which signals are blocked for each thread), cancel state


// struct Handling_response_struct info;

//az se bude delat HTTP, tak toto se musi dat do nejake HTTP struct
// SSL *ssl_connection = NULL; // SSL je datova struktura, ktera obsahuje real-time informace o kazde SSL/TLS konekce
SSL_CTX *ctx = NULL; // SSL_CTX je datova struktura obsahujici veskere informace a nastaveni o SSL/TLS konekci, muze byt pouzivana jako sablona pro dalsi HTTPS konekce
const SSL_METHOD *method;
// SSL datovy typ je ve skutecnosti ssl_st struktura, ale je to interni struktura, takze kompilator nezna jeji velikost a nevi, jak s ni ma zachazet
// ale protoze to bychom museli si pridavat ty objekty samotne, tak udelame pole takove, ze kazda polozka bude pointer na objekt SSL*
// taky bychom mohli udelat sizeof(te struktury, ze ktere je SSL), ale ta se nachazi v openssl/ssl/ssl_local.h a to je interni knihovna, ke ktere muzeme mit pristup
// ale kod by byl hodne zavisly na verzi openssl
// globalni promenna nesmi byt dynamicky alokovana

// enum Ftp_Type {
//     CONTROL = 0,
//     DATA = 1,
// };




// struct Ptr_To_Bufevents {
//     struct Ftp_Sockets *ptr;
//     char *command;
// };


// int count = 0;
// int css_already = 0;



void sending_response(char *response, size_t lengthresponse, int comsocket);
void create_http_response(int comsocket);
char *printing_request(int comsocket);
char *receiving();
int next_decimal(int length);
enum Media_Enum response_spec(char *buffer);
void handling_response();
char *printing_request(int scomsocket);
char *compact_request(char *buffer);
// int end_of_response(char *buf);
struct HTTPS_response *prepare_html_response(char *request, enum HTML_Enum Html_spec, enum Media_Enum Media_spec);
struct HTTPS_response *prepare_css_response();
struct HTTPS_response *prepare_favicon_response();
enum Account_enum login_lookup(char *username, char *password);
char *html_path(enum HTML_Enum HTML_spec, enum Media_Enum Media_spec, char *path);
void username_password_extraction(char *post_request);
int is_empty(void *buf, size_t size);
char *extraction_path_files(char *buffer);
void send_file(char *path);
void account_created(char *username, char *password);
void initialization_of_openssl(void);
void handle_error();
void handle_error_thread(pthread_t thread_ID);
void *wrapper_handling_response(void *arg);
void cb(SSL *CONNECTION, int where, int ret); // musi zustat v tomto tvaru, jinak vsude muze byt struct Thread_info
int cb_alpn(SSL *ssl_connection, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int intlen, void *arg);
void *select_ftp();
void control_send_ftp(struct bufferevent *bufevent_control);
void bufevent_write_cb_data(struct bufferevent *bufevent_data, void *ptr_arg);
void bufevent_read_cb_data(struct bufferevent *bufevent_data, void *ptr_arg);
void bufevent_read_cb_control(struct bufferevent *bufevent_control, void *ptr_arg);
void bufevent_write_cb_control(struct bufferevent *bufevent_control, void *ptr_arg);
void bufevent_event_cb_data(struct bufferevent *bufevent_both, short events, void *ptr_arg);
void bufevent_event_cb_control(struct bufferevent *bufevent_both, short events, void *ptr_arg);
char *insert_crlf(char *response);
char *read_contents_ftp(char *path);
int save_file(char *path, char *data_received);
void get_dynamic_files_table(char *temp_path);
struct HTTPS_response *prepare_html_contents_path(char *path);
void func_try(evutil_socket_t fd, short what, void *arg);

// ~ NOT, | OR, ^ XOR, & AND, >> right shift, << left shift

/*
https://github.com/openssl/openssl/blob/master/ssl/record/rec_layer_s3.c
https://github.com/openssl/openssl/blob/53e5071f3402ef0ae52f583154574ddd5aa8d3d7/ssl/ssl_sess.c#L1392
https://github.com/openssl/openssl/blob/master/ssl/d1_msg.c
https://github.com/openssl/openssl/blob/53e5071f3402ef0ae52f583154574ddd5aa8d3d7/include/openssl/ssl.h.in#L1079
*/

// SSL_ST_MASK = 4095 (na dec) - 0FFF

// int reset_queue_message_len() { // protoze je to globalni promenna, tak je ulozena na datove sekci => po skonceni funkce nezmizi => neni na stacku
//     QUEUE_MESSAGE_LEN = 256;
// }

void free_all() {
    // SSL_CTX_free(ctx); // SSL context => ctx, kdyby toto bylo nezakomentovane, tak by OPENSSL_cleanup udelal double free(), tak radsi zavolam funkci, ktera to dealokuje vsechno nez nej funkci, ktera dealokuje neco

    printf("\n\n\n\n\n\nTED SE SPUSTIL FREE_ALL()");
    fflush(stdout);

    if (ftp_user_info.control_queue != -1) {
        mq_close(ftp_user_info.control_queue);
    }
    if (ftp_user_info.data_queue != -1) {
        mq_close(ftp_user_info.data_queue);
    }
    

    if (ftp_user_info.ftp_sockets_obj.ftp_data_socket != -1) {
        close(ftp_user_info.ftp_sockets_obj.ftp_data_socket);
    }
    if (ftp_user_info.ftp_sockets_obj.ftp_data_com != -1) {
        close(ftp_user_info.ftp_sockets_obj.ftp_data_com);
    }
    if (ftp_user_info.ftp_sockets_obj.ftp_control_socket != -1) {
        close(ftp_user_info.ftp_sockets_obj.ftp_control_socket);
    }
    if (ftp_user_info.ftp_sockets_obj.ftp_control_com != -1) {
        close(ftp_user_info.ftp_sockets_obj.ftp_control_com);
    }


    if (ftp_user_info.bufevent_control != NULL) {
        bufferevent_free(ftp_user_info.bufevent_control);
    }
    if (ftp_user_info.bufevent_data != NULL) {
        bufferevent_free(ftp_user_info.bufevent_data);
    }
    if (ftp_user_info.evbase_control != NULL) {
        event_base_free(ftp_user_info.evbase_control);
    }
    if (ftp_user_info.evbase_data != NULL) {
        event_base_free(ftp_user_info.evbase_data);
    }


    if ( ftp_user_info.username != NULL) {
        free(ftp_user_info.username);
    }
    if ( ftp_user_info.password != NULL) {
        free(ftp_user_info.password);
    }
    if ( ftp_user_info.last_path != NULL) {
        free(ftp_user_info.last_path);
    }
    if ( ftp_user_info.filename_to_save != NULL) {
        free(ftp_user_info.filename_to_save);
    }
    
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());

    CRYPTO_cleanup_all_ex_data();
    EVP_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_PBE_cleanup();
    CONF_modules_free();

    // EVP_CIPHER_CTX_free();


    // if (ctx != NULL) {
    //     printf("\n\n\nOPENNSL_cleanup\n\n");
    //     fflush(stdout);
    //     OPENSSL_cleanup();
    // }

    OPENSSL_thread_stop();
    // ERR_remove_thread_state();
    _exit(EXIT_FAILURE);
}

void set_queue_message_len() {
    // AVE CHRISTUUS REX! don't you ever ever forget that God is good and great and amazing!

    // popen() udela novy shell process, ktery bude propojen s timto procesem a to jednosmerne (bud jenom read nebo jenom write)
    FILE *command_sp;
    if ((command_sp = popen("cat /proc/sys/fs/mqueue/msgsize_default", "r")) == NULL) {
        perror("popen() selhal - set_queue_message_len");
        exit(EXIT_FAILURE);
    }

    size_t read_nums;
    char *buf = (char *)malloc(10);
    memset(buf, 0, sizeof(10));

    while ((read_nums = fread(buf, sizeof(char), 10, command_sp)) < 10) {
        if (feof(command_sp)) {
            fprintf(stderr, "fread - set_queue_message_len - EOF");
            break;
        }
        else if (ferror(command_sp)) {
            perror("fread() selhal - set_queue_message_len");
            exit(EXIT_FAILURE);
        }
    }
    int bytes = atoi(buf);
    free(buf);

    printf("QUEUE_MESSAGE_LEN: %ld", bytes);

    global_mq_setting.mq_flags = 0, // tady muze byt jenom O_NONBLOCK
    global_mq_setting.mq_maxmsg = 4, // max messages, kolik jich muze byt v queue
    global_mq_setting.mq_msgsize = bytes, // Bytes => velikost
    global_mq_setting.mq_curmsgs = 0, // current messages v queue

    QUEUE_MESSAGE_LEN = bytes;
}

void cb(SSL *CONNECTION, int where, int ret) {
    // SSL_ST = SSL State, ale pro callback funkci toto neni!!
    // pro callback funkce je SSL_CB!!!

    // callback function
    // where je bitmaska int 000000000010001 apod., specifikuje contenxt, jaky SSL objekt se tam dal, jestli je v handshake nebo u cert posilani apod.
    // ret slouzi jako indikace nejakeho erroru, ktery kdyztak mohl nastat, muzeme to vypsat pomoci funkci v rodine ssl_alert_type_string
    // int w = where & ~SSL_ST_MASK; // odstrani se 1,5 Bytes worth of information v bitmask
    // promenna & bitova_hodnota = zkontroluje se, jestli jsou ty stejne bits nastavene v te promenne

    // SSL3_AL... jsou konstanty definujici alerty v SSL/TLS komunikaci 

    const char *p_error = NULL;
    char string_error[120];
    unsigned long errorcode;

    if (where & SSL_CB_LOOP) {
        printf("\n== callback - zmena stavu ==\n");
    }
    else if (where & SSL_CB_EXIT) {
        printf("\n== callback - konec handshake - muze byt i error ==\n");
        p_error = SSL_alert_type_string_long(ret);
        errorcode = ERR_get_error();
        ERR_error_string(errorcode, string_error);
    }
    else if (where & SSL_CB_READ) {
        printf("\n== callback - read operace ==\n");
    }
    else if (where & SSL_CB_WRITE) {
        printf("\n== callback - write operace==\n");
    }
    else if (where & SSL_CB_ALERT) {
        printf("\n== callback - sent/received alert==\n");
        p_error = SSL_alert_type_string_long(ret);
        errorcode = ERR_get_error();
        ERR_error_string(errorcode, string_error);
    }
    else if (where & SSL_CB_READ_ALERT) {
        printf("\n== callback - read alert sent/received==\n");
        p_error = SSL_alert_type_string_long(ret);
        errorcode = ERR_get_error();
        ERR_error_string(errorcode, string_error);
    }
    else if (where & SSL_CB_WRITE_ALERT) {
        printf("\n== callback - write alert sent/received==\n");
        p_error = SSL_alert_type_string_long(ret);
        errorcode = ERR_get_error();
        ERR_error_string(errorcode, string_error);
    }
    else if (where & SSL_CB_ACCEPT_LOOP) {
        printf("\n== callback - zmena stavu ssl nastaveno na server mode==\n");
    }
    else if (where & SSL_CB_ACCEPT_EXIT) {
        printf("\n== callback - zmena stavu ssl nastavovani na server mode - chyba==\n");
    }
    else if (where & SSL_CB_CONNECT_LOOP) {
        printf("\n== callback - zmena stavu ssl nastaveno na client mode==\n");
    }
    else if (where & SSL_CB_CONNECT_EXIT) {
        printf("\n== callback - zmena stavu ssl nastavovani na client mode - chyba ==\n");
        p_error = SSL_alert_type_string_long(ret);
        errorcode = ERR_get_error();
        ERR_error_string(errorcode, string_error);
    }
    else if (where & SSL_CB_HANDSHAKE_START) {
        printf("\n== callback - zmena stavu novy handshake==\n");
    }
    else if (where & SSL_CB_HANDSHAKE_DONE) {
        printf("\n== callback - zmena stavu handshake dokonceny==\n");
    }

    if (p_error != NULL) {
        printf("\n= pokud je unknown nebo error:00000000 - vse v poradku =\n");
        printf("error: %s\n", p_error);
        fprintf(stderr, "%s\n", string_error);
    }

    fflush(stdout);
}

// v C nejdou dat nepovinne argumenty, ale kdyz mam makro a mam tam dany, to chce 2 argumenty treba a ten 2. pouziju jako nejakou preddefinovanou hodnotu, tak to pusobi jako nepovinny argument

// int cb_alpn(SSL *ssl_connection, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
//     // 8-bit length-prefixed bytes string = kazdy Byte ma 8 bitu
//     // protokoly jsou http/1.1, h2, h3
//     // wire format, to cislo na zacatku se nepocita do delky toho stringu 2 ab
//     // vector v tomhle slova smyslu, ze to je nejaky buffer a jeho velikost je oddelena do jine promenne
    
//     // pointer1 bude ukazovat na stejnou memory adresu jako pointer2
//     // pointer1 = pointer2 

//     // pointer, ukazujici na hodnotu X bude zmenen na hodnotu, na kterou ukazuje pointer2
//     // *pointer1 = *pointer2

//     // i++ nejdriv proved, potom inkrementuj
//     // ++i nejdrive inkrementuj, potom udelej

//     // out = &in;

//     // char protocol[10];
//     // int protocol_i = 0;
//     // int len_bytes_string;

//     // 02 68 32 08 68 74 74 70 2f 31 2e 31 = 12 Bytes
//     // 2 h2 8 http/1.1 = wire format
//     // kdyz je v definicich napsano, ze je tam keyword restrict (je to jenom pro pointery), tak jen jedine tim danym pointerem muzeme pristupovat k te memory oblasti, zadnym jinym!!
//     // strcmp() 0 = rovnaji se

//     // nemuzu to rovnou inicializovat na {0}, protoze, inlen nebude znama pri kompilaci 
//     char proposed_protocols[inlen + 1]; // protoze in neni NULL terminated, tak ja chci z toho udelat normalni pole, kde muzu pouzit strstr() => NULL termination povinne
//     memset(proposed_protocols, inlen + 1, 0);

//     int p_p_i = 0;
//     for (int i = 0; i < inlen; i++) {
//         if ( *(in + i) >= 47 && *(in + i) <= 122) { // cca ASCII abeceda + znaky pro cisla
//             proposed_protocols[p_p_i] = *(in + i);
//             p_p_i++;
//         }
//         else {
//             continue;
//         }
//     }
//     proposed_protocols[p_p_i] = '\0';
//     printf("TADY JE PROPOSED_PROTOCOLS: %s", proposed_protocols);
//     fflush(stdout);

//     // https://stackoverflow.com/questions/246127/why-is-volatile-needed-in-c

//     unsigned char *selected_protocol;
//     unsigned char *length_protocol;
//     char *p = strstr(proposed_protocols, "h2");
//     if (p) {
//         printf("\nHTTP/2 (h2) protokol se bude pouzivat\n");
//         static unsigned char h2[] = {2, 'h', '2'}; // presune se to ze stacku na data segment, zustane to mit stejnou hodnotu i po skonceni funkce!!
//         selected_protocol = h2;
//         length_protocol = (unsigned char *) sizeof(h2) - 1;
//     }
//     else if (p = strstr(proposed_protocols, "http/1.1") )
//     {
//         printf("\nHTTP/1.1 (http/1.1) protokol se bude pouzivat\n");
//         static unsigned char http1_1[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'}; // ze stacku na data segment!! alternativa jako heap pro pointery
//         selected_protocol = http1_1;
//         length_protocol = (unsigned char *) sizeof(http1_1) - 1;
//     }
//     else {
//         printf("\nneznamy protokol, nejspise HTTP/3 (h3), tento server nepodporuje h3");
//         handle_error_thread(pthread_self());
//     }
 
//     out =  (const unsigned char **) &selected_protocol;
//     outlen = length_protocol; // TATO 2 SE PREMENI NA BINARNI KOD, POKUD BYCHOM TO DALI DO '', TAK SE JE TO ASCII REPREZENTACE => PORAD BINARNI KOD, ALE JINY NEZ TEN ZAMYSLENY BINARNI KOD!!
// }



void reset_timeval_struct_control (evutil_socket_t fd, short what, void *arg) {
    ftp_user_info.timeout_control.tv_sec = 5;
    ftp_user_info.timeout_control.tv_usec = 0;


    printf("\nftp_user_info.new_event_timeout: %d", ftp_user_info.new_event_timeout.tv_sec);
    printf("\nftp_user_info.new_event_timeout: %d", ftp_user_info.new_event_timeout.tv_usec);
    printf("ftp_user_info.timeout_data.tv_sec: %d", ftp_user_info.timeout_data.tv_sec);
    printf("ftp_user_info.timeout_data.tv_usec: %d", ftp_user_info.timeout_data.tv_usec);

    printf("\n\nCONTROL timeval\n");
    fflush(stdout);
}

void reset_timeval_struct_data (evutil_socket_t fd, short what, void *arg) {
    printf("\n\nDATA timeval\n");
    puts("\nDATA TIMEVAL");
    fflush(stdout);

    
    event_base_dump_events(ftp_user_info.evbase_control, stdout);

    
    ftp_user_info.timeout_data.tv_sec = 5;
    ftp_user_info.timeout_data.tv_usec = 0;
}

void *wrapper_handling_response(void *arg) {
    CONNECTION_thread = *((int *)arg);
    // invalid type of argument of unary `*` => snazim se dereferencovat neco co neni typu yyy * (neco, co neni ukazatel)
    // & give me address of!
    // * give me a value on the memory address of!
    // * => JE JENOM KDYZ CHCI DEREFERENCOVAT !POINTER!

    // nastavim, ze vlakno muze ihned skoncit
    int oldstate;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ASYNCHRONOUS, &oldstate) != 0) {
        perror("pthread_setcancelstate");
        fflush(stderr);
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    printf("\n===Wrapper===\n");
    printf("THREADID: %lu\n", HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].thread_id);
    printf("comsocket %d\n", HTTPS_global_info.COMSOCKARRAY[CONNECTION_thread]);
    printf("connection (CONNECTION_thread) %d\n", CONNECTION_thread);
    fflush(stdout);

    // SSL *obj = HTTPS_global_info.SSL_CONNECTIONS_ARRAY[CONNECTION_thread];
    /*
    /home/marek/Documents/FTP_SERVER/ftp_server.c:159:16: error: initialization of ‘SSL *’ {aka ‘struct ssl_st *’} from incompatible pointer type ‘SSL **’ {aka ‘struct ssl_st **’} [-Wincompatible-pointer-types]
    159 |     SSL *obj = &SSL_CONNECTIONS_ARRAY[CONNECTION_thread];
        |                ^

    jenom mi to vysvetli, ja myslel, ze tim SSL_CONNECTIONS_ARRAY[CONNECTION_thread] ziskam ty data a kdyz to chce pointer na SSL, tak SSL_CONNECTIONS_ARRAY[CONNECTION_thread] neni pointer ale jenom ta hodnota? nebo protoze je to dynamicky alokovane, tak array[x] je to ze dostanu kazdy prvek a kdyz je to dynamicky alokovane to by znamenalo pointe, tak to & je tedy nepotrebne?
    */

    SSL_set_fd(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection, HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].comsocket); // nastavi a "presmeruje" komunikaci na konkretni bod

    // staticke pole je jakoby blok pameti hned u sebe a jsou tam samotna ty data, ale kdyz je dynamicky alokovane pole, tak to znaci k tomu, ze nevime kolik presne prvku toho pole budeme mit, proto by davalo smysl do toho pole ukladat jen memory adresy tich samotnych prvku
    // staticke pole ma v sobe char, ale dostaneme se k tomu pres pointer na prvni prvek pole
    // dynamicke pole ma v sobe adresu na samotny prvek a dostaneme se k tomu pomoci pointeru


    // 0A00009C = HTTP pozadavek prisel i kdyz mel prijit pozadavek HTTPS => neni to sifrovane
    // if (SSL_accept(ssl_CONNECTION) <= 0) { // ceka az client zacne SSL/TLS handshake
    //     fprintf(stderr, "SSL/TLS se nepodarilo zacit");
    //     handle_error_thread(thread);
    // }
    int result;
    if ( (result = SSL_accept(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection)) == 1) {
        printf("tady jsem");
        handling_response();
    }
    else {
        fprintf(stderr, "\nSSL_accept() selhal");
        fflush(stderr);

        int errcode = SSL_get_error(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection, result);

        // error:0A00009C s velikou sanci znamena, ze misto HTTPS se poslal jenom HTTP
        // printf("\nerror%d\n", errcode);
        printf("\n\nTADY JE ERROR");
        ERR_print_errors_fp(stderr); // zadna return value
        printf("\n\nKONEC\n");
        fflush(stdout);
        pthread_cancel(pthread_self());
    }
}

// openssl se sklada prevazne z libcrypto a libssl
void initialization_of_openssl(void) {
    if (OPENSSL_init_ssl(0, NULL) != 1) { // vraci 1 pri success
        handle_error();
    }

    SSL_load_error_strings(); // nacte error stringy z libcrypto a libssl

    if (OPENSSL_init_crypto(0, NULL) != 1) { // nahrazeno z OPENSSL_no_config()/OPENSSL_config(), vraci 1 pri success
        handle_error();
    }
    // nastaveny a inicializovany vsechny potrebne knihovny/funkce
}

void handle_error() {
    char string_error[120];
    unsigned long errorcode = ERR_get_error();
    ERR_error_string(errorcode, string_error);
    fprintf(stderr, "\n%s\n", string_error);
    exit(EXIT_FAILURE);
}

void handle_error_thread(pthread_t thread_ID) {
    char string_error[120];
    unsigned long errorcode = ERR_get_error();
    ERR_error_string(errorcode, string_error);
    fprintf(stderr, "\n%s\n", string_error);
    if (pthread_cancel(thread_ID) != 0) {
        perror("pthread_cancel() selhal");
        exit(EXIT_FAILURE);
    }
}

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

// char *remove_delimiter_files(char *temp_path) {
//     int length = strlen(temp_path);
    
// }

char *path_safety(char *path) {
    // path/$./path_od_tree => ./path_od_tree je vygenerovano, ja si to chci poupravit
    // 0 = nepracuje se s dynamic_table
    // 1 = pracuje se s dynamic table
    // prida / na konec path, pokud uz to tam neni pro lehci doplnovani slozek u LIST apod.
    // curr_dir apod je uz s / (jakoze /path/, protoze se lehceji pridavaji dalsi slozky, to je vse), ale musi se davat pozor u files, to by vyvolalo error
    size_t len = strlen(path);

    char *output = (char *)malloc(len + 2); // pokud to bude bez /, tak tam musi byt misto pro / a pro \0, pokud to bude s /, tak misto jen pro 
    if (output == NULL) {
        free_all();
    }
    memset(output, 0, len + 2);

    if (path[len - 1] != '/') {
        // output = strdup(path); // pozor! strdup() alokuje novou memory oblast, nekopiruje, takze se ztrati ten output u alokovani outputu a pri tom to muze udelat (udelalo) random data pri printf
        strcpy(output, path);
        output[len] = '/';
    }
    else {
        strcpy(output, path);
    }

    // free_all();
    return output;
}

static char *path_to_open(char *buf, int working_with_files) {
    int uid = getuid(); // user ID
    struct passwd *password = getpwuid(uid);
    char *home_directory = password->pw_dir;

    char *curr_dir = (char *)malloc(100);
    if (curr_dir == NULL) {
        perror("malloc() selhal");
        free_all();
    }
    memset(curr_dir, 0, 100);

    if (getcwd(curr_dir, 100) == NULL) {
        perror("getwcd() selhal");
        free_all();
    }

    size_t path_len = strlen(buf) + 1;
    size_t home_directory_len = strlen(home_directory) + 1;

    char *tilde_p = strstr(buf, "~");
    int tilde_index = (int)(tilde_p - buf);

    char *path_to_file = (char *)malloc(path_len + home_directory_len - 1 + 50); // aby byly dostatecne velky buffer na path, protoze muze byt treba ./12345678 a to by potom byl buffer overflow
    if (path_to_file == NULL) {
        free_all();
    }

    char *path_to_control = (char *)malloc(strlen(buf) + 1);
    if (path_to_control == NULL) {
        perror("malloc() selhal - #path_to_open - path_to_control");
        free(path_to_file);
        free(curr_dir);

        free_all();
    }


    char *start_filename = NULL;
    if (ftp_user_info.filename_to_save != NULL) {
        char *temp = (char *)malloc(strlen(buf) + 10);
        if (temp == NULL) {
            free(path_to_file);
            free(curr_dir);
            free_all();
        }
        memset(temp, 0, strlen(buf) + 10);

        start_filename = strstr(buf, ftp_user_info.filename_to_save);
        if (start_filename != NULL) {
            int start_filename_i = (int)(start_filename - buf);

            for (int i = 0; i < start_filename_i; i++) {
                temp[i] = buf[i];
            }

            temp[start_filename_i] = '\0';

            strcpy(path_to_control, temp);
            free(temp);
        }
    } // explicitne receno, ze se pracuje s files
    else {
        strcpy(path_to_control, buf);
    }


    // printf("\n\n\n\033[31mpath_to_file - path_to_open - zacatek: %s", path_to_file);
    printf("\nbuf - path_to_open - zacatek: %s\033[0m\n\n", buf);

    /*
    path versions:
    .
    " "
    ~
    /slozka/
    ~/slozka
    ./slozka
    slozka => ./slozka
    */

    // .
    if (tilde_p == NULL && strstr(path_to_control, ".") != NULL && strlen(path_to_control) == 1) { // 1 protoze se pracuje uz s jenom temp path, takze cokoliv se napsalo za path => to se tady objevi
        strcpy(path_to_file, "/tmp/ftp_server/");
    }
    // ~
    else if (tilde_p != NULL && strlen(path_to_control) == 1) {
        strcpy(path_to_file, home_directory);
        // printf("\n1. if path: %s", path_to_file);
        fflush(stdout);
    }
    // /slozka/slozka
    else if ( tilde_p == NULL && strstr(path_to_control, "/") != NULL && strstr(path_to_control, ".") == NULL) { // kde se hleda, co se hleda
        strcpy(path_to_file, path_to_control);
        // printf("\n1. if path: %s", path_to_file);
        fflush(stdout);
    }
    // ~/slozka
    else if (tilde_p != NULL && strlen(path_to_control) > 1 && strstr(path_to_control, "/") != NULL) {
        strcpy(path_to_file, home_directory);
        strcpy(path_to_file + home_directory_len - 1, path_to_control + tilde_index + 1);
        // printf("\n1. if path: %s", path_to_file);
        fflush(stdout);
    }
    // ./slozka
    else if (tilde_p == NULL && strstr(path_to_control, ".") != NULL && strstr(path_to_control, "/") != NULL && strlen(path_to_control) > 1) {
        strcpy(path_to_file, "/tmp/ftp_server");
        strcpy(path_to_file + strlen("/tmp/ftp_server"), path_to_control); // protoze ftp_user_info.curr_dir ma format /tmp/
    }
    // slozka => ./slozka
    else if (tilde_p == NULL && strstr(path_to_control, ".") == NULL && strstr(path_to_control, "/") == NULL) {
        // printf("\n\n\n\n\nTADY TO JE");
        fflush(stdout);
        strcpy(path_to_file, "/tmp/ftp_server");
        strcpy(path_to_file + strlen("/tmp/ftp_server"), path_to_control); // toto jde protoze je tam curr_dir ve formatu /slozka/
    }
    else {
        printf("\nNejaka chyba v if statementu v path_to_open()\n");
        return NULL;
    }

    if (start_filename != NULL) { 
        char *output = (char *)malloc(strlen(path_to_file) + strlen(ftp_user_info.filename_to_save) + 2); // / \0
        if (output == NULL) {
            free(path_to_file);
            free(buf);
            free_all();
        }

        snprintf(output, strlen(path_to_file) + strlen(ftp_user_info.filename_to_save) + 2, "%s%s", path_to_file, ftp_user_info.filename_to_save); // !CHRIST IS GOD!
        // char *output = path_safety(temp); // kdyby to bylo s path_safety, tak by open() vyhodil error, ze to neni directory, i kdyz je to file /soubor.txt => soubor, /soubor.txt/ => directory

        free(path_to_file);
        free(buf);
        return output;
    }
    else if (working_with_files == 1) { // pracuje se se soubory
        char *output = (char *)malloc(strlen(path_to_file) + strlen(ftp_user_info.filename_to_save) + 1);
        if (output == NULL) {
            perror("malloc() selhal - path_to_open - working with files");
            fflush(stderr);
            free(buf);
            free_all();
        } // CHRIST IS GOD!!
        memset(output, 0, strlen(path_to_file) + strlen(ftp_user_info.filename_to_save) + 1);
 
        snprintf(output, strlen(path_to_file) + strlen(ftp_user_info.filename_to_save) + 1, "%s%s", path_to_file, ftp_user_info.filename_to_save);
    }
    else {
        char *output = path_safety(path_to_file);
        // free(buf);
        return output;
    }
}

void data_send_ftp(struct bufferevent *bufevent_data, char *data_to_send) {
    // pokud chceme poslat soubor tak    read cb_c => write cb_c => write cb_d
    // pokud chceme prijmout souvor, tak read cb_c => write cb_c => read cb_d
    // mqd_t data_queue = mq_open(DATA_QUEUE_NAME, O_RDONLY);

    // if (data_queue == -1) {
    //     perror("mq_open() selhal - bufevent_write_cb_data");
    //     exit(EXIT_FAILURE);
    //     // AVE CHRISTUS REX!
    // }

    // char *path_to_send = (char *)malloc(QUEUE_MESSAGE_LEN);
    // if ( mq_receive(data_queue, path_to_send, QUEUE_MESSAGE_LEN, NULL) == -1) {
    //     perror("mq_receive() selhal - bufevent_write_cb_data");
    //     exit(EXIT_FAILURE);
    // }
    // // ted mame path AVE CHRISTUS REX!!

    // struct stat temp_struct;
    // if (stat(path_to_send, &temp_struct) == -1) {
    //     perror("stat() selhal - bufevent_write_cb_data");
    //     exit(EXIT_FAILURE);
    // }
    // int path_len = temp_struct.st_size;

    // char *data_to_send = read_contents_ftp(path_to_send);
    if (bufevent_data != NULL) { // && ftp_user_info.user_loggedin != 1
        printf("\n\n\n\n\n\n\n\n\n\nDATA_SEND_FTP\n\n\n\n\n");
        fflush(stdout);
        size_t path_len = strlen(data_to_send); // BEZ +1, PROTOZE FILES NEMAJI NULL TERMINATOR
        if ( bufferevent_write(bufevent_data, data_to_send, path_len) == -1) { // + 1 pro \0, protoze 1 char file => @ Bytes => 3 Bytes pro \0
            perror("bufferevent_write() selhal - bufevent_write_cb_data");
            exit(EXIT_FAILURE);
        }
        printf("\n\n\n\n\n\n\n\n\n\nDATA_SEND_FTP\n\n\n\n\n\n");
        fflush(stdout);
    }
    else {
        fprintf(stderr, "\nUser Not Logged In\n");
        fflush(stderr);
    }
}

void signal_handler(int signal_value) {
    if (ftp_user_info.bufevent_control == NULL) {
        puts("ftp_user_info.bufevent_control je prazdny");
        free_all();
    }
    if (bufferevent_write(ftp_user_info.bufevent_control, "!END!", strlen("!END!") + 1) == -1) {
        free_all();
    }
    bufferevent_write(ftp_user_info.bufevent_control, "!END!", strlen("!END!") + 1);

    free_all();
}

// static void ftp_pi(struct Ftp_Sockets *arg) {
//     // PI = protocol interpreter
//     int ftp_control_fd = arg.ftp_control_com;

//     int fcntl_rv;
//     if ( (fcntl_rv = fcntl(ftp_control_fd, F_SETFL, O_NONBLOCK)) == -1) {
//         perror("fcntl() selhalo - ftp_pi");
//         exit(EXIT_FAILURE);
//     }

//     struct timeval timeout = {.tv_sec = 1, .tv_usec = 0}; // takhle se rovnou prirazuje k te strukture (k tomu objektu)

//     // umask je set permisi, ktery ma svoji defaultni hodnotu, a slouzi k tomu k defaultnimu upraveni prav NOVE vytvorenych souboru (potom se to muze zmenit pomoci chmod), nekdy se maska pouziva jako AND s pouzitymi permisemi complement operator (~) = NOT, permise & ~umask, umask rika jake permise se komu maji odebrat, pomoci AND a NOT, ale NENI to NAND!
//     // execute = 1, write = 2, read = 4
//     // 0000
//     // ^ specialni bits = 4 setuid (spoustet program s pravy vlastnika), 2 = setgid (spoustet program s pravy group), 1 = sticky (zabranuje mazani cizich souboru v adresari)

    
//     // ty permise se maskujou jeste s umask
//     mqd_t message_queue_fd_pi = mq_open("/ftp_pi", O_RWDR | O_CREAT | O_NONBLOCK, 0777, &attributes);
//     if (message_queue_fd_pi == -1) {
//         perror("mq_open() selhal - ftp_pi");
//         exit(EXIT_FAILURE);
//     }

//     int nfds = ftp_control_fd + 1;

//     while (1) {

//     }


// }

// static void ftp_dtp(struct Ftp_Sockets *arg) {
//     // DTP = data process

//     int ftp_data_fd = arg->ftp_data_com;

//     int fcntl_rv;
//     if ( (fcntl_rv = fcntl(ftp_data_fd, F_SETFL, O_NONBLOCK)) == -1) {
//         perror("fnctl() selhalo - ftp_dtp");
//         exit(EXIT_FAILURE);
//     }

//     mqd_t message_queue_fd_dtp = mq_open("/ftp_dtp", O_RWDR | O_CREAT | O_NONBLOCK, 0777, &attributes);
//     if (message_queue_fd_dtp == -1) {
//         perror("mq_open() selhal - ftp_dtp");
//         exit(EXIT_FAILURE);
//     }

//     int nfds = ftp_data_fd + 1;

//     while (1) {

//     }


// }

// PORT = ACTIVE DATA CONNECTION
// PASV = PASSIVE DATA CONNECTION

void send_conformation_account(struct bufferevent *bufevent_control, int yay_or_nay) {
    switch (yay_or_nay) {
        case 0:
            {
                char buf[] = "200 - command okay";
                char *buf_to_send = insert_crlf(buf);

                if (bufferevent_write(ftp_user_info.bufevent_control, buf_to_send, strlen(buf_to_send) + 1) == -1) {
                    perror("bufferevent_write() selhal - send_conformation_account");
                    exit(EXIT_FAILURE);
                }
                free(buf_to_send);
                break;
            }
        case 1:
            {
                char buf2[] = "Server - 530 - Not logged in";
                char *buf_to_send = insert_crlf(buf2);

                if (bufferevent_write(ftp_user_info.bufevent_control, buf_to_send, strlen(buf_to_send) + 1) == -1) {
                    perror("bufferevent_write() selhal - send_conformation_account");
                    exit(EXIT_FAILURE);
                }
                free(buf_to_send);
                break;
            }
        default:
            {
                fprintf(stderr, "\nhodnota nabyva zvlastni hodnoty - send_conformation_account()");
                exit(EXIT_FAILURE);
            }
    }
}

// void make_port_connection(struct sockaddr_in *client_struct) {
//     // switch(client_struct->sin_family) {
//     //     case AF_INET:
//     //         printf("\nAF_INET family");
//     //         break;
//     //     default:
//     //         printf("Lord Jesus Christ, Son of God, Word of God, have mercy on me, a sinner");
//     //         break;
//     // }
//     // struct sockaddr temp_struct;
//     // temp_struct.sa_family = AF_INET;
//     // memcpy(&(temp_struct.sa_data), "127.0.0.1", strlen("127.0.0.1") + 1);
//     // // temp_struct.sa_data = ;

//     struct sockaddr_in temp_struct;
//     temp_struct.sin_family = AF_INET;
//     temp_struct.sin_port = htons(DATA_PORT);


//     int connect_rv = connect(ftp_sockets_obj.ftp_data_socket, (struct sockaddr *)&temp_struct, sizeof(temp_struct));
//     if (connect_rv != 0) {
//         perror("connect() selhal - make_port_connection");
//         printf("\n%s", strerror(errno));
//         fflush(stdout);
//         exit(EXIT_FAILURE);
//     }
//     ftp_sockets_obj.ftp_data_com = ftp_sockets_obj.ftp_data_socket;
//     printf("HALOOOO\n");
//     fflush(stdout);
// }

short int return_port(char **metadata_command) {
    short int port;
    unsigned char *port_array = malloc(sizeof(unsigned char ) * 2);
    for (int i = 4, i_port_arr = 0; i < 6; i++) {
        port_array[i_port_arr++] = atoi(metadata_command[i]); // ASCII to Int
    }
    memcpy(&port, port_array, sizeof(unsigned char ) * 2); // takhle se kopiruji data celeho array do jedne promenne

    free(port_array);
    return htons(port); // aby uz to bylo na network 
}

char *get_address(char **metadata_command) {
    char *address = (char *)malloc(INET_ADDRSTRLEN); // 16 bytes => IPv4 + \0
    memset(address, 0, INET_ADDRSTRLEN);
    size_t total_offset = 0, len = 0;

    for (int i = 0; i < 4; i++) {
        // strcat pridava \0 na konec a overwrituje \0 uprostred stringu
        len = strlen(metadata_command[i]) + 1; // pro .

        strcat(address + total_offset, metadata_command[i]);
        if (i == 3) {
            return address;
        }
        strcat(address + total_offset + 1, ".");

        total_offset = total_offset + len;
    }
}

void make_connection(char **metadata_command) {
    // INADDR_ANY se pouziva v sin_addr.s_addr, protoze INADDR_ANY je definovano jako uint32_t, takze se to da do uint32_t
    // inet_pton() se pouziva na strukturu, ktera opravdu drzi tu adresu, nic jineho (family, port, padding apod.), proto se musi pouzit ta samotna struktura => sin_addr.s_addr
    // bind(), connect(), listen() apod., tyto funkce pracuji jako s celymi strukturami a ne jen s castmi tich struktur, proto to chce cely pointer na tu strukturu

    if ((ftp_user_info.ftp_sockets_obj.ftp_data_socket = socket(ftp_user_info.server_data_info.sin_family, SOCK_STREAM, 0)) == -1) {
        perror("\nsocket() selhal - make_connection");
        exit(EXIT_FAILURE);
    }

    char *address = get_address(metadata_command);
    short int port = return_port(metadata_command);
    printf("\n\n\n\n\n\n\n\nport: %d", port);
    fflush(stdout); // JESUS IS GOD!

    // vse ostatni uz nastaveno
    ftp_user_info.server_data_info.sin_port = htons(port); // 2000

    // stal se takovy error, ze transport endpoint is already connected, ale ten endpoint byl ephemeral port (ten random port, ktery priradi kernel) - to se zjistilo, ze jsem udelal nekolik connections a koukal se na to, jake porty se opakovaly v tich connections
    // proto kdyz klient se pripojuje a dostane socket descriptoru od socket(), tak by se melo udelat setsockopt(), protoze kdyz server se pripojoval na klienta (PORT), tak server vyhodil error transport endpot is alreadu connected => client at fault 
    // By default, the kernel will not reuse any in-use port for an ephemeral port, which may result in failures if you have 64K+ simultaneous ports in use.
    
    printf("\n\nftp_user_info.ftp_sockets_obj.ftp_data_socket: %d", ftp_user_info.ftp_sockets_obj.ftp_data_socket);

    /*if () {
        OS kernel prideluje ephemeral porty (docasne porty), ktere nejsou v TIME_WAIT, pokud by vsechny byly vTIME_WAIT, tak by nejspis TCP (bind() nebo connect() vyhodilo error) a nepustilo by me to dal
        proto pokud bych chtel reusovat ty porty, tak bych musel nejak pouzit SO_REUSEADDR (to pusobi na IP odkud:ephemeral port), takze bych musel explicitne bind() nejakou local adresu a udelat jeste pred tim setsockopt() SOL_SOCKET, SO_REUSEADDR, proto jen toto setsockopt() SO_REUSEADDR na socket nema moc velke ucinky

        int yes = 1;
        if ( setsockopt(ftp_sockets_obj.ftp_data_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &yes, sizeof(yes)) == -1) {
            perror("setsockopt() selhal - make_connection - PORT");
            exit(EXIT_FAILURE);
        }
    }*/
    
    // printf("\n\npo setsockopt(), port na connect: %d, %s", port);
    fflush(stdout);

    if (inet_pton(ftp_user_info.server_data_info.sin_family, (const char *)address, (void *)&(ftp_user_info.server_data_info.sin_addr) ) == -1) { // mam pointer na struct, ktera ma v sobe objekty, proto musim udelat &
        perror("\ninet_pton() selhal - make_connection");
        exit(EXIT_FAILURE);
    }

    int return_value = fcntl(ftp_user_info.ftp_sockets_obj.ftp_data_socket, F_SETFL, O_NONBLOCK);
    if (return_value == -1) {
        perror("fcntl() selhal - #make_connection");
        free_all();
    }



    printf("\n\nmake connection");
    fflush(stdout);

    clock_t start = clock(), difference = 0, end = 0;
    while (difference < 5) {
        if (connect(ftp_user_info.ftp_sockets_obj.ftp_data_socket, (struct sockaddr *)&ftp_user_info.server_data_info, sizeof(struct sockaddr_in)) == -1) { // blocking operace
            if (errno == EINPROGRESS) {
                printf("\nzatim nepovedene\n");
                fflush(stdout);
            }
            if (errno == ECONNREFUSED) {
                perror("\nerrno je ECONNREFUSED");
                perror("\nconnect() selhal - make_connection");
                printf("\n%s", strerror(errno));
                fflush(stdout);
                free_all();
            }
            end = clock();
            difference = (end - start) / CLOCKS_PER_SEC;
        }
        ftp_user_info.ftp_sockets_obj.ftp_data_com = ftp_user_info.ftp_sockets_obj.ftp_data_socket;
        break;
    }
    if (difference > 5) {
        puts("\nnepodarilo se pripojit");
    }
    printf("\ndifference: %d\n", difference);
  

    //  ftp_user_info.data_connection_sd = ftp_sockets_obj.ftp_data_com;
    //         ftp_user_info.data_connection_port = port;
    printf("HALOOOO: %d\n", ftp_user_info.ftp_sockets_obj.ftp_data_com);
    fflush(stdout);

    free(address);
}

char **metadata_command(char *command) {
    // pro PORT = 7 jednotlivych slov, pro PORT to neni potreba, protoze vime, ze tato funkce je primo pro PORT => 6 slov
    // PORT h1,h2,h3,h4,p1,p2
    // PORT 12,255,64,38,10,20\r\n
    // 25, 26

    char **array = (char **)calloc(6, sizeof(char *));
    int i_arr = 0;
    int j_arr = 0;
    // [i][j]

    for (int i = 0; i < 6; i++) {
        array[i] = (char *)malloc(4); // max IP adresa muze byt 255 => 3 chars + 1 pro \0
        memset(array[i], 0, 4); // automaticke NULL terminated strings
        printf("\ns");
    }

    char *st_space = strstr(command, " "); // kde a co
    if (st_space == NULL) {
        fprintf(stderr, "strstr nenaslo ' '");
        exit(EXIT_FAILURE);
    }

    char *st_separator = strstr(command, ","); // kde a co
    if (st_space == NULL) {
        fprintf(stderr, "strstr nenaslo ,");
        exit(EXIT_FAILURE);
    }

    int i_space = (int)(st_space - command);
    int i_separator = (int)(st_separator - command);

    for (int second_end = i_separator, i = i_space + 1; i < strlen(command) + 1; i++) { // musime specifikovat typ pouze jednou
        if (i < second_end) {
            array[i_arr][j_arr++] = command[i];

            printf("\nhalo: %c", array[i_arr][j_arr]);
        }
        else {
            char *next_separator = (strstr(command + i + 1, ",") == NULL) ? strstr(command + i + 1, "\r") : strstr(command + i + 1, ","); // kde a co
            if (next_separator == NULL && i < 15) { // cca 15 muze byt minimalni pocet, kde muze opravdu nastat chyba
                fprintf(stderr, "strstr nenaslo , ani CR");
                exit(EXIT_FAILURE);
            }
            else if (next_separator == NULL && i > 15) {
                break;
            }
            second_end = (int)(next_separator - command);
            printf("\nsecond_end: %d, %c", second_end, command + 1 + i);
            i_arr++;
            j_arr = 0;
        }
    }
    return array;
}

char *extract_path_command(char *command) {
    char *separator = strstr(command, " ");
    if (separator == NULL) {
        perror("strstr() selhal - extract_path_command");
        exit(EXIT_FAILURE);
    }
    int separator_i = (int)(separator - command);

    char *carriage_return = strstr(command, "\r");
    if (separator == NULL) {
        perror("strstr() selhal - extract_path_command");
        exit(EXIT_FAILURE);
    }
    int carriage_return_i = (int)(carriage_return - command);

    char *path = (char *)malloc(92); // protoze 100 - 3 (\r\n\0) - 5 (RETR )
    if (path == NULL) {
        perror("malloc() selhal - extract_path_command");
        exit(EXIT_FAILURE);
    }
    memset(path, 0, 92);

    for (int i = separator_i + 1, path_i = 0; i < carriage_return_i; i++) {
        path[path_i++] = command[i];
    }
    // nemusime resit \0, protoze automaticky NULL terminated
    printf("\n\n\n\nextract_path: path: %s\n\n\n", path);
    fflush(stdout);
    return path;
}

char *extract_username_password(char *command_user_pass) {
    char *info = (char *)malloc(sizeof(char) * 9); // 8 chars + \0, protoze max username a passwod je 8 chars (jako i z http serveru), 9 chars => 8 chars + \0 
    memset(info, 0, sizeof(char) * 9); // automaticky NULL terminated

    char *space = strstr(" ", command_user_pass);
    int space_i = (int)(space - command_user_pass);

    char *end = strstr("\r", command_user_pass); // CRLF konci kazdy FTP command (Telnet)
    int end_i = (int)(end - command_user_pass);

    int info_i = 0;
    for (int i = space_i + 1; i < end_i; i++) {
        info[info_i++] = command_user_pass[i];
    }
    info[info_i] = '\0'; // explicitni NULL terminator, i kdyz by to melo fungovat i bez toho, protoze tam je to memset()

    return info;
}

// int available_commands(char *text) {
//     // linux pouziva pro novy radek (\n) - Line Feed (0x0aA)
//     // getline() bere celou radku ze souboru (dokud nenarazi na \n), getdelim() cte do te doby, nez se nenajde specifikovany delimiter
//     FILE *f_stream = fopen("./TXT/available_commands.txt", "r");

//     char *command_from_text = (char *)malloc(5);
//     memset(command_from_text, 0, 5); // automaticky NULL terminating

//     for (int i = 0; i < 5; i++) {
//         command_from_text[i] = text[i];
//     }

//     if (f_stream == NULL) {
//         perror("fopen() neotevrel soubor FTP_SERVER/TXT/available_commands.txt - is_command_or_data");
//     }

//     size_t len = 0;
//     char *line = NULL;

//     ssize_t chars_read;
//     while ( (chars_read = getline(&line, &len, f_stream)) != -1) { // pokud -1 => EOF a EOF indicator set => feof(), vraci se pocet chars i s delimiterem, ale bez \0
//         line[chars_read - 1] = '\0';
//         if ( strcmp(line, command_from_text) != 0) { // nerovnaji se
//             return 0; // false
//         }
//     }
//     return 1; // true
// }
// enum Ftp_Type is_command_or_data(int comsocket, char *text) {
//     char *data = (char *)malloc(31); // maximalni delka zpravy od ftp serveru => 30 chars + \0
//     memset(data, 0, 31); // automaticky NULL terminated
//     recv(comsocket, data, 31, MSG_PEEK); // to, co se precte se neodebere ze TCP stack internal bufferu

//     if ( available_commands(data) && strstr("\r\n", text) != NULL) {
//         return CONTROL;
//     }
//     return DATA;
// }

int partial_login_lookup(char *text, int username_password) {
    // 0 - username
    // 1 - password
    FILE *fs = fopen("./TXT/account.txt", "r+");

    if (fs == NULL) {
        perror("fopen() selhal - partial_login_lookup()");
        exit(EXIT_FAILURE);
    }
    char **account_info = (char **)malloc(sizeof(char *) * 2);
    account_info[0] = (char *)malloc(9); // protoze max je 8 chars => + \0
    account_info[1] = (char *)malloc(9); // 8 chars + \0
    memset(account_info[0], 0, 9); // automaticky NULL terminated
    memset(account_info[1], 0, 9); // automaticky NULL terminated

    char *line = NULL; // toto se automaticky alokuje
    size_t n = 0; // toto se automaticky updatuje
    ssize_t chars_read;
    while ( (chars_read = getline(&line, &n, fs)) != -1) {
        char *line_separator = strstr(" ", line);
        int line_separator_i = (int)(line_separator - line);

        int len_line = strlen(line) - 1; // strlen(line) je i s \n a bez \0
        memcpy(account_info[0], line, line_separator_i - 1); // username
        memcpy(account_info[1], line + line_separator_i + 1, len_line - (line_separator_i + 1)); // password

        switch(username_password) {
            case 0:    
                if (strcmp(account_info[0], text) == 0) {
                    return 0;
                }
            case 1:
                if ( strcmp(account_info[1], text) == 0) {
                    return 0;
                }
            default:
                fprintf(stderr, "username_password faulty - partial_login_lookup");
                exit(EXIT_FAILURE);
                break;
        }

        memset(account_info[0], 0, 9); // reset bufferu
        memset(account_info[1], 0, 9); // reset bufferu
    }
    return 1;
}

void *run_ev_base_loop(void *) {
    printf("\ndiyciuervfurvy4uvy98y4fyfuyfuf");
    fflush(stdout);
    event_base_loop(ftp_user_info.evbase_data, EVLOOP_NO_EXIT_ON_EMPTY);
    exit(EXIT_FAILURE);

}

void send_message_queue(mqd_t message_descriptor, char *message, size_t len, char *error_message) {
    int flags = O_NONBLOCK;
    if (fcntl(message_descriptor, F_SETFL, flags) == -1) {
        perror("fcntl() selhal - send_message_queue");
        exit(EXIT_FAILURE);
    }

    if (mq_send(message_descriptor, message, len, 30) == -1) { // 31 je nejvyssi priorita
        if (errno == EAGAIN) {
            perror("mq_send() selhal - snaha poslat vice message kdyz message_queue full - send_message_queue");
            fprintf(stderr, "%s", error_message);
        }
        fprintf(stderr, "mq_send() selhal - send_message_queue");
        exit(EXIT_FAILURE);
    }

    flags = flags & ~(O_NONBLOCK); // zpatky na blocking
    if (fcntl(message_descriptor, F_SETFL, flags) == -1) {
        perror("fcntl() selhal - send_message_queue");
    }
}

char *get_file_name(char *path) {
    char *filename = (char *)malloc(strlen(path) + 1);
    int filename_i = 0;
    memset(filename, 0, strlen(path) + 1); // pokud user posle jenom filename, tak maximalni filename musi byt path, ktery poslal, // automaticky NULL terminating

    char *temp_last_slash_buf = (char *)malloc(strlen(path) + 1);
    int temp_last_slash_buf_i = 0;
    memset(temp_last_slash_buf, 0, strlen(path) + 1); // automaticky NULL terminating

    for (int i = strlen(path) - 1; i >= 0; i--) { // nebo vetsi nez -1 => > -1
        temp_last_slash_buf[temp_last_slash_buf_i++] = path[i];
    }
    char *last_slash = strstr(temp_last_slash_buf, "/");
    
    if (last_slash == NULL) {
        perror("strstr() nenasel posledni slash - get_file_name");
        exit(EXIT_FAILURE);
    }
    int last_slash_i = (int)(last_slash - temp_last_slash_buf);

    for (int i = last_slash_i - 1; i >= 0; i--) { // muze byt i vetsi nez -1 => > -1
        filename[filename_i++] = temp_last_slash_buf[i];
    }
    ftp_user_info.filename_to_save = strdup(filename);
    return filename;
}

void execute_commands(char *command, struct bufferevent *bufevent_control) {
    // tato queue je zpusob komunikace mezi control a data funkcemi, budeme posilat jakekoliv zpravy s mensi priority hodnotou nez posilani zprav s paths, ktere mame poslat, aby v queue byly na uplnem vrcholu a aby se nemuselo cekat nez se odesle zprava, protoze path > zprava (priorita)
    // zprava = 30, path = 31
    
    // char msg4[] = "501 - Syntax error in parameters or arguments";
    // const char msg2[] = "426 - Connection closed; transfer aborted";


    if (strstr(command, "NOOP") != NULL) {
        event_base_dump_events(ftp_user_info.evbase_data, stdout);
        // bufevent_read_cb_data(ftp_user_info.bufevent_data, NULL);
        char msg1[] = "200 - command okay";
        send_message_queue(ftp_user_info.control_queue, msg1, strlen(msg1) + 1, "mq_send() selhal - execute commands - NOOP - msg1");
        // void * pointer ((void *)0) muze nabyvat jakehokoliv typu
    }
    else if (strstr(command, "RETR") != NULL) { // CONTROL + DATA

        // exit(EXIT_FAILURE);
        char msg1[] = "250 - Requested file action was okay, completed";
        char msg2[] = "530 - Not Logged in - can't send file";
        char msg3[] = "425 - Can't open data connection";
        printf("\n\n\nftp_user_loggedin %d\n\n\n\n\n", ftp_user_info.user_loggedin);
        fflush(stdout);

        if (ftp_user_info.user_loggedin == 1) { // OK
            char *temp_path = (char *)malloc(strlen(command));
            memset(temp_path, 0, strlen(command));
            temp_path = extract_path_command(command);
            
            char *filename = get_file_name(temp_path);
            char *path = path_to_open(temp_path, 1);
            if (path != NULL) {
                // CONTROL
                send_message_queue(ftp_user_info.control_queue, msg1, strlen(msg1) + 1, "mq_send() selhal - execute commands - RETR - msg1"); // file se posle

                // // DATA
                // printf("\n\n\n\n%s", temp_path);
                // fflush(stdout);
                
                // if ( mq_send(data_queue, path, strlen(path) + 1, 30) == -1) {
                //     perror("mq_send() selhal - execute commands - RETR - msg1");
                //     exit(EXIT_FAILURE);
                // }

                char *contents = read_contents_ftp(path);
                printf("\n\n\n\n\ncontents: %s");
                fflush(stdout);
                data_send_ftp(ftp_user_info.bufevent_data, contents);

                // free(temp_path);
                free(path);
            }
            else {
                fprintf(stderr, "\nspatna path!\n");
                fflush(stderr);
                send_message_queue(ftp_user_info.control_queue, "550 - Action not taken", strlen("550 - Action not taken") + 1, "mq_send() selhal - #execute_commands - STOR - spatna path");
            }         
        }
        else if (ftp_user_info.user_loggedin == 0) {
            send_message_queue(ftp_user_info.control_queue, msg1, strlen(msg1) + 1, "mq_send() selhal - execute commands - RETR - msg2"); // not logged in
        }
        else {
            send_message_queue(ftp_user_info.control_queue, msg3, strlen(msg3) + 1, "mq_send() selhal - execute commands - RETR - msg3"); // // neni otevrena data connection
        }
        // send_file_bypath();
    }
    else if (strstr(command, "STOR") != NULL) { // CONTROL + DATA
        printf("\n\n\n\n\ntady u STOR: %s", command);
        fflush(stdout);
        char msg1[] = "200 - Command okay";
        char msg2[] = "532 - Need account for storing files";
        // const char msg3 = "501 - Syntax error in parameters or arguments";

        if (ftp_user_info.user_loggedin == 1) { // pokud nonzero value, tak je to true
            char *temp_path = extract_path_command(command);
            char *filename = get_file_name(temp_path);
            char *path = path_to_open(temp_path, 0);
           
            if (path != NULL) {
                
                ftp_user_info.filename_to_save = strdup(filename);
                printf("\n\n\n\n\nfilename: %s", filename);
                fflush(stdout);
                // char *contents = read_contents_ftp(temp_path); musi z data socketu prijit

                send_message_queue(ftp_user_info.data_queue, filename, strlen(filename) + 1, "mq_send() selhal - execute_commands - STOR");
                send_message_queue(ftp_user_info.control_queue, "226 - Partial transfer complete", strlen("226 - Partial transfer complete") + 1, "mq_send() selhal - #execute_commands - STOR");

                // AVE CHRISTUS REX!      

                // free(temp_path);
                // free(path);
                // free(filename);
            }
            else {
                fprintf(stderr, "\nspatna path!\n");
                fflush(stderr);
                send_message_queue(ftp_user_info.control_queue, "550 - Action not taken", strlen("550 - Action not taken") + 1, "mq_send() selhal - #execute_commands - STOR - spatna path");
            }
        }
        else if (ftp_user_info.user_loggedin) {
            send_message_queue(ftp_user_info.control_queue, msg2, strlen(msg2) + 1, "mq_send() selhal - execute commands - STOR - msg2");
        }
        // get_file from data and save it
    }
    else if (strstr(command, "PORT") != NULL) {
        // send this information

        printf("\n\n\nftp_user_info.user_loggedin: %d, && ftp_user_info.ftp_sockets_obj.ftp_data_com: %d", ftp_user_info.user_loggedin, ftp_user_info.ftp_sockets_obj.ftp_data_com);
        fflush(stdout);
        if ((ftp_user_info.user_loggedin == 1) && (ftp_user_info.ftp_sockets_obj.ftp_data_com == -1)) { // nenulove a je to true
            char **array = metadata_command(command);
            // x1,x2,x3,x4,p1,p2




            make_connection(array);
            evutil_make_socket_nonblocking(ftp_user_info.ftp_sockets_obj.ftp_data_socket);

            // sock_struct->sin_port = htons(port); // nemuzu dat -1, to by se udelalo max cislo portu, jakoby overwrite
           
            // make_port_connection(address); // ftp_sockets_obj.ftp_data_com = ftp_sockets_obj.ftp_data_socket, protoze connect()
            
            ftp_user_info.evbase_data = event_base_new(); // event_base nepotrebujeme, protoze event_base se pouziva na socket/buffer, kdyz je ready na read/write apod. ale bufferevent uz rovnou vola callbacky kdyz se prectou/zapisou data
            ftp_user_info.timeout_data.tv_sec = 3;
            ftp_user_info.timeout_data.tv_usec = 0;

            evutil_make_socket_nonblocking(ftp_user_info.ftp_sockets_obj.ftp_data_com);

            ftp_user_info.event_timeout_data = event_new(ftp_user_info.evbase_data, -1, EV_PERSIST | EV_TIMEOUT, reset_timeval_struct_data, NULL);
            event_add(ftp_user_info.event_timeout_data, &(ftp_user_info.timeout_data));

    











            // if (fcntl(ftp_sockets_obj.ftp_data_com, F_SETFL, O_NONBLOCK) == -1) { // musi byt nonblocking, aby se to mohlo dat do bufferevent_socket_new()
            //     perror("fcntl() selhal - neslo nastavit O_NONBLOCK - handle_command_function");
            //     exit(EXIT_FAILURE);
            // }
            
            // int one = 1;
            // setsockopt(ftp_user_info.ftp_sockets_obj.ftp_data_com, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(int));


            // protoze libevent drzi lock na vsechny buffereventy (mutex), tak pokud bychom chteli precist neco, na cem je lock, tak by ten thread cekal na to, nez se ten lock da pryc, to by se cekalo donekonecna => deadlock => proto BEV_OPT_UNLOCK_CALLBACKS
            ftp_user_info.bufevent_data = bufferevent_socket_new(ftp_user_info.evbase_data, ftp_user_info.ftp_sockets_obj.ftp_data_com, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE); // BEV_OPT_UNLOCK_CALLBACKS

            void (*bufevent_write_data)(struct bufferevent *bufevent_data, void *ptr_arg) = &bufevent_write_cb_data; // v oficialni dokumentaci je misto void *ptr_arg void *ctx (context)
            void (*bufevent_read_data)(struct bufferevent *bufevent_data, void *ptr_arg) = &bufevent_read_cb_data;
            void (*bufevent_event_data)(struct bufferevent *bufevent_data, short events, void *ptr_arg) = &bufevent_event_cb_data;
            bufferevent_setcb(ftp_user_info.bufevent_data, bufevent_read_data, bufevent_write_data, bufevent_event_data, NULL);
            bufferevent_enable(ftp_user_info.bufevent_data, EV_READ | EV_WRITE); // nastavi eventy pro buffer event, write callback se zavola jenom po tom, co user zapise ty data

            char msg1[] = "200 - command okay";

            printf("\n\nnova funkce implementovana send_messaage_queue");
            fflush(stdout);
            send_message_queue(ftp_user_info.control_queue, msg1, strlen(msg1) + 1, "mq_send() selhal - execute_commands");
            printf("\n\npo nove funkci send_messaage_queue");
            fflush(stdout);

            pthread_t bufevent_data_base_thread;
            if (pthread_create(&bufevent_data_base_thread, NULL, run_ev_base_loop, NULL) != 0) {
                perror("pthread_create() selhal - execute_command - PORT");
                exit(EXIT_FAILURE);
            }

            if (pthread_detach(bufevent_data_base_thread) != 0) {
                perror("pthread_detach() selhal - execute_command - PORT");
                exit(EXIT_FAILURE);
            }

            for (int i = 0; i < 6; i++) {
                free(array[i]);
            }
            free(array);
        }
        else if (ftp_user_info.ftp_sockets_obj.ftp_data_com == -1) {
            char msg2[] = "125 - Data connection already open; transfer starting";
            send_message_queue(ftp_user_info.control_queue, msg2, strlen(msg2) + 1, "mq_send() selhal - execute_commands");
        }

        // // pokud delka je variable a chci to vyzerooutovat, tak je potreba memset, pokud je to compile time konstanta, tak je to v poradku
        // // pokud bych tadu prijmul zpravu z control queue, tak by to potom cekalo donekonecna v control_send_ftp() na mq_receive() a protoze tato funkce je volana asznchrone z eventu tak pokud to zamrzlo tak event_base loop nemuze jit na dalsi event => stuckle
        // // char message[QUEUE_MESSAGE_LEN];
        // // memset(message, 0, QUEUE_MESSAGE_LEN);

        // // mq_receive(control_queue, message, QUEUE_MESSAGE_LEN, NULL);
        // // printf("\n\n\n\n\n\n\n\n\n\nmessage: %s", message);

        // // struct mq_attr attr;
        // // mq_getattr(control_queue, &attr);
        // // printf("\ncurrent messages: %d", attr.mq_curmsgs);
        // // printf("\ntady to je u portu ted\n");
        // // fflush(stdout);
        // exit(EXIT_FAILURE);
        // ted kdyz jsme udelali data connection, tak musime nastavit bufferevent a event_loop na tomto socket descriptoru a ty callbacky, stejne u PASV

        // ("501 - Syntax error in parameters or arguments")
        // aktivni - data connection - server initiates
    }
    else if (strstr(command, "PASV") != NULL) {
        printf("\nPASV execute commands, %d", ftp_user_info.user_loggedin);
        fflush(stdout);
        // passive - client starts every connection, server listens
        // ("227 - Entering Passive Mode (h1,h2,h3,h4,p1,p2)")
        // if (ftp_sockets_obj.ftp_data_com == -1) {
        //     char msg2[] = "125 - Data connection already open; transfer starting";
        //     if (mq_send(control_queue, msg2, strlen(msg2) + 1, 30) == -1) {
        //         perror("mq_send() selhal - execute_commands");
        //         exit(EXIT_FAILURE);
        //     }
        // }
        if (ftp_user_info.user_loggedin == 1) {
            int yes = 1;

            // int ftp_data_socket = socket(ftp_user_info.server_data_info.sin_family, SOCK_STREAM, 0);
            // if (ftp_data_socket == -1) {
            //     perror("socket selhal - ftp_data");
            //     exit(EXIT_FAILURE);
            // }

            // int optvalftp3 = 1;
            // int optvalftp4 = 1;
            // if ( (setsockopt(ftp_data_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optvalftp3, sizeof(int))) == -1 || (setsockopt(ftp_data_socket, IPPROTO_TCP, TCP_NODELAY, &optvalftp4, sizeof(int))) == -1) {
            //     perror("setsockopt() selhal - ftp_data");
            //     exit(EXIT_FAILURE);
            // }

            // if ( inet_pton(ftp_user_info.server_data_info.sin_family, "127.0.0.1", &ftp_user_info.server_data_info.sin_addr) <= 0) {
            //     perror("inet_pton() selhal - ftp_data");
            //     exit(EXIT_FAILURE);
            // }
            if ((ftp_user_info.ftp_sockets_obj.ftp_data_socket = socket(ftp_user_info.server_data_info.sin_family, SOCK_STREAM, 0)) == -1) {
                perror("socket() selhal - execute_commands - PASV");
                exit(EXIT_FAILURE);
            }

            printf("\n\nftp_sockets_obj.ftp_data_socket: %d", ftp_user_info.ftp_sockets_obj.ftp_data_socket);
            // setsockopt MUSI BYT pred bind(), listen(), accept(), connect(), PROTOZE TO MENI JAK SE TEN SOCKET BUDE CHOVAT
            if ( (setsockopt(ftp_user_info.ftp_sockets_obj.ftp_data_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &yes, sizeof(int))) == -1) {
                perror("setsockopt() selhal - execute command - PASV");
                exit(EXIT_FAILURE);
            }

            if ( bind(ftp_user_info.ftp_sockets_obj.ftp_data_socket, (struct sockaddr *)&ftp_user_info.server_data_info, sizeof(ftp_user_info.server_data_info)) == -1) {
                perror("bind() selhal - ftp_data");
                exit(EXIT_FAILURE);
            }

            // pokud se to bude bindovat 2., tak to vrati error invalid argument
            // if ( (bind(ftp_sockets_obj.ftp_data_socket, (struct sockaddr *)&ftp_user_info.server_data_info, sizeof(ftp_user_info.server_data_info))) == -1){
            //     perror("bind() selhal - execute commands - PASV");
            //     exit(EXIT_FAILURE);
            // }

            if ( listen(ftp_user_info.ftp_sockets_obj.ftp_data_socket, BACKLOG) == -1) {
                perror("listen() selhal - execute commands - PASV");
                exit(EXIT_FAILURE);
            }

            if ((ftp_user_info.ftp_sockets_obj.ftp_data_com = accept(ftp_user_info.ftp_sockets_obj.ftp_data_socket, NULL, NULL)) == -1) {
                perror("accept() selhal - execute commands - PASV");
                exit(EXIT_FAILURE);
            }
            evutil_make_socket_nonblocking(ftp_user_info.ftp_sockets_obj.ftp_data_socket);

            printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\naccepted\n\n");
            fflush(stdout);

            // // vetsinou se setsockopt() ma davat pred bind(), listen(), accept(), connect(), ale pry jsou i nejaky options, ktere se maji dat az po
            // if (setsockopt(ftp_sockets_obj.ftp_data_com, SOL_SOCKET | SO_REUSEPORT, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            //     perror("setsockopt() selhal - execute command - PASV");
            //     exit(EXIT_FAILURE);
            // }
            evutil_make_socket_nonblocking(ftp_user_info.ftp_sockets_obj.ftp_data_com);

            ftp_user_info.evbase_data = event_base_new();
            ftp_user_info.timeout_data.tv_sec = 3;
            ftp_user_info.timeout_data.tv_usec = 0;
            ftp_user_info.event_timeout_data = event_new(ftp_user_info.evbase_data, -1, EV_PERSIST | EV_TIMEOUT, reset_timeval_struct_data, NULL);
            event_add(ftp_user_info.event_timeout_data, &ftp_user_info.timeout_data);

            // if (fcntl(ftp_sockets_obj.ftp_data_com, F_SETFL, O_NONBLOCK) == -1) { // musi byt nonblocking, aby se to mohlo dat do bufferevent_socket_new()
            //     perror("fcntl() selhal - neslo nastavit O_NONBLOCK - handle_command_function");
            //     exit(EXIT_FAILURE);
            // }
            
            ftp_user_info.bufevent_data = bufferevent_socket_new(ftp_user_info.evbase_data, ftp_user_info.ftp_sockets_obj.ftp_data_com, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE); // BEV_OPT_UNLOCK_CALLBACKS

            void (*bufevent_write_data)(struct bufferevent *bufevent_control, void *ptr_arg) = &bufevent_write_cb_data;
            void (*bufevent_read_data)(struct bufferevent *bufevent_control, void *ptr_arg) = &bufevent_read_cb_data;
            void (*bufevent_event_data)(struct bufferevent *bufevent_both, short events, void *ptr_arg) = &bufevent_event_cb_data;
            bufferevent_setcb(ftp_user_info.bufevent_data, bufevent_read_data, bufevent_write_data, bufevent_event_data, NULL); // 2. pointer, ktery budou chtit
            bufferevent_enable(ftp_user_info.bufevent_data, EV_READ | EV_WRITE);

            char *address = (char *)malloc(INET_ADDRSTRLEN); // 255.255.255.255 => 15 + \0 => INET_ADDRSTRLEN
            if ( !inet_ntop(ftp_user_info.server_data_info.sin_family, (struct sockaddr *)&ftp_user_info.server_data_info.sin_addr.s_addr, address, INET_ADDRSTRLEN)) {
                perror("inet_ntop() selhalo - execute_commands - PASV");
            }
            
            for (int i = 0; i < INET_ADDRSTRLEN; i++) {
                if (address[i] == '.') {
                    address[i] = ',';
                }
            }
            ftp_user_info.server_data_info.sin_port = htons(DATA_PORT);
            unsigned char *port_array = (unsigned char *)&ftp_user_info.server_data_info.sin_port;
            int st_Byte_port = port_array[0];
            int nd_Byte_port = port_array[1];

            char *reply = (char *)malloc(50);
            memset(reply, 0, 50);
            snprintf(reply, 49, "227 Entering Passive Mode (%s,%d,%d)", address, st_Byte_port, nd_Byte_port); // prida i \0
            
            send_message_queue(ftp_user_info.control_queue, reply, strlen(reply) + 1, "mq_send() selhal - execute_commands");

            // struct timeval je u event base protoze ty notifikace jsou spozdene, tak prave k tomu to tam je, aby porad bylo nejake podniceni te event_base, aby nezaostavala

            pthread_t bufevent_data_base_thread;
            if (pthread_create(&bufevent_data_base_thread, NULL, run_ev_base_loop, NULL) != 0) {
                perror("pthread_create() selhal - execute_command - PORT");
                exit(EXIT_FAILURE);
            }

            if (pthread_detach(bufevent_data_base_thread) != 0) {
                perror("pthread_detach() selhal - execute_command - PORT");
                exit(EXIT_FAILURE);
            }

            free(address);
            free(reply);
        }
    }
    else {
        char msg1[] = "202 - Command not implemented, superfluous at this site"; // superfluous => nadbytecny 
        send_message_queue(ftp_user_info.control_queue, msg1, strlen(msg1) + 1, "mq_send() selhal - execute commands - QUIT");
    }
    // printf("\n\npred control_send_ftp: %s", command);
    // fflush(stdout);

    ftp_user_info.new_event_timeout.tv_sec = 4;
    ftp_user_info.new_event_timeout.tv_usec = 0;

    ftp_user_info.timeout_control.tv_sec = 5;
    ftp_user_info.timeout_control.tv_usec = 0;

    ftp_user_info.timeout_data.tv_sec = 3;
    ftp_user_info.timeout_data.tv_usec = 0;

    // if (ftp_user_info.event_timeout_data != NULL) {
    //     event_add(ftp_user_info.event_timeout_data, &ftp_user_info.timeout_data);
    // }
    

    control_send_ftp(ftp_user_info.bufevent_control);
}

char *read_contents_ftp(char *path) {
    // char *carriage_return = strstr(path, "\r");
    // if (carriage_return == NULL) {
    //     perror("strstr() selhal - read_contents_ftp");
    //     exit(EXIT_FAILURE);
    // }
    // int carriage_return_i = (int)(carriage_return - path);

    // path[carriage_return_i + 1] = '\0';
    // path[carriage_return_i] = '\0';

    int fd = open(path, O_RDONLY);
    printf("\n\n\npath a fd v read_contents_ftp: %s, %d\n\n", path, fd);
    
    fflush(stdout);
    if (fd == -1) {
        perror("open() selhal - read_contents_ftp");
        exit(EXIT_FAILURE);
    }

    printf("\n\n\n\n%s", path);
    fflush(stdout);
    // pokud bychom meli FILE *, tak musime pouzit fileno() pro ziskani file descriptoru
    struct stat info;

    // stat/fstat/lstat
    if (stat(path, &info) == -1) {
        perror("stat() selhal - read_contents_ftp");
        exit(EXIT_FAILURE);
    }

    size_t len_file = info.st_size;
    char *data_from_file = (char *)malloc(len_file); // file s jednim znakem vytvoreny s nano => 2 Bytes pokud to => char + \n, pokud je to vytvoreno pomoci usera, tak jenom => char, FILES NEMAJI NULL CHARACTER!!

    ssize_t bytes_read;
    size_t total_bytes = 0;

    while (1) {
        bytes_read = read(fd, data_from_file + total_bytes, len_file - total_bytes);
        total_bytes = total_bytes + bytes_read;

        if (total_bytes == len_file) {
            return data_from_file;
        }
        else if (bytes_read == -1) {
            perror("read() selhal - read_contents_ftp");
            exit(EXIT_FAILURE);
        }
    }   
}

char **get_account_information(char *client_information) {
    char *st_ampersand = strstr(client_information, "&");
    if (st_ampersand == NULL) {
        fprintf(stderr, "strstr() nenasel prvni ampersand - get_account_information");
        exit(EXIT_FAILURE);
    }
    int st_ampersand_i = (int)(st_ampersand - client_information);

    char *username = (char *)malloc(9);
    memset(username, 0, 9);
    for (int i = 0; i < st_ampersand_i; i++) {
        username[i] = client_information[i];
    }

    char *nd_ampersand = strstr(client_information + st_ampersand_i + 1, "&");
    if (nd_ampersand == NULL) {
        fprintf(stderr, "strstr() nenasel druhy ampersand - get_account_information");
        exit(EXIT_FAILURE);
    }
    int nd_ampersand_i = (int)(nd_ampersand - client_information);

    char *password = (char *)malloc(9);
    memset(password, 0, 9);

    int password_i = 0;
    for (int i = nd_ampersand_i + 1; i < strlen(client_information) + 1 - 3; i++) {
        password[password_i++] = client_information[i];
    }

    char **account_info = (char **)malloc(2 * sizeof(char *));
    account_info[0] = (char *)malloc(9);
    account_info[1] = (char *)malloc(9);
    memset(account_info[0], 0, 9);
    memset(account_info[1], 0, 9);

    strcpy(account_info[0], username);
    strcpy(account_info[1], password);

    free(username);
    free(password);

    return account_info;
}

// nemusime implementovat event_cb, protoze kazda funkce dostava short events, kde muzeme treba zjistit, jestli peer disconectnul socket
void bufevent_read_cb_control(struct bufferevent *bufevent_control, void *ptr_arg) {
    // v bufferu muzou byt vice TCP segmentu (data z TCP segmentu)
   printf("\n\nREAD_CB_CONTROL\n\n");
   fflush(stdout);
//    exit(EXIT_FAILURE);

   struct evbuffer *new_evbuffer = evbuffer_new();

   int ret_value = bufferevent_read_buffer(ftp_user_info.bufevent_control, new_evbuffer);
    // protoze bufferevent_write pouziva read/write, tak muzeme dostat 0 Bytes, protoze bud se peer disocnectnul nebo jsme pouze dostali 0 Bytes, proto musime kontrolovat i flags
    size_t length = evbuffer_get_length(new_evbuffer);
    char data[length + 1];

    if (evbuffer_remove(new_evbuffer, data, length) == -1) {
        perror("evbuffer_remove() selhal - #bufevent_read_cb_control");
        free_all();
    }

    if (strstr(data, "&<>&") != NULL) { // pri login
        char **account_info = get_account_information(data);

        // prirazeni memory accouont_info[0] do ftp_user_info.username, takze pokud se zrusi jeden pointer, tak i vsechny ostatni jsou neplatne
        // toto znamena, ze ftp_user_info.username se nastavi na memory adresu account_info[0], pokud se zrusi i to, tak se znehodnoti i ten druhy pointer
        // ftp_user_info.username = account_info[0];
        ftp_user_info.username = strdup(account_info[0]); // proto se to musi dat na heap, aby nebyl problem
        ftp_user_info.password = strdup(account_info[1]);

        printf("\n\n\n\ndata: %s", data);
        fflush(stdout);

        free(account_info[0]);
        free(account_info[1]);
        free(account_info);
        
        ftp_user_info.user_loggedin = 1;
        send_conformation_account(ftp_user_info.bufevent_control, 0);
        // user je prihlasen
    }
    else if (strstr(data, "<&&>") != NULL) { // u quit
        printf("\n\n\nftp_user_info.username: %s, ftp_user_info.password: %s", ftp_user_info.username, ftp_user_info.password);
        fflush(stdout);
        // exit(EXIT_FAILURE);
        if (ftp_user_info.username != NULL && ftp_user_info.password != NULL) {
            printf("\n\n\n\nDEALOKACE USERNAME PASSWORD LAST_PATH");
            fflush(stdout);
            free(ftp_user_info.username); // free nezerouje memory!
            free(ftp_user_info.password);
            free(ftp_user_info.last_path);

            ftp_user_info.username = NULL;
            ftp_user_info.password = NULL;
            ftp_user_info.last_path = NULL;

            ftp_user_info.user_loggedin = 0;
            ftp_user_info.quit_command_now = 1;

            close(ftp_user_info.ftp_sockets_obj.ftp_data_com);
            ftp_user_info.ftp_sockets_obj.ftp_data_com = -1;        
        }
        printf("\n\n\n\n\n\nQUIT");
        fflush(stdout);
        send_conformation_account(ftp_user_info.bufevent_control, 1);
        // break; // protoze se potrebuje jeste neco udelat u QUIT v execute_commands
        return;
    }
    else if (strstr(data, "!END!") != NULL) {
        fprintf(stderr, "\nklient ukoncil proces");
        _exit(EXIT_FAILURE);
    }

    char *crlf_end = strstr(data, "\n");
    /* data musi byt pointer, aby tento komentar fungoval*/
    // if (crlf_end == NULL || strstr(data, "\r") == NULL) {
    //     fprintf(stderr, "\nclient neukoncil svoji zpravu s CRLF");
    //     char *data_new_space = realloc(data, length + 3);

    //     data_new_space[strlen(data_new_space)] = '\r';
    //     data_new_space[strlen(data_new_space)] = '\n';
    //     data_new_space[strlen(data_new_space)] = '\0';

    //     crlf_end = strstr(data, "\n");
    // }

    int crlf_end_i = (int)(crlf_end-data);

    data[crlf_end_i + 1] = '\0'; // funkce ocekavaji \r\n konec commandu

    printf("\n\n\nstrlen(data): %zu %s, crlf_end_i: %d", strlen(data), data, crlf_end_i); // tady buffer overflow, at tam neni zbytecne +5 - Christ is God!
    fflush(stdout);

    char *command_to_execute = (char *)malloc(strlen(data) + 1); // +1 pro \0
    memset(command_to_execute, 0, strlen(data) + 1);

    memcpy(command_to_execute, data, strlen(data) + 1); // strcpy kopiruje string az do \0 (konci prave na \0), strcpy delal buffer overflow
    printf("\n\n\nhaloooooo %s\n\n", command_to_execute);
    fflush(stdout);
    execute_commands(command_to_execute, ftp_user_info.bufevent_control);
    
    printf("\n\n\ntohle se vykona");
    fflush(stdout);
    free(command_to_execute);
    evbuffer_free(new_evbuffer);
    // strstr() nevraci malloced memory, jenom vraci str + x Bytes v tom stringu

    // UDP dela to, ze pokud supplied buffer je mensi nez samotna zprava, tak se naplni buffer a potom se zbytek dat orizne, zatimco TCP toto nedela a data cekaji v TCP stack bufferu
    // ftp commands jsou ukonceny CRLF jako v Telnetu (\r\n)
}

char *insert_crlf(char *response) {
    int response_len = strlen(response) + 1;

    char *new_response = (char *)malloc(response_len + 2); // pro \r\n
    memset(new_response, 0, response_len + 2);

    strcpy(new_response, response);
    new_response[response_len - 1] = '\r';
    new_response[response_len] = '\n';
    new_response[response_len + 1] = '\0';

    return new_response;
}

void control_send_ftp(struct bufferevent *bufevent_control) {
    // control/data connection
    // based on that either send file or send an ftp code
    // write vrati 0 jenom pri tom pokud je zprava 0 (pokud je to pry POSIX system, tak by to nemelo vratit 0, mozna pokud by size zpravy by bylo vetsi SSIZE_MAX => 32 767 => getconf SSIZE_MAX)

    printf("\nftp_user_info.username:%d control_send_ftp", ftp_user_info.user_loggedin);
    fflush(stdout);
    switch(ftp_user_info.user_loggedin) {
        case 0: // false
            if (ftp_user_info.username == NULL) {
                char *buf = "Name (!AVE CHRISTUX REX FTP SERVER!) Name: "; // nesmi byt free(), protoze je to string-literal, tak je to v read-only casti procesu
                char *new_buf = insert_crlf(buf);

                if (strlen(buf) > 0) { // protoze bufferevent_write() vraci 0 pro write, tak je to jenom takova ochrana
                    if (bufferevent_write(ftp_user_info.bufevent_control, new_buf, strlen(new_buf) + 1) == -1) { // da data do output bufferu (struct evbuffer) struct bufferevent
                        perror("bufferevent_write() selhal - write_control_cb - username");
                        exit(EXIT_FAILURE);
                    }
                }
                free(new_buf);
            }
            else if (ftp_user_info.password == NULL) {
                char *buf = "Password: ";
                char *new_buf = insert_crlf(buf);
                
                if (strlen(buf) > 0) {
                    if ( bufferevent_write(ftp_user_info.bufevent_control, new_buf, strlen(new_buf) + 1) == -1) {
                        perror("bufferevent_write() selhal - write_control_cb - password");
                        exit(EXIT_FAILURE);
                    }
                }
                free(new_buf);
            }
            break;
        case 1: // true
            struct mq_attr mq;
            mq_getattr(ftp_user_info.control_queue, &mq);
            printf("\nmessage_size: %ld", mq.mq_msgsize);
            fflush(stdout);


            char *received_message = (char *)malloc(QUEUE_MESSAGE_LEN);
            memset(received_message, 0, QUEUE_MESSAGE_LEN); // automaticky NULL terminated => uz i vime, kolik cca Bytes budeme psat            

            struct mq_attr attr;
            mq_getattr(ftp_user_info.control_queue, &attr);
            printf("\ncurrent messages: %d", attr.mq_curmsgs);
            printf("\ntady to je u portu ted\n");
            fflush(stdout);

            // tady se ceka porad
            if ( mq_receive(ftp_user_info.control_queue, received_message, QUEUE_MESSAGE_LEN, NULL) == -1) {
                perror("mq_receive() selhal - bufevent_write_cb_control");
                exit(EXIT_FAILURE);
            }
            else if (strlen(received_message) > 0) {
                char *new_received_message = insert_crlf(received_message);
                printf("\n\n\n\n\nmessage to client: %s", new_received_message);
                fflush(stdout);;
                if ( bufferevent_write(ftp_user_info.bufevent_control, new_received_message, strlen(new_received_message) + 1) == -1) {
                    perror("bufferevent_write() selhal - write_control_cb - loggedin - case 1");
                    exit(EXIT_FAILURE);
                }
                free(new_received_message);

                printf("\n\nTADY\nAVE CHRISTUS REX AVE MARIA\n\n");
                fflush(stdout);
            }
            free(received_message);
            
            // poslat codes z mqueue => z execute commands
            break;
        default:
            fprintf(stderr, "spatna hodnota u user_loggedin - bufevent_write_cb_control");
            fflush(stderr);
            exit(EXIT_FAILURE);
            break;
    }
    // pokud user logged in, tak pokracovat, pokud ne, tak poslat USER, PASS
}

void bufevent_write_cb_control(struct bufferevent *bufevent_control, void *ptr_arg) {
   printf("\nall data sent");
}

int save_file(char *path, char *data_received) {
    printf("\n\nsave_file()\n\n");
    fflush(stdout);
    
    int fd_new_file = open(path, O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID); // 4777
    int fd_save_info_file = open("./TXT/files.txt", O_APPEND | O_WRONLY, S_IRWXU | S_IRWXO | S_IRWXG | S_ISUID); // 4777
    
    if (fd_new_file == -1) {
        perror("open() selhal - save_file");
        exit(EXIT_FAILURE);
    }
    else if (fd_save_info_file == -1) {
        perror("open() selhal - save_file");
        exit(EXIT_FAILURE);
    }

    char *info_file = (char *)malloc(strlen(ftp_user_info.username) + strlen(path) + strlen(ftp_user_info.filename_to_save) + 4); // 2 space + \0, aby to bylo dobre terminovane, ale do file se nesmi zapsat \0, files nemaji v sobe \0
    memset(info_file, 0, strlen(ftp_user_info.username) + strlen(path) + strlen(ftp_user_info.filename_to_save) + 4);
    snprintf(info_file, strlen(ftp_user_info.username) + strlen(path) + strlen(ftp_user_info.filename_to_save) + 4, "\n%s %s %s", ftp_user_info.filename_to_save, path, ftp_user_info.username);

    ssize_t bytes_written1 = 0;
    size_t total_bytes1 = 0;
    while(1) {
        bytes_written1 = write(fd_save_info_file, info_file + total_bytes1, strlen(info_file) - total_bytes1);

        total_bytes1 += bytes_written1;
        if (bytes_written1 == -1) {
            perror("write() selhal - save_file");
            exit(EXIT_FAILURE);
        }
        else if (total_bytes1 == strlen(info_file)) {
            break;
        }
    }


    int len_of_data_received = strlen(data_received);
    ssize_t total_bytes2 = 0;
    size_t bytes_written2;

    if (len_of_data_received > 0) {
        while ( (bytes_written2 = write(fd_new_file, data_received + total_bytes2, len_of_data_received - total_bytes2)) != len_of_data_received) {
            if (bytes_written2 == -1) {
                perror("write() selhal - save_file");
                exit(EXIT_FAILURE);
            }

            total_bytes2 += bytes_written2;
        }
    }

    return 0;
}

void bufevent_event_cb_data(struct bufferevent *bufevent_data, short events, void *ptr_arg) {
    printf("\nBUFEVENT_EVENT_CB_DATA\n");
    fflush(stdout);
    
    printf("\n\n\nftp_user_info.quit_command_now: %d", ftp_user_info.quit_command_now);
    fflush(stdout);
    // sleep(3);
    if (ftp_user_info.quit_command_now == 1) {
        close(ftp_user_info.ftp_sockets_obj.ftp_data_com);
        ftp_user_info.ftp_sockets_obj.ftp_data_com = -1;
        ftp_user_info.quit_command_now = 0;
        return; // early return
    }
    printf("\n\n\n\n\n\nEVENT DATA\n\n\n");
    fflush(stdout);

    evutil_socket_t socket_to_close = bufferevent_getfd(ftp_user_info.bufevent_data);
    if (socket_to_close == -1) {
        fprintf(stderr, "\nbufferevent_getfd() selhal - bufevent_event_cb_data");
        free_all();
    }

    printf("\n\nTADY - bufevent_event_cb_data\n\n");
    fflush(stdout);

    if ((BEV_EVENT_EOF & events) == BEV_EVENT_EOF) {
        fprintf(stderr, "\nbufferevent_read() selhal - bufevent_event_cb_data");
        fprintf(stderr, "\npeer ukoncil connection - EOF - data connection - bufevent_event_cb_data");
        fflush(stderr);
        free_all();
    }
    else if ( (BEV_EVENT_ERROR & events) == BEV_EVENT_ERROR) {
        fprintf(stderr, "\nbufferevent_read() selhal - data connection - bufevent_event_cb_data");
        fflush(stderr);
        free_all(); 
    }
}

void bufevent_event_cb_control(struct bufferevent *bufevent_control, short events, void *ptr_arg) {
    printf("\n\n\n\n\n\nEVENT CONTROL\n\n\n");
    fflush(stdout);
    evutil_socket_t socket_to_close = bufferevent_getfd(ftp_user_info.bufevent_control);
    if (socket_to_close == -1) {
        fprintf(stderr, "\nbufferevent_getfd() selhal - bufevent_event_cb_data");
        _exit(EXIT_FAILURE);
    }

    if ((BEV_EVENT_EOF & events) == BEV_EVENT_EOF) {        
        fprintf(stderr, "\nbufferevent_read() selhal - control connection - bufevent_event_cb_control");
        fprintf(stderr, "\npeer ukoncil connection - EOF - control connection - bufevent_event_cb_control");
        fflush(stderr);
        free_all();
    }
    else if ( (BEV_EVENT_ERROR & events) == BEV_EVENT_ERROR) {
        fprintf(stderr, "\nbufferevent_read() selhal - control connection - bufevent_event_cb_control");
        fflush(stderr);
        free_all();
    }
}

char *precise_path() {
    char * precise_path = (char *)malloc(strlen("/tmp/ftp_downloaded/") + strlen(ftp_user_info.filename_to_save) + 1);
    memset(precise_path, 0, strlen("/tmp/ftp_downloaded/") + strlen(ftp_user_info.filename_to_save) + 1);

    snprintf(precise_path, strlen("/tmp/ftp_downloaded/") + strlen(ftp_user_info.filename_to_save) + 1, "/tmp/ftp_downloaded/%s", ftp_user_info.filename_to_save);
    return precise_path;
}

 void finish_receive(evutil_socket_t fd, short what, void *arg) {
    int bytes;
    if (ioctl(fd, FIONREAD, &bytes) == -1) { // podiva se, kolik bytes je v kernel bufferu
        perror("ioctl() selhal - #bufevent_read_cb_data");
        fflush(stderr);

        free_all();
    }
    else if (bytes == 0) {
        struct event *event_finish_receive = (struct event *)arg;
        event_del(event_finish_receive);
        event_base_loopbreak(ftp_user_info.evbase_data);
        return;
    }

    printf("bytes: %zu", bytes);
    fflush(stdout);

    char *new_data = malloc(bytes + 1);
    if (new_data == NULL) {
        perror("malloc() selhal - #bufevent_read_cb_data");
        fflush(stderr);

        free_all();
    }
    memset(new_data, 0, bytes + 1);


    size_t read_now, read_total = 0;
    if ( (read_now = bufferevent_read(ftp_user_info.bufevent_data, new_data + read_total, bytes + 1 - read_total)) == 0) {
        return;
    }
    read_total += read_now;

    printf("NEW_DATA: %s\nlen: %zu", new_data, strlen(new_data));
    fflush(stdout);
 }

int i_func = 0;
 void func_try(evutil_socket_t fd, short what, void *arg) {
    if (i_func == 0) {
        ftp_user_info.new_event_timeout.tv_sec = 4;
        ftp_user_info.new_event_timeout.tv_usec = 0;
        // puts("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nAHOOOJ TRY FUNC");
        printf("\n\n\n\n\n\n\n\nnAHOOOJ TRY FUNC");

        printf("\n\nTADY TO JE");
        event_base_dump_events(ftp_user_info.evbase_data, stdout);
        printf("\n\nTADY JE TO");

        // fprintf(stderr, "\n\n\n\n\n\n\n\nnAHOOOJ TRY FUNC");
        fflush(stdout);
        sleep(2);
    }
    else  {
        exit(EXIT_FAILURE);
    }
    i_func++;
    

    // exit(EXIT_FAILURE);
   
    
    
    // exit(EXIT_FAILURE);
    // free_all();
 }

void *finish_receive_wrapper(void *args) {
    // struct Arguments {
    //     struct event *event;
    //     void *ptr;
    // };
    // struct Arguments args;
    // args.bev = ftp_user_info.bufevent_data;
    // args.ptr = NULL;

    ftp_user_info.new_event_timeout.tv_sec = 4;
    ftp_user_info.new_event_timeout.tv_usec = 0;
    
    // exit(EXIT_SUCCESS);
    printf("\n\n\n\n\n\n\n\nfunc_try: %p", (void *)func_try);
    fflush(stdout);

    // evutil_socket_t fd = bufferevent_getfd(ftp_user_info.bufevent_data);
    struct event *event_call_read_cb_data = event_new(ftp_user_info.evbase_data, -1, EV_PERSIST | EV_TIMEOUT, func_try, NULL); // (void *)event_call_read_cb_data
    // event_active(event_call_read_cb_data, EV_TIMEOUT | EV_PERSIST | EV_READ | EV_WRITE, 0);
    if (event_add(event_call_read_cb_data, &ftp_user_info.new_event_timeout) == -1) {
        perror("event_add() selhal - #finish_receive_wrapper");

        free_all();
    }
    else {
        // event_pending(ftp_user_info)
        // event_active(event_call_read_cb_data, EV_PERSIST, 0);
        sleep(1);
        puts("\n\nTED TO JE TADY V TOM WRAPPERU");
        printf("\n%d",  ftp_user_info.ftp_sockets_obj.ftp_data_com);
        fflush(stdout);
    }
    // event_base_once(ftp_user_info.evbase_data, ftp_user_info.ftp_sockets_obj.ftp_data_com, EV_TIMEOUT | EV_PERSIST, func_try, NULL, &ftp_user_info.new_event_timeout);

    // free_all();
    // return NULL;
}



void bufevent_read_cb_data(struct bufferevent *bufevent_data, void *ptr_arg) {
    printf("tadyyy\n\n\n\n");
    fflush(stdout);
    
    printf("\nQUEUE_MESSAGE_LEN: %d", QUEUE_MESSAGE_LEN);
    fflush(stdout);

    char *filename = (char *)malloc(QUEUE_MESSAGE_LEN);
    if (filename == NULL) {
        perror("malloc() selhal - #bufevent_read_cb_data");
        free_all();
    }
    memset(filename, 0, QUEUE_MESSAGE_LEN);

    // char *data2 = malloc(1000);
    // bufferevent_read(ftp_user_info.bufevent_data, data2, 1000);
    // printf("\n\ndata2: %s", data2);

    if ( mq_receive(ftp_user_info.data_queue, filename, QUEUE_MESSAGE_LEN, NULL) == -1) {
        if (errno == EAGAIN) {
            perror("HALO JE TO EAGAIN");
            free_all();
        }
        perror("mq_receive() selhal - #bufevent_read_cb_data");
        exit(EXIT_FAILURE);
    }
    free(filename);
    
    while (1) {

        int bytes;
        int fd = bufferevent_getfd(ftp_user_info.bufevent_data);
        if (ioctl(fd, FIONREAD, &bytes) == -1) { // podiva se, kolik bytes je v kernel bufferu
            perror("ioctl() selhal - #bufevent_read_cb_data");
            fflush(stderr);

            free_all();
        }
        else if (bytes == 0) {
            return;
        }

        printf("bytes: %zu", bytes);
        fflush(stdout);

        char *new_data = malloc(bytes + 1);
        if (new_data == NULL) {
            perror("malloc() selhal - #bufevent_read_cb_data");
            fflush(stderr);

            free_all();
        }
        memset(new_data, 0, bytes + 1);

        bufferevent_flush(ftp_user_info.bufevent_data, EV_READ, BEV_FLUSH);

        // vetsinou pokud 0 = bud zadne data nebo error a ze skusenosti se ten error zachyti drive nez 0 bytes a zavola se nejdrive event_cb_data
        size_t read_now, read_total = 0;
        if ( (read_now = bufferevent_read(ftp_user_info.bufevent_data, new_data + read_total, bytes + 1 - read_total)) == 0) {
            puts("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nbufferevent_read() nema dalsi dostupne bytes");







            // struct Arguments {
            //     struct event *event;
            //     void *ptr;
            // };
            // struct Arguments args;
            // args.bev = ftp_user_info.bufevent_data;
            // args.ptr = NULL;

            ftp_user_info.new_event_timeout.tv_sec = 4;
            ftp_user_info.new_event_timeout.tv_usec = 0;
            
            // exit(EXIT_SUCCESS);
            printf("\n\n\n\n\n\n\n\nfunc_try: %p", (void *)func_try);
            fflush(stdout);

            // evutil_socket_t fd = bufferevent_getfd(ftp_user_info.bufevent_data);
            struct event *event_call_read_cb_data = event_new(ftp_user_info.evbase_data, -1, EV_PERSIST | EV_TIMEOUT, func_try, NULL); // (void *)event_call_read_cb_data
            // event_active(event_call_read_cb_data, EV_TIMEOUT | EV_PERSIST | EV_READ | EV_WRITE, 0);
            if (event_add(event_call_read_cb_data, &ftp_user_info.new_event_timeout) == -1) {
                perror("event_add() selhal - #finish_receive_wrapper");

                free_all();
            }
            else {
                // event_pending(ftp_user_info)
                // event_active(event_call_read_cb_data, EV_PERSIST, 0);
                sleep(1);
                puts("\n\nTED TO JE TADY V TOM WRAPPERU");
                printf("\n%d",  ftp_user_info.ftp_sockets_obj.ftp_data_com);
                fflush(stdout);
            }
            // event_base_once(ftp_user_info.evbase_data, ftp_user_info.ftp_sockets_obj.ftp_data_com, EV_TIMEOUT | EV_PERSIST, func_try, NULL, &ftp_user_info.new_event_timeout);

            // free_all();
            // return NULL;








            // pthread_t finish_receive;
            // if ( pthread_create(&finish_receive, NULL, finish_receive_wrapper, NULL) != 0) {
            //     perror("pthread_create() selhal - #bufevent_read_cb_data");

            //     free_all();
            // }

            // if (pthread_join(finish_receive, NULL) != 0) {
            //     perror("spatne xd");
            //     free_all();
            // }


            // if (pthread_detach(finish_receive) != 0) {
            //     perror("pthread_detach() selhal - #bufevent_read_cb_data");

            //     free_all();
            // }

            return;
        }
        read_total += read_now;

        printf("NEW_DATA: %s\nlen: %zu", new_data, strlen(new_data));
        fflush(stdout);

        
        sleep(5);
        printf("\n\n\n");
        fflush(stdout);
    }



    // struct evbuffer *new_evbuffer = evbuffer_new();
    // size_t length = 0, total_bytes = 1;
    // char *data = (char *)malloc(1);
    // if (data == NULL) {
    //     perror("malloc() selhal - #bufevent_read_cb_data");
    //     free_all();
    // }
    // memset(data, 0, length + 1);

    // for (;;) {
    //     int bytes;
    //     int fd = bufferevent_getfd(ftp_user_info.bufevent_data);
    //     ioctl(fd, FIONREAD, &bytes); // podiva se, kolik bytes je v kernel bufferu
    //     if (bufferevent_set_max_single_read(ftp_user_info.bufevent_data, bytes) == -1) {
    //         perror("bufferevent_set_max_single_read() selhal - #bufevent_read_cb_data");
    //         free_all();
    //     }

    //     int return_value = (bufferevent_read_buffer(ftp_user_info.bufevent_data, new_evbuffer));
    //     if (return_value == -1) {
    //         perror("bufferevent_read_buffer() selhal - #bufevent_read_cb_data");
    //         free_all();
    //     }
    //     printf("\n\nbytes: %d", bytes);
    //     fflush(stdout);
    //     // new_evbuffer = bufferevent_get_input(ftp_user_info.bufevent_data);

    //     length = evbuffer_get_length(new_evbuffer);
    //     if (length == 0) {
    //         break;
    //     }

    //     char *temp_data = (char *)realloc(data, total_bytes + length);
    //     if (temp_data == NULL) {
    //         perror("realloc() selhal - #bufevent_read_cb_data");
    //         free_all();
    //     }
    //     memset(temp_data, 0, total_bytes + length);
    //     data = temp_data;       

    //     if (evbuffer_remove(new_evbuffer, data, length) == -1) {
    //         perror("evbuffer_remove() selhal - #bufevent_read_cb_data");
    //         free(filename);
    //         free_all();
    //     }
    //     total_bytes += length;

    //     printf("\nlength: %d\ndata: %s", length, data);
    //     fflush(stdout);

    //     char *path = precise_path();
    //     printf("\n\n\n\n\n\n\n\n\n\n\n\npath: %s", path);
    //     printf("\n\n\ntak co tady to je");
    //     fflush(stdout);
    //     save_file(path, data); // tato funkce bud udela co ma, nebo skonci program => nemusime kontrolovat pomoci if statement

    //     if (strstr(data, "\r\n")) {
    //         break;
    //     }
    // }
    // if (length == 0) {
    //     bufferevent_write(ftp_user_info.bufevent_data, " ", 1);
    //     evbuffer_free(new_evbuffer);
    //     free(data);
    //     return;
    // }   
}

void bufevent_write_cb_data(struct bufferevent *bufevent_data, void *ptr_arg) {
    printf("\nall data sent");
}

// struct event, event_base, bufferevent, evbuffer
// event je samotny event, ktery se bude hlidat pro dany file descriptor
// event_base je struktura, kde mohou byt ulozene vsechny file descriptory a ty jejich eventy struct event structures
// bufferevent je abstraktura nad network I/O, kde kazdy bufferevent ma svuj vlastni event_base a pokud underlying vrstva prijme data, tak se zavolaji ty samotne callbacky
// evbuffer ma dva poslani: slouzi bud jako fronta u normalni buffer I/O, nebo je u bufferevent, kde slouzi k posilani dat
// takze pokud mame cb u event a u bufferevent, tak se zavola callback u bufferevent

// bufferevent ma input a output buffer, s tim ze input buffer je read a output buffer je write

// struct bufferevent *bufevent_control;
void *handle_ftp_connections(void *) {
    printf("\n=== handle_ftp_connections ===");
    fflush(stdout);
    // bufferevents pro ftp control com socket

    // int ftp_control_com = ftp_sockets_p->ftp_control_com; // nebude zmateni, kompilator vi, ze nalevo je promenna a napravo je clen struktury, proto si to nepoplete
    // // kdyz nevime delku zpravi, tak bud musime poslat pred samotnou zpravou, kolik Bytes to bude chtit nebo udelame non-blocking socket => libevent
    // ftp_sockets_p->control_or_data = CONTROL;

    ftp_user_info.evbase_control = event_base_new(); // default settings
    if (ftp_user_info.evbase_control == NULL) {
        perror("event_base_new() selhal - data_connection");
        exit(EXIT_FAILURE);
    }

    /*
    struct timeval
    kdyz se neco posle pres bufferevent_write() nebo precte pres bufferevent_read(), tak jeste pred tim nez se zavolaji tyto funkce, tak se uz spusti event_base_loop, coz znamena, ze tento thread by byll zasekly v select(), epoll() apod. a ceka se na nejaky event prave na underlying socketu, jediny event, ktery ta druha strana muze udelat je ukoncit socket, pokud se toto udela, select(), epoll() uvidi ze je novy event, tento se zaregistruje a potom se event_base_loop() zase podiva na eventy, ktere ma v event_base, kde uz je prave treba ten read/write a az potom se to udela, ale druha strana uz zavrela socket

    nebo by client mohl posilat vzdy 2 zpravy aby jedna se zaregistrovala a ta druha by slouzila pro precteni, toto je ale implementacne tezke a zbytecne, proto diky Bohu, se muze udelat persistivni TIMEOUT event, ktery v event_base zustane a bude se pripominat podle toho, jak se nastavi struktura timeval
    */

    // event se bude opakovat kazdou sekundu
    ftp_user_info.timeout_control.tv_sec = 5;
    ftp_user_info.timeout_control.tv_usec = 0;    


    // if (fcntl(ftp_sockets_obj.ftp_control_com, F_SETFL, O_NONBLOCK) == -1) { // musi byt nonblocking, aby to mohlo ji do bufferevent_socket_new()
    //     perror("fcntl() selhal - neslo nastavit O_NONBLOCK - handle_command_function");
    //     exit(EXIT_FAILURE);
    // }

    evutil_make_socket_nonblocking(ftp_user_info.ftp_sockets_obj.ftp_control_com); // musi byt volane pred event_new()
    evutil_make_socket_nonblocking(ftp_user_info.ftp_sockets_obj.ftp_control_socket);
    ftp_user_info.event_timeout_control = event_new(ftp_user_info.evbase_control, -1, EV_PERSIST | EV_TIMEOUT, reset_timeval_struct_control, NULL); // function a argumenty nemusi byt, protoze jenom je potreba porad aktualizovat ten event_base
    event_add(ftp_user_info.event_timeout_control, &ftp_user_info.timeout_control);

    ftp_user_info.bufevent_control = bufferevent_socket_new(ftp_user_info.evbase_control, ftp_user_info.ftp_sockets_obj.ftp_control_com, BEV_OPT_CLOSE_ON_FREE); // thread safe // BEV_OPT_UNLOCK_CALLBACKS
    if (ftp_user_info.bufevent_control == NULL) {
        perror("bufferevent_socket_new() selhal - handle_ftp_connections");
        exit(EXIT_FAILURE);
    }
    printf("\n=== code runs to this point - AVE CHRISTUS REX");
    fflush(stdout);

    void (*bufevent_write_control)(struct bufferevent *bufevent_control, void *ptr_arg) = &bufevent_write_cb_control;
    void (*bufevent_read_control)(struct bufferevent *bufevent_control, void *ptr_arg) = &bufevent_read_cb_control;
    void (*bufevent_event_control)(struct bufferevent *bufevent_control, short events, void *ptr_arg) = &bufevent_event_cb_control;
    bufferevent_setcb(ftp_user_info.bufevent_control, bufevent_read_control, bufevent_write_control, bufevent_event_control, NULL); // prvni NULL je pro eventcb, coz by melo byt ale stejny cb jako u event_base, ftp_sockets_p je pointer na argumenty ke vsem temto funkcim
    bufferevent_enable(ftp_user_info.bufevent_control, EV_READ|EV_WRITE);

    // edge-trigger event a level event trigger
    // toto se pouziva i digitalnich obvodech, ale v trochu jinem svetle, ale predstavme si 0 a 1 a stav mezi nimi, zkracene to znamena kdyz mame nejake event (hodnotu 0 nebo 1), tak u level event trigger dostaneme notifikaci s tim, ze event byl spusten a tato notifikace nam zustane porad nekde ulozena (u epoll events nebo u libevent), ale porad tam bude napsane, ze je mozno neco udelat, ale kdyz to bude edge trigger, tak dostaneme jenom tu notifikaci o tom, ze neco je pripravene a tuto notifikaci dostaneme jenom jednou do te doby nez treba ten socket neprecteme z neho vsechny data a potom az muzeme dostat dalsi upozorneni od onoho socketu, takovy nonblocking upozorneni


    // toto nepotrebujeme, toto za nas dela bufferevent, toto je jenom pro samotny socket
    // struct event *event_read = event_new(evbase_control, ftp_control_com, EV_READ | EV_WRITE, event_callback, NULL); // initialized event
    // event_add(event_read, NULL); // event pending, to druhe je pro timeval struct pro timeval struct, proto, aby se v event loopu cekalo na ten timeout a potom se reklo, jestli se ten event opravdu stal nebo ne

    // evbase control se naplni interne
    // https://stackoverflow.com/questions/70432388/libevent-running-the-loopevent-base-loop
    // event_base_loop(evbase_control, EVLOOP_NO_EXIT_ON_EMPTY); // EVLOOP_NONBLOCK tam nemuze byt protoze kdyby nebyly eventy, tak se to ukonci, paradox // bude cekat nez se nejake eventy udelaji ready a pokud zadne nebudou ready, tak se z tohoto loopu nevyskoci
    
    printf("\n\n\n\n\n\n\n\n\n\n\n=== code runs to this point - AVE MARIA ===\n\n\n\n\n\n\n\n\n");
    fflush(stdout);

    event_base_loop(ftp_user_info.evbase_control, EVLOOP_NO_EXIT_ON_EMPTY); // , EVLOOP_NO_EXIT_ON_EMPTY
}

void *select_ftp() {
    int optvalftp = 1;
    if ( (setsockopt(ftp_user_info.ftp_sockets_obj.ftp_control_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optvalftp, sizeof(int))) == -1) {
        perror("setsockopt() selhal - select_ftp");
        exit(EXIT_FAILURE);
    }

    if ( bind(ftp_user_info.ftp_sockets_obj.ftp_control_socket, (struct sockaddr *)&ftp_user_info.server_control_info, sizeof(ftp_user_info.server_control_info)) == -1) {
        perror("bind() selhal - select_ftp");
        exit(EXIT_FAILURE);
    }

    // clock_t time = clock() / CLOCKS_PER_SEC;

    if ( listen(ftp_user_info.ftp_sockets_obj.ftp_control_socket, BACKLOG) == -1) {
        perror("listen() selhal - select_ftp");
        exit(EXIT_FAILURE);
    }

    printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n=== Acceptovani control_socket ===");
    if ((ftp_user_info.ftp_sockets_obj.ftp_control_com = accept(ftp_user_info.ftp_sockets_obj.ftp_control_socket, NULL, NULL)) == -1) {
        perror("accept() selhal - select_ftp");
        // exit(EXIT_FAILURE);
    }

    if (ftp_user_info.control_queue == -1 || ftp_user_info.data_queue == -1) {
        ftp_user_info.control_queue = mq_open(CONTROL_QUEUE_NAME, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID, &global_mq_setting); // 4777

        if (ftp_user_info.control_queue == -1) {
            perror("mq_open() selhal - select_ftp()");
            exit(EXIT_FAILURE);
        }

        ftp_user_info.data_queue = mq_open(DATA_QUEUE_NAME, O_CREAT | O_RDWR, S_IRWXU | S_IRWXO | S_IRWXG | S_ISUID, &global_mq_setting); // 4777 -> /name pokud bude tady nekde mq_open se stejnou hodnotou, tak se to odkazuje na tu stejnou mqueue
        if (ftp_user_info.data_queue == -1) {
            perror("mq_open() selhal - select_ftp()");
            exit(EXIT_FAILURE);
        }
    }

    pthread_t thread_control;
    void *(*handle_ftp_p)(void *) = &handle_ftp_connections;
    if ( (pthread_create(&thread_control, NULL, handle_ftp_p, NULL)) != 0) {
        perror("pthread_create() selhal - select_ftp");
        // exit(EXIT_FAILURE);
    }

    pthread_detach(thread_control);

    // if (nic) {
    //     // pthread_detach(thread_control);

    //     // if (pthread_detach(thread_control) != 0) {
    //     //     perror("pthread_detach() selhal - select_ftp()");
    //     //     exit(EXIT_FAILURE);
    //     // }

    //     /*

    //     // accept ma uz zabudovany pocet file descriptoru, ktere obslouzi, a to je 1024, je to pole typu long, kde kazdy bit je jeden file descriptor => bit. 256 => file descriptor 256
    //     // na jeden long je to 64 bitu (8 Bytes) => 1024 / 64 = 16, vetsinou tato maska je 16 Bytes velka
        
    //     // kdyz dereferencujeme void * pointer, tak kompilator nevi, kolik Bytes musi dereferencovat => warning, ale nemuzeme udelat, protoze si to kompilator nezapamatuje => casting je JEN ONE TIME THING, museli bychom typecastovat u kazdeho, proto radsi udelam novy pointer
    //     // (struct Ftp_Sockets *)ftp_sockets;
    //     printf("\n\nHALOOOO, ted jsem tady\n\n\n\n");

    //     // struct timeval nema zadne pocatecni hodnoty, proto se to musi nastavit obe
    //     struct timeval timeout;
    //     timeout.tv_sec = 5;
    //     timeout.tv_usec = 0;

    //     fd_set readbitmask;
    //     FD_ZERO(&readbitmask);
    //     FD_SET(ftp_sockets_obj.ftp_control_socket, &readbitmask);

    //     // read, write, exception
    //     // kousek na tom socketu prijme, kousek na tom socketu zapise, moc se nedeje, je to exception treba out of band data u TCP
    //     int nfds = ftp_sockets_obj.ftp_data_socket > ftp_sockets_obj.ftp_control_socket ? ftp_sockets_obj.ftp_data_socket : ftp_sockets_obj.ftp_control_socket;
    //     nfds++;
    //     int rv = select(50, &readbitmask, NULL, NULL, &timeout);
        
    //     printf("\n%d", rv);
    //     fflush(stdout);
    //     // select vraci total pocet vsech file desciptoru, ktere jsou volne na operaci (v ramci daneho fd_setu)
    //     // pokud se tento if statement nestane, tak ono prijde SYN => SYN queue, odesle se SYN + ACK => client je touto dobou uz pripojeny, posle ACK, ted je server pripojeny, ale je to pripojene jenom na kernel level, protoze server neudelal accept()! => z tohoto muze byt velky problem => SYN flood, connection pool flooding => DoS
    //     // atomicka operace je ta, ktera bezi bez preruseni
    //     if (rv == 1) {
    //         printf("\n\ntady ted je ftp_sockets_obj.ftp_control_socket ready");
    //         // proces ma 4 nejhlavnejsi identity => RUID (Real U - user ID), EUID (Effective UID), RGID (Real group id), EGID (Effective group id), nejhlavnejsi jsou ale RUID a EUID, AUID => je cislo, ktere se priradi userovi kdyz se prihlasi a pokazde kdyz ten user spusti nejaky program, tak ten proces zdedi tento AUID => audit user ID
    //         // pokud bude mode jiny nez ma samotny soubor, tak se to rozhodne podle implemetance UNIX/Linux, nase implementace bude mit permise 4777 -> man mq_open
            
    //         printf("\n\n\nANO, JE TO VSE OK\n\n\n\n\n");
    //         fflush(stdout);

    //         ftp_sockets_obj.ftp_data_com = -1;
    //         ftp_sockets_obj.ftp_control_com = accept(ftp_sockets_obj.ftp_control_socket, NULL, NULL);
    //         char temp_buf[10];
    //         snprintf(temp_buf, 10, "%s%c%c", "ahoj", 0x0d, 0x0a);
    //         send(ftp_sockets_obj.ftp_control_com, temp_buf, 10, 0);
    //         printf("\n\n\npo accept, ftp_cotnrol com: %d\n\n\n\n\n", ftp_sockets_obj.ftp_control_com);
            
    //         printf("\n\n\npo pthread_create\n\n\n\n\n");

    //         // ftp_sockets_p->ftp_data_com = accept(ftp_sockets_p->ftp_data_socket, NULL, NULL);
    //         // printf(":%d :%d", ftp_sockets_p->ftp_control_com, ftp_sockets_p->ftp_data_com);
    //         // fflush(stdout);
    //         return NULL;
    //     }
    //     else {
    //         printf("\n\n\n\nnestalo se\n\n\n\n");
    //         // exit(EXIT_FAILURE);
    //     }

    //     */
    // }
    
}

int main()
{
    // get_dynamic_files_table("/media/sf_projects_on_vm/FTP_SERVER/");
    // CRYPTO_set_mem_debug(1);
    // CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    signal(SIGINT, signal_handler);
    system("./unlink_mqs");
    system("python ./PYTHON/make_user_directories.py");
    printf("\n");
    event_enable_debug_mode();
    event_enable_debug_logging(EVENT_DBG_ALL);
    evthread_use_pthreads(); // abychom mohli pouzivat libevent s threads
    set_queue_message_len();
    // client ma toho vice na praci, protoze si musi nastavit taky kontext (jako server), nastavit sifry (jako server), musi mit logiku na overovani toho certifikatu,
    // kdyztak pridat nejake flags (jako server)
    // pokud client pouziva BIO, tak si musi cely handshake delat sam, pokud pouziva klasicke SSL_connect, tak se to udela automaticky

    // char *x = (char*)malloc(10);
    // na heapu bude 10 Bytes a protoze je to char *x, tak pole &x[0] bude pointer na char, takze jakoby pointer na char a char zaroven
    // a protoze malloc vraci void * protoze to nejspise podporuje filosofii, tady mas kus pameti, delej si s ni co chces
    // tak protoze mi dostaneme pointer na uplny zacatek, tak je potreba specifikovat na jaky datovy typ ten pointer bude ukazovat
    // char *x = (char *)malloc(10);

    initialization_of_openssl();

    method = TLS_server_method(); // SSL_METHOD je datova struktura popisujici internalni informace o protokolech, ktere se pouziji
    // TLS_server_metohd = chci TLS server, ktery pouzije jakoukoliv pouzitelnou verzi TLS

    if (method == NULL) {
        handle_error();
    }
    // openSSL nabizi tzv. BIO (Basic Input/Output), coz je zlehceny interface mezi vsemi input/output operacemi, slouzi pro soubory, sockety...
    // je to velice univerzalni, obsahuje to i filtry, pokud do kterych se zadaji data, tak se napr. zasifruji do urciteho formatu...
    // SSL_CTX je struktura, ktera obsahuje settings/nastaveni pro urcitou SSL/TLS komunikaci a obsahuje urcite flags => flags na verifikaci SSL_CTX_set_verify...
    // a nebo "normalni" flags pro beh komunikace a o siforach

    // SSL_CTX_set_verify_depth() kdyz ja si vygeneruji certifikat, tak ho dostanu od nejake firmy, ale tato firma nemusi byt tak znama, a proto by ji browser
    // nemusel verit, takze by komunikace zanikla, ale co kdyby se browser podival na ten muj certifikat a zjistil by, ze je "podepsany" od nejake firmy, ktere by browser veril, 
    // protoze je treba znamejsi, tak diky teto firme si browser rekne, ze tento certifikat je opravdu opravdicky a realny
    
    ctx = SSL_CTX_new(method); // aplikace informaci, ktere se pouziji do jedne "sablony" (frameworku), aby to bylo pohromade, malokuje memory!!
    if (ctx == NULL) {
        handle_error();
    }

    // nic nevraci
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // toto je pro servery => client nemusi posilat svuj certifikat => nemusi se nejak autorizovat, SSL_VERIFY_PEER => musi se poslat
    // musi byt nastaveno jedno nebo druhe, ale ne obe najednou   
    long options =  SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3; // neco je tam zbytecne
    // jako treba ty verze, protoze uz predtim verze jsem specifikoval
    SSL_CTX_set_options(ctx, options); // upravi pravidla SSL/TLS komunikace

    // PEM je textovy! => ja mam textovy => PEM
    // DER je binarni!

    if (SSL_CTX_use_certificate_file(ctx, "CERTS/server-cert.pem", SSL_FILETYPE_PEM) != 1) {
        handle_error();
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "CERTS/server-key.pem", SSL_FILETYPE_PEM) != 1) {
        handle_error();
    }

    // (void (*)() ), pretypovani funkce na funkci, ktera vraci void, ze to je pointer na funkci (*) a ze nevime, jake ma funkce paramtery ()!! NE ze nema, ZE TO "NEVIME"
    SSL_CTX_set_info_callback(ctx, (void (*)() )cb); // toto se aplikuje na "samotnou sablonu" => ctx

    // function pointer and its return value NEEDS NOT to be in (), that means casting and not a definition of a function pointer
    // int (*f_p_cb_alpn) (SSL *ssl_connection, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) = cb_alpn;
    // SSL_CTX_set_alpn_select_cb(ctx, f_p_cb_alpn, NULL); // POKUD se zajisti, ze client posle ALPN s listem, ktere by mohl pouzit (soucasti SSL/TLS handshake), tak pokud se zachyti tento request na ty protokly (ALPN), tak se
    // nastavi nova callback funkce, kde si muzeme udelat to, co chceme => vypsat nejake informace/spustit dalsi funkce/vybrat si protokol

    // protoze control connection bude porad a vzdycky navazana, tak se sockaddr_in muze naplnit uplne cela a jelikoz to bude vykonavat funkci serveru, tak ta IP adresa a port je dulezita pro klienta
    memset(&ftp_user_info.server_control_info, 0, sizeof(struct sockaddr_in)); // nejspise se muze dat pryc, protoze pri deklaraci uz je to dano na 0
    ftp_user_info.server_control_info.sin_family = AF_INET;
    ftp_user_info.server_control_info.sin_port = htons(CONTROL_PORT);
    // muze se do davat rovnou do te struktury, protoze ma jen jednoho clena a tam se kopiruji ty data a zrovna to vyjde na tu delku, ale kdyby tam byly dva cleny, tak je lepsi tam uvest samotneho clena te struktury
    if ( inet_pton(ftp_user_info.server_control_info.sin_family, "127.0.0.1", &ftp_user_info.server_control_info.sin_addr) <= 0) {
        perror("inet_pton() selhal - ftp_control");
        exit(EXIT_FAILURE);
    }

    // protoze data connection bud vubec nemusi nastat nebo muze nastat pomoci PASV nebo PORT, tak se tam lisi trochu rozdily, pomoci PASV, tak client initiates, takze staci naslouchat na nejakem portu a IP adrese, ale u PORT server plni funkci klienta a pripojuje se na klienta (ted jakoby server v tomto pripade) a musim znat IP adresu a port toho klienta, (coz se posle pres control connection), takze ta IP adresa a ten port mohou byt jine, proto se muze vyplnit jenom sin_family jako AF_INET, protoze tato implementace bude podporovat jenom IPv4

    // PASV = client initiates
    // PORT = server initiates
    memset(&ftp_user_info.server_data_info, 0, sizeof(struct sockaddr_in)); // nejspise se muze dat pryc, protoze pri deklaraci uz je to dano na 0
    ftp_user_info.server_data_info.sin_family = AF_INET;
    ftp_user_info.server_data_info.sin_port = htons(DATA_PORT);
    if ( inet_pton(ftp_user_info.server_data_info.sin_family, "127.0.0.1", &ftp_user_info.server_data_info.sin_addr) <= 0) {
        perror("inet_pton() selhal - ftp_data");
        exit(EXIT_FAILURE);
    }

    if ((ftp_user_info.ftp_sockets_obj.ftp_control_socket = socket(ftp_user_info.server_control_info.sin_family, SOCK_STREAM, 0)) == -1) {
        perror("socket() selhal - ftp_control");
        exit(EXIT_FAILURE);
    }

    // ftp_sockets_obj.ftp_control_socket = ;
    ftp_user_info.ftp_sockets_obj.ftp_control_com = -1;
    ftp_user_info.ftp_sockets_obj.ftp_data_socket = -1;
    ftp_user_info.ftp_sockets_obj.ftp_data_com = -1;

    pthread_t ftp_threadID;
    if (pthread_create(&ftp_threadID, NULL, select_ftp, NULL) != 0) {
        perror("pthread_create() selhal - ftp");
        printf("\n\n\n\n\n\n\nTADY V EXIT V MAIN");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    // CRYPTO_mem_leaks_fp(stdout);

    // je potreba toto udelat pro vice konekci, ted je to jen pro jednu
    // int ftp_control_com;
    // int ftp_data_com;
    // if (select_ftp(ftp_control_socket, ftp_data_socket) == EXIT_SUCCESS) { // 0
    //     ftp_control_com = accept(ftp_control_socket, NULL, NULL);

    //     ftp_data_com = accept(ftp_data_socket, NULL, NULL);
    // }



    // while (1) {

    // }












    struct sockaddr_in http_server_info;
    memset(&http_server_info, 0, sizeof(http_server_info));

    HTTPS_thread_specific = malloc(sizeof(struct HTTPS_Thread_Specific));
    if (HTTPS_thread_specific == NULL) {
        perror("malloc() selhal - main - http");
        free_all();
    }
    memset(HTTPS_thread_specific, 0, sizeof(struct HTTPS_Thread_Specific));

    struct sockaddr_storage httpclient_info;
    socklen_t httpclient_infolen = sizeof(httpclient_info);

    http_server_info.sin_family = AF_INET;
    http_server_info.sin_port = htons(8000);

    if ( inet_pton(AF_INET, "127.0.0.1", &http_server_info.sin_addr) != 1) {
        perror("inet_pton() selhal - http");
        return EXIT_FAILURE;
    }

    int http_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( http_socket == -1) {
        perror("socket() selhal - http");
        return EXIT_FAILURE;
    }

    int option_value = 1;

    if ( setsockopt(http_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option_value, sizeof(option_value)) == -1) {
        perror("setsockopt() selhal - http");
        return EXIT_FAILURE;
    }

    if ( bind(http_socket, (struct sockaddr *)&http_server_info, sizeof(http_server_info)) == -1) {
        perror("bind() selhal - http");
        return EXIT_FAILURE;
    }

   // webservery maji limit na to kolik mohou mit TCP spojeni v jednu dobu => je to 6-8 => toto ale znamena, ze muze webbrowser stahovat 6-8 souboru z jedne domeny, ale take zalezi na verzi HTTP, ale vetsinou ty browsery se snazi znovu pouzivat ty uz natolene TCP spojeni, takze 1 webbrowser, 1 stranka, 2 nebo vice oken otevrenych => 1 TCP spojeni => 1 TCP handshake

    // FD_ISSET() je makro bud vraci nenulovou hodnotu nebo 0 pokud socket neni pripraven, ale protoze to je makro tak nenastavuje errno promennou => nelze pouzit perror
    // error:0A000416:SSL routines::ssl/tls alert certificate unknown => od clienta, ze server nema veritelny certifikat, nebo ze je self-signed a client ukoncuje spojeni    

    printf("HALOOO");
    // system("firefox localhost:8000");
    fflush(stdout);

    if ( listen(http_socket, BACKLOG) == -1) {
        perror("listen() selhal - http");
        return EXIT_FAILURE;
    }

    // alokace globalnich pointeru
    HTTPS_global_info.THREADSPECIFIC_ARRAY = (struct HTTPS_Thread_Specific *)calloc(MAX_THREADS, sizeof(struct HTTPS_Thread_Specific));
    HTTPS_global_info.SSL_CONNECTIONS_ARRAY = (SSL **)calloc(MAX_THREADS, sizeof(SSL *));
    HTTPS_global_info.COMSOCKARRAY = (int *) calloc(MAX_THREADS, sizeof(int));
    HTTPS_global_info.EVENT_CONTEXT = (struct event_base **) calloc(MAX_THREADS, sizeof(struct event_base *));
    ACCOUNTS_USER_DATA_ARRAY = (struct User_Data *)calloc(MAX_THREADS, sizeof(struct User_Data));

    if (HTTPS_global_info.THREADSPECIFIC_ARRAY == NULL) { // nebo !ARRAYTHREAD
        perror("calloc() selhal - #main# - HTTPS_global_info.THREADSPECIFIC_ARRAY");
        exit(EXIT_FAILURE);
    }
    else if (HTTPS_global_info.SSL_CONNECTIONS_ARRAY == NULL) { // nebo !SSL_CONNECTIONS_ARRAY
        perror("calloc() selhal - #main# - HTTPS_global_info.SSL_CONNECTIONS_ARRAY");
        exit(EXIT_FAILURE);
    }
    else if (HTTPS_global_info.COMSOCKARRAY == NULL) {
        perror("calloc() selhal - #main# - HTTPS_global_info.COMSOCKARRAY");
        exit(EXIT_FAILURE);
    }
    else if (HTTPS_global_info.EVENT_CONTEXT == NULL) {
        perror("calloc() selhal - #main# - HTTPS_global_info.EVENT_CONTEXT");
        free_all();
    }
    else if (ACCOUNTS_USER_DATA_ARRAY == NULL) {
        perror("calloc() selhal - #main# - ACCOUNTS_USER_DATA_ARRAY");
        free_all();
    }

    // vezmi muj pointer comarray a chci aby se k tim datum v teto memory oblasti, ktera je ulozena prave v tomto pointeru, choval jako pointer na int>!
    // pointer na int => pointer (comarray) na pole int!!!
    // array[x] dostanu SAMOTNY ten prvek, je to alternativa *(array + x)

    // !!
    // SSL samotny objekt v OpenSSL NEEXISTUJE a nemel by se pouzivat, jenom POINTER NA SSL/POLE POINTERU NA SSL!!
    // nedokoncena struktura (opague type) = struktura, ktera neni viditelna v hlavickach a struktura, jejiz obsah je neznamy pri prekladu, pointer uz endela problemys opaque type
    // !!

    for(;;) {
        // dokoncit od thread_info
        if (CONNECTION == (MAX_THREADS - 1) ) {
            MAX_THREADS += 5;
            
            struct HTTPS_Thread_Specific *temp_threadspecific_array = (struct HTTPS_Thread_Specific *)realloc(HTTPS_global_info.THREADSPECIFIC_ARRAY, sizeof(struct HTTPS_Thread_Specific) * MAX_THREADS);
            SSL **temp_ssl_connections_array = (SSL **)realloc(HTTPS_global_info.SSL_CONNECTIONS_ARRAY, sizeof(SSL *) * MAX_THREADS);
            int *temp_comarray = (int *)realloc(HTTPS_global_info.COMSOCKARRAY, sizeof(int) * MAX_THREADS);
            struct User_Data *temp_user_data_array = realloc(ACCOUNTS_USER_DATA_ARRAY, sizeof(struct User_Data) * MAX_THREADS);
            struct event_base **temp_event_context_array = realloc(HTTPS_global_info.EVENT_CONTEXT, sizeof(struct event_base *) * MAX_THREADS); // realloc() stary blok memory automaticky uvolni, nemusim to delat manualne!
            
            if (temp_threadspecific_array == NULL) {
                perror("realloc() selhal - #main# - temp_threadspecific_array");
                free(temp_threadspecific_array);

                free_all();
            }
            if (temp_ssl_connections_array == NULL) {
                perror("realloc() selhal - #main# - temp_ssl_connections_array");
                free(temp_ssl_connections_array);
                
                free_all();
            }
            if (temp_comarray == NULL) {
                perror("realloc() selhal - #main# - temp_comarray");
                free(temp_comarray);
                
                free_all();
            }
            if (temp_user_data_array == NULL) {
                perror("realloc() selhal - #main# - temp_user_data_array");
                free(temp_user_data_array);
                
                free_all();
            }
            if (temp_event_context_array == NULL) {
                perror("realloc() selhal - #main# - temp_event_context_array");
                free(temp_event_context_array);
                
                free_all();
            }

            HTTPS_global_info.THREADSPECIFIC_ARRAY = temp_threadspecific_array;
            HTTPS_global_info.SSL_CONNECTIONS_ARRAY = temp_ssl_connections_array;
            HTTPS_global_info.COMSOCKARRAY = temp_comarray;
            ACCOUNTS_USER_DATA_ARRAY = temp_user_data_array;
            HTTPS_global_info.EVENT_CONTEXT = temp_event_context_array;
        }

        printf("\n\nAVE CHRISTUS REX\n\n");
        fflush(stdout);

        HTTPS_global_info.COMSOCKARRAY[CONNECTION] = accept(http_socket, (struct sockaddr *)&httpclient_info, &httpclient_infolen);
        if (HTTPS_global_info.COMSOCKARRAY[CONNECTION] == -1) {
            perror("accept() selhal - http");
            exit(EXIT_FAILURE);
        }
        // int *array = mallo()..., tak to pole se sklada z normalnich intu, ktere jsou ulozene na heapu hned za sebou, proto treba u realloc() se ukazuje na novou
        // memory lokaci, aby to bylo hezky za sebou, ALE my dostaneme POINTER ns tuto memory oblast, coz JE POINTER na int! 
        // ale pro ukladani muzeme jenom specifikovat ten pointer, nejaky offset a samotnou int hodnotu, protoze to je pole plne normalmich hodnot int

        HTTPS_global_info.SSL_CONNECTIONS_ARRAY[CONNECTION] = SSL_new(ctx); // vytvori novou SSL strukturu, ktera v sobe drzi real time informace o pripojeni, pouziva malloc!
        if (HTTPS_global_info.SSL_CONNECTIONS_ARRAY[CONNECTION] == NULL) {
            printf("connections_array");
            fflush(stdout);
            handle_error();
        }

        // HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION] = pthread_self();
        // if (HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION] != pthread_self()) {
        //     fprintf(stderr, "\nprirazovani thread_self() do HTTPS_global_info.THREADSPECIFIC_ARRAY selhal - main\n");
        //     free_all();
        // }

        SSL_set_accept_state(HTTPS_global_info.SSL_CONNECTIONS_ARRAY[CONNECTION]); // explicitni oznaceni, ze tento kod bude pracovat jako server

        printf("\n\n\n\n\n\n\n\nnovy userrrrr\n\n\n\n");
        fflush(stdout);
        /*
            // int one = 1;
            // ioctl(httpcomsocket, FIONBIO, &one);

            // int ftpcontrolcomsocket = accept(ftp_control_socket, NULL, NULL);
            // if (ftpcontrolcomsocket == -1) {
            //     perror("accept() selhal - ftp");
            //     exit(EXIT_FAILURE);
            // }
            // altgr + z

            // x[1] = hodnota pole
            // &x[1] = pointer na hodnotu pole
            
            // proc by toto neslo?
            // protoze SSL objekt je ve skutecnosti struct ssl_st, ktera je napsana nekde hluboko v kodu openssl a nepatri pro user-use, proto vznikl ten "datovy typ" SSL
            // protoze diky tomu muzeme pristupovat do te struktury, ale jenom pres API, samozrejme si muzeme udelat staticky objekt u openssl a potom z toho udelat pointer
            // pomoci &, ale problem prichazi kdyz si chceme udelat pole tichto objektu, narazime na problem te velikosti te struktury, reseni: kdyz muzeme pristupovat jenom
            // k pointeru SSL, tak si muzeme zkusit udelat pole typu SSL ** => struct ssl_st **p_to_p
            // SSL *pole = calloc(10, sizeof(SSL));
        */
        
        // mozna prejmenovat HTTPS_thread_specific na rovnou threadspecific_array[connection], protoze jinak bych musel to memcpy do toho array a takhle by to bylo jednodussi
        pthread_mutex_t lock_thread_specific; // mezi lock a unlock se ta promenna neda updatnout nikoliv jinym a kdyby jo, tak by thread blokoval, nez se to odemkne!
        // pthread_mutex_lock(&lock_thread_specific);
        HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION].connection = CONNECTION;
        HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION].comsocket = HTTPS_global_info.COMSOCKARRAY[CONNECTION];
        HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION].thread_id = pthread_self();
        HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION].specific_ssl_connection = HTTPS_global_info.SSL_CONNECTIONS_ARRAY[CONNECTION];
        // pthread_mutex_unlock(&lock_thread_specific);
        
        printf("\n===MAIN===\n");
        printf("comsocket: %d\n", HTTPS_global_info.COMSOCKARRAY[CONNECTION]);
        printf("threadID: %lu %d, %lu %d\n", (unsigned long)HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION].thread_id, HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION].thread_id, (unsigned long)pthread_self(), pthread_self());
        printf("CONNECTION: %d\n", CONNECTION);
        fflush(stdout);

        // 1. je . a potom 2. az &
        // kdyz je stejny operator precedence, tak se jde zprava doleva CHRIST IS GOD
        if (pthread_create(&HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION].thread_id, NULL, wrapper_handling_response, (void *)&CONNECTION) != 0) { // pointer na konkretni thread, pointer na strukturu s atributy na thread, pointer na funkci, kterou thread bude konat void* (*f_pointer)(int) = function;, pointer na arg (void *)
            exit(EXIT_FAILURE);
        }
        // nebudu moct vedet, jaky bude jeho return value, ale po skonceni tohoto threadu se jeho recources uvolni samy
        // temp
        if (pthread_detach(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION].thread_id) != 0) {
            perror("pthread_detach() selhal");
            exit(EXIT_FAILURE);
        }

        printf("CONNECTION: %d\n", CONNECTION);
        fflush(stdout);

        // CHRIST IS KING!
        sleep(1); // sleep(), protoze to nekdy fungovalo s __thread a nekdy ne a nejspise je to tim, ze system uz udelal CONNECTION++ a napr. pthread_cancel() jenom poda zadost na ukonceni threadu, tak mozna se podala zadost na to, aby se vytvoril thread a predala se CONNECTION (copy) a CONNECTION++ bylo rychlejsi, takze misto 0 se predalo 1, coz dale potom vyhodi error 
        CONNECTION++;
        printf("deje se neco?");
        fflush(stdout);
    }
    return EXIT_SUCCESS;
}

void get_dynamic_files_table(char *temp_path) {
    char *path = path_to_open(temp_path, 0);
    // printf("\n\n\n\npath - dynamic_files: %s", path);
    if (path == NULL) {
        fprintf(stderr, "\nspatna path!\n");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }
    // sleep(1);

    // printf("\n\npath: %s\n\n\n\n\n", path);
    // fflush(stdout);

    // char path[2] = "a";
    int pipe_ends_length[2];
    if (pipe(pipe_ends_length) == -1) {
        perror("pipe() selhal");
        free_all();
    }


    // 1 - velikost
    pid_t forked_process_length;
    int waitpid_result_length;

        char *command = malloc(strlen("tree -H $ | wc -c") + strlen(path) + 2);
        if (command == NULL) {
            perror("malloc() selhal - #get_dynamic_files_table# - length");
            free_all();
        }
        memset(command, 0, strlen("tree -H $ | wc -c") + strlen(path) + 2);
        snprintf(command, strlen("tree -H $ | wc -c") + strlen(path) + 2, "tree -H $ %s | wc -c", path);
    // printf("\n\ncommand - 1.1: %s\n", command);
    // fflush(stdout);

    // rozdil mezi $ /path/ a $/path/, to $/path/
    // kdyz se udela tree -H $ /path/ => tak tam u jednoho href vyjede /path//, nemelo by to vadit, protoze se tam vlozi PATH_REQUEST
    if ((forked_process_length = fork()) == -1) {
        perror("fork() selhal");
        free_all();
    }
    else if (forked_process_length == 0) {
        //                                        tady path
        char *command = malloc(strlen("tree -H $ | wc -c") + strlen(path) + 2);
        if (command == NULL) {
            perror("malloc() selhal - #get_dynamic_files_table# - length");
            free_all();
        }
        memset(command, 0, strlen("tree -H $ | wc -c") + strlen(path) + 2);
        snprintf(command, strlen("tree -H $ | wc -c") + strlen(path) + 2, "tree -H $ %s | wc -c", path);

        char *argv[] = {"zsh", "-c", command, NULL}; // po / tam pujde automaticky path ktera se tam zada
        close(pipe_ends_length[0]);
        // printf("\n\ntady, %s\n\n", path_to_command);
        fflush(stdout);
        dup2(pipe_ends_length[1], STDOUT_FILENO); // STDIN_FILENO = pipe_ends_length[1], old, new, new dostane hodnotu old
        close(pipe_ends_length[1]); // nemuzu uzavrit stdout, protoze pipe_ends_length[1] odkazuje na stdout, tak muzu uzavrit prave to, ale nemuzu uzavrit stdout, to by nedavalo smysl, protoze ta pipe samotna neukazuje na stdout

        // dash = systemove skripty apod., bash, zsh je pro usera
        // echo $SHELL => jaky shell se ted pouziva
        execv("/bin/zsh", argv); // prepne se memory toho forknuteho procesu na proces, ktery dam do zavorek
        free_all();
        // execl = vim, kolik mam argumentu pisu to jako list "a", "b", "c"...
        // execv = pisu to jako char *pole[] = {...}
    }
    close(pipe_ends_length[1]);
    waitpid(forked_process_length, &waitpid_result_length, 0); // pocka se az forked proces uplne skonci

    if (WIFEXITED(waitpid_result_length)) {
        // printf("\n\nvse probehlo ok!\n");
        // fflush(stdout);
    }

    char command_length_array[10] = {0};
    ssize_t read_now1, read_total1 = 0;
    while (1) {
        read_now1 = read(pipe_ends_length[0], command_length_array + read_total1, 9 - read_total1); // up to => 9 + 1 \0

        read_total1 += read_now1;

        if (read_now1 == -1) {
            perror("read() selhal - #get_dynamic_files_table# - read command_length");
            free_all();
        }
        else if (read_now1 == 0) {
            break; // eof
        }
    }
    int command_length = atoi(command_length_array);












    // 2 - cteni
    // printf("\n\n\nCOMMAND_LENGTH: %d\n\n\n\n", command_length);
    fflush(stdout);

    pid_t forked_process_command;
    int waitpid_result_command, pipe_ends_command[2];

    if (pipe(pipe_ends_command) == -1) {
        perror("pipe() selhal - #get_dynamic_files_table# - command");
        free_all();
    }

    forked_process_command = fork();
    if (forked_process_command == -1) {
        perror("fork() selhal - #get_dynamic_files_table#");
        free_all();
    }
    else if (forked_process_command == 0) {
        close(pipe_ends_command[0]);
     

        char *command = (char *)malloc(strlen("tree -H $ ") + strlen(path) + 1);
        if (command == NULL) {
            perror("malloc() selhal - #get_dynamic_files_table#");
            free_all();
        }
        memset(command, 0, strlen("tree -H $ ") + strlen(path) + 1);
        snprintf(command, strlen("tree -H $ ") + strlen(path) + 1, "tree -H $ %s", path);
        // printf("\n\n\n\nTADY NECO: %s", command);
        fflush(stdout);
        char *argv[] = {"zsh", "-c", command, NULL};

        dup2(pipe_ends_command[1], STDOUT_FILENO); // pipe ukazuje na stdout
        close(pipe_ends_command[1]);

        execv("/usr/bin/zsh", argv);
        free_all();
    }
    close(pipe_ends_command[1]);
    waitpid(forked_process_command, &waitpid_result_command, 0);

    if (WIFEXITED(waitpid_result_command)) {
        // printf("\nvse probehlo ok!");
        fflush(stdout);
    }

    char *command_output = (char *)malloc(command_length); // wc pocita null terminator
    if (command_output == NULL) {
        perror("malloc() selhal - #get_dynamic_files_table# - command");
        free_all();
    }
    memset(command_output, 0, command_length); // automaticky null terminator

    ssize_t read_now2, read_total2 = 0;
    while (1) {
        read_now2 = read(pipe_ends_command[0], command_output + read_total2, (command_length - 1) - read_total2);

        read_total2 += read_now2;

        if (read_now2 == 0) {
            // printf("\nvse precteno!\n"); // eof
            fflush(stdout);
            command_output[command_length - 1] = '\0';
            // printf("\ncommand_output: %s", command_output);
            fflush(stdout);
            break;
        }
        else if (read_now2 == -1) {
            perror("read() selhal - #get_dynamic_files_table# - read command");
            free_all();
        }
    }

    // printf("\n\ncommand_output: %s", command_output);
    fflush(stdout);







    // 3 - supplying dynamic_table
    int table_fd = open("/tmp/dynamic_table.txt", O_CREAT | O_APPEND | O_TRUNC | O_RDWR, 0777);
    if (table_fd == -1) {
        perror("open() selhal - #get_dynamic_files_table#");
        free_all();
    }

    ssize_t written_now1, written_all1 = 0;
    while (1) {
        written_now1 = write(table_fd, command_output + written_all1, command_length - written_all1);

        written_all1 += written_now1;

        if (written_now1 == -1) {
            perror("write() selhal - #get_dynamic_files_table#");
            free_all();
        }
        else if (written_all1 == command_length) {
            // printf("\n\n\n\nwritten_all: ok\n\n\n\n");
            fflush(stdout);
            break;
        }
    }
    lseek(table_fd, SEEK_SET, 0);
    
    // 4 - modyfing dynamic table

    pid_t forked_process_run_dynamic_table;
    int waitpid_result_run_dynamic_table;
    if ( (forked_process_run_dynamic_table = fork()) == -1) {
        perror("fork() selhal - #get_dynamic_files_table#");
        free_all();
    }
    else if (forked_process_run_dynamic_table == 0) {
        char *argv[] = {"python3", "PYTHON/dynamicke_tabulky.py", NULL};
        execv("/usr/bin/python3", argv);
        perror("execv() selhal - #get_dynamic_files_table#");
        free_all();
    }
    // printf("\npo running python scriptu");
    waitpid(forked_process_run_dynamic_table, &waitpid_result_run_dynamic_table, 0);
    // system("python3 PYTHON/dynamicke_tabulky.py");

    if (WIFEXITED(waitpid_result_run_dynamic_table)) {
        // printf("\ngenerovani dynamicke tabulky - ok!");
        // fflush(stdout);
    }

    ssize_t read_now3, read_total3 = 0;
    char length_dynamic_table_array[11] = {0};
    while (1) {
        read_now3 = read(table_fd, length_dynamic_table_array + read_total3, 10 - read_total3);

        if (read_now3 == -1) {
            perror("\nread() selhal - #get_dynamic_files_table#");
            free_all();
        }
        else if (read_now3 == 0 || read_now3 == 10) {
            // printf("\ndelka dynamicke tabulky precteno (10 safe Bytes) - ok!");
            // fflush(stdout);
            break;
        }
    }

    char *length_dynamic_table_array_delimiter = strstr(length_dynamic_table_array, "$");
    if (length_dynamic_table_array_delimiter == NULL) {
        fprintf(stderr, "\nnenasel se delimiter na urceni velikosti dynamicke tabulky");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }
    int length_dynamic_table_array_delimiter_index = (int)(length_dynamic_table_array_delimiter - length_dynamic_table_array);

    char length_array_to_atoi[10] = {0};
    for (int i = 0; i < length_dynamic_table_array_delimiter_index; i++) {
        length_array_to_atoi[i] = length_dynamic_table_array[i];
    }
    int dynamic_table_length = atoi(length_array_to_atoi);


    char *dynamic_table = (char *)malloc(dynamic_table_length + 300 + 1);
    if (dynamic_table == NULL) {
        perror("malloc() selhal - #get_dynamic_files_table#");
        exit(EXIT_FAILURE);
    }
    memset(dynamic_table, 0, dynamic_table_length);

    ssize_t read_now4, read_total4 = 0;
    while (1) {
        read_now4 = read(table_fd, dynamic_table + read_total4, dynamic_table_length + 300 - read_total4);

        read_total4 += read_now4;
        if (read_now4 == -1) {
            perror("read() selhal - #get_dynamic_files_table#");
            exit(EXIT_FAILURE);
        }
        else if (read_now4 == 0 || read_now4 == dynamic_table_length - 1) {
            // printf("\ndynamic table precten - ok!");
            // fflush(stdout);
            break;
        }
    }
    // printf("\n\n\n\\ndynamic_table: %s, strlen(dynamic_table): %zu, dynamic_table_length: %zu\n\n", dynamic_table, strlen(dynamic_table), dynamic_table_length);

    int fill_html_file = open("HTML/files_html.html", O_APPEND | O_RDWR | O_TRUNC, 0777);
    if (fill_html_file == -1) {
        perror("open() selhal - #get_dynamic_files_table#");
        free_all();
    }

    ssize_t written_now2, written_total2 = 0;
    while (1) {
        written_now2 = write(fill_html_file, dynamic_table + written_total2, dynamic_table_length - written_total2);

        written_total2 += written_now2;
        if (written_now2 == -1) {
            perror("write() selhal - #get_dynamic_files_table#");
            free_all();
        }
        else if (written_total2 == dynamic_table_length) {
            // printf("\nHTML soubor naplnen dynamic files table - ok!\n");
            // fflush(stdout);
            break;
        }
    }
    /*
    pid_t forked_process_table_length;
    int pipe_ends_table_length[2], waitpid_result_table_length;

    if (pipe(pipe_ends_table_length) == -1) {
        perror("pipe() selhal - #get_dynamic_files_table# - table_length");
        free_all();
    }

    if ((forked_process_table_length = fork()) == -1) {
        perror("fork() selhal - #get_dynamic_files_table# - table_length");
        free_all();
    }
    else if (forked_process_table_length == 0) {
        close(pipe_ends_table_length[0]);
        
        // python ./PYTHON/dynamicke_tabulky.py OUTPUT PATH

        // protoze to neni jako v shellu, kde by to muselo byt v '', protoze to je multiline, tady je to tak, co se da do execv, to se presne preda tomu python scriptu, takze neni potreba ''
        dup2(pipe_ends_table_length[1], STDOUT_FILENO); // old, new, new gets old, whenever stdout is used, pipe_ends_table_length[1] is used
        close(pipe_ends_table_length[1]);

        //  strlen(" | wc -m")
        int heredoc_length = strlen("<< 'EOF' \n\n\n\n\n EOF") + strlen(command_output) + 100;
        char *heredoc = (char *)malloc(heredoc_length);
        if (heredoc == NULL) {
            perror("malloc() selhal - #get_dynamic_files_table# - table_length");
            free_all();
        }
        memset(heredoc, 0, heredoc_length + 1);
        snprintf(heredoc, heredoc_length, "<< 'EOF'\n%s\nEOF EOF EOF EOF EOF EOF EOF", command_output);
        // protoze heredoc funguje jenom, co jsem vypozoroval s pomoci Boha, ze se musi napsat delimiter a potom newline aby se to vubec uznalo jako heredoc, takze protoze \n
        // tyhle pipes a >> maji nejvyssi prioritu! potom vse ostatni

        int command_length = strlen("python3 PYTHON/dynamicke_tabulky.py") + strlen(path) + strlen(command_output) + 300;
        char *command = (char *)malloc(command_length);
        if (command == NULL) {
            perror("malloc() selhal - #get_dynamic_files_table# - table_length");
            free_all();
        }
        memset(command, 0, command_length);
        snprintf(command, command_length, "python3 PYTHON/dynamicke_tabulky.py %s << EOF\n%s\nEOF'", path, command_output);
        char *argv[] = {"zsh", "-c", command, NULL};

        // printf("\n\n\ncommand - 3: %s", command);
        // printf("\n\nheredoc - 3: %s", heredoc);
        // printf("\n\ncommand_length - 3: %d", command_length);
        // printf("\n\nheredoc_length: %d", heredoc_length);
        
        // printf("\n\ncommand_output: %s", command_output);
        // fflush(stdout);
        // fflush

        execv("/usr/bin/zsh", argv);
        perror("execv() selhal - #get_dynamic_files_table# - table_length");
        free_all();
    }
    close(pipe_ends_table_length[1]);
    
    char table_length_array[30000] = {0};
    ssize_t read_now3, read_total3 = 0;
    while(1) {
        read_now3 = read(pipe_ends_table_length[0], table_length_array + read_total3, 29999 - read_total3);

        read_total3 += read_now3;
        if (read_now3 == 0) {
            printf("\n\nvse precteno - read3, bytes_all: %zu", read_total3);
            fflush(stdout);

            break;
        }
        else if (read_now3 == -1) {
            if (errno == EFAULT) {
                printf("\n\n\nEFAULT");
            }
            perror("read() selhal - #get_dynamic_files_table# - table_length");
            free_all();
        }
    }
    printf("\n\n\n\n\n\n\n\n\n\n\ntable_length_array: %s tady to konci", table_length_array);
    fflush(stdout);

    waitpid(forked_process_table_length, &waitpid_result_table_length, 0);

    if (WIFEXITED(waitpid_result_table_length)) {
        printf("\nvse ok!");
        fflush(stdout);
    }

    int table_length = atoi(table_length_array);
    */

    

    /*
    pid_t forked_process_table;
    int pipe_ends_table[2], waitpid_result_table;

    if (pipe(pipe_ends_table) == -1) {
        perror("pipe() selhal - #get_dynamic_files_table# - table");
        free_all();
    }

    // dup2(x, y) => y ukazuje na x, vsechno co ma jit do y, pujde do x
    if ( (forked_process_table = fork()) == 0) {
        close(pipe_ends_table[0]);
        if (dup2(pipe_ends_table[1], STDOUT_FILENO) == -1) { // old, ew, new gets old
            perror("dup2() selhal - #get_dynamic_files_table# - table");
            free_all();
        }

        // python /media/sf_projects_on_vm/FTP_SERVER/PYTHON/dynamicke_tabulky.py PATH
        // "zsh" "-c" "python /media/sf_projects_on_vm/FTP_SERVER/PYTHON/dynamicke_tabulky.py OUTPUT PATH"
        char *command = (char *)malloc(strlen("./PYTHON/dynamicke_tabulky.py '' ") + strlen(command_output) + strlen(path) + 1);
        if (command == NULL) {
            perror("malloc() selhal - #get_dynamic_files_table# - table");
            free_all();
        }
        memset(command, 0, strlen("./PYTHON/dynamicke_tabulky.py '' ") + strlen(command_output) + strlen(path) + 1);
        snprintf(command, strlen("./PYTHON/dynamicke_tabulky.py '' ") + strlen(command_output) + strlen(path) + 1, "./PYTHON/dynamicke_tabulky.py '%s' %s", command_output, path);
        char *argv[] = {"zsh", "-c", command, NULL};
        execv("/usr/bin/zsh", argv);
        free_all();
    }
    close(pipe_ends_table[1]);
    waitpid(forked_process_table, &waitpid_result_table, 0);

    if (WIFEXITED(waitpid_result_table)) {
        printf("\nvse ok!");
        fflush(stdout);
    }

    char *output_table = (char *)malloc(table_length);
    if (output_table == NULL) {
        perror("malloc() selhal - #get_dynamic_files_table# - table");
        free_all();
    }
    memset(output_table, 0, table_length);

    ssize_t read_now4, read_total4 = 0;
    while (1) {
        read_now4 = read(pipe_ends_table[0], output_table + read_total4, (table_length - 1) - read_total4);

        if (read_now4 == 0) {
            printf("\nvse precteno!!\n");
            fflush(stdout);
            break; // eof
        }
        else if (read_now4 == -1) {
            perror("read() selhal - #get_dynamic_files_table#");
            free_all();
        }
    }
    printf("\n\n\n\nfinal_output: %s", output_table);
    fflush(stdout);



    // printf("\n\n\n\ncommand_output: %s", command_output);
    printf("\n\n\n\n\ntady jsem");
    fflush(stdout);
    return command_output; */
}

char *html_path(enum HTML_Enum Html_spec, enum Media_Enum Media_spec, char *path) {
    switch (Html_spec) {
        case HTML_FORMULAR_PRIHLASENI:
            // memcpy(html_path_union.path_prihlaseni, "/home/marek/Documents/FTP_SERVER/HTML/formular_prihlaseni.html", strlen("/home/marek/Documents/FTP_SERVER/HTML/formular_prihlaseni.html"));
            html_path_union.html_file_path = strdup("HTML/formular_prihlaseni.html");
            return html_path_union.html_file_path;
        case HTML_FORMULAR_TVORBA_UCTU:
            html_path_union.html_file_path = strdup("HTML/formular_tvorba_uctu.html");
            return html_path_union.html_file_path;
        case HTML_FILES_HTML:
            switch (Media_spec) {
                case HTML:
                    get_dynamic_files_table("/tmp/ftp_server/");
                    html_path_union.html_file_path = strdup("HTML/files_html.html");
                    return html_path_union.html_file_path;
                case PATH:
                    get_dynamic_files_table(path);
                    html_path_union.html_file_path = strdup("HTML/files_html.html");
                    return html_path_union.html_file_path;
            }            
            return html_path_union.html_file_path;
        case HTML_INVALID_LOGINS:
            html_path_union.html_file_path = strdup("HTML/invalid_logins.html");
            return html_path_union.html_file_path;
        case HTML_ACCOUNT_TAKEN:
            printf("\n\n\nCOZE JAK TO ZE TADY\n\n\n");
            html_path_union.html_file_path = strdup("HTML/account_taken.html");
            return html_path_union.html_file_path;
        case HTML_UNKNOWN_TYPE:
            html_path_union.html_file_path = strdup("HTML/neznamy_typ_requestu.html");
            return html_path_union.html_file_path;
        default:
            printf("\nHTML_spec enum je bud moc maly nebo moc velky: %d\n", Html_spec);
            exit(EXIT_FAILURE);
    }
}
struct HTTPS_response *prepare_favicon_response() {
    // printf("\n\n\n\n\n\n\nHEJ FAVICON\n\n\n\n\n\n");
    char wd[50];
    getcwd(wd, sizeof(wd));
    printf("\n%s\n", wd);
    struct stat info;
    if ( stat("IMAGES/icon.avif", &info) == -1) {
        perror("stat() selhal");
        exit(EXIT_FAILURE);
    }
    size_t lengthfile = info.st_size;
    printf("\nLengthfile: %zu\n", lengthfile);

    FILE *filepointer = fopen("IMAGES/icon.avif", "rb"); // icon.avif
    if (filepointer == NULL) {
        perror("fopen() selhal - favicon.ico");
        exit(EXIT_FAILURE);
    }

    unsigned char *buffer = (unsigned char *)malloc(lengthfile);
    if ( buffer == NULL) {
        perror("malloc() selhal");
        exit(EXIT_FAILURE);
    }
    memset(buffer, 0, lengthfile);

    size_t bytes_read = fread(buffer, 1, lengthfile, filepointer);
    printf("bytes_read %zu", bytes_read);

    if ( ferror(filepointer)) {
        printf("\nANO, JE TAM NEKDE CHYBA");
    }
    else if ( feof(filepointer)) {
        printf("\nEOF\n");
    }
    
    if ( bytes_read != lengthfile) {
        perror("fread() selhal");
        exit(EXIT_FAILURE);
    }

    char headers[HEADERLEN];
    snprintf(headers, HEADERLEN,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: image/avif\r\n"
    "Connection: keep-alive\r\n"
    "Cache-Control: no-cache, private\r\n" // no-store
    "Content-length: %zu\r\n\r\n", lengthfile 
    );

    char responsebuf[RESPONSELEN]; // pokud tam bude mene Bytes nactene a potom se to bude kopirovat, tak se to zkopiruje i s tima neinicializovanymi daty
    memset(responsebuf, 0, RESPONSELEN);
    // <!-- image/x-icon --> je jen pro ikony
    // pokud nechci favicon jako soubor, tak <link> tag muze mit atribut data, kde to je zakodovane, to jsem nezkousel
    // SVG/PNG je asi jedna z nejlepsich moznosti verzi pro favicon, SVG je nejak do budoucnosti ze se bude pouzivat
    // rel="icon" takovyto shortcut icon uz se nepouziva ani ten ? otaznik v te path se uz nepouziva u icon, nebo ty verze taky uz ne
    // no-cache a no-store je rozdil!! Cache si precist, co to je a jak to funguje
    // ctrl + shift + R je hard refresh webpage, nepouzije cache, ale stahne to rovnou z toho serveru 
    // ctrl + shift + delete odstrani cache, podle moznosti samozrejme, ktery si nastavime
    // icona musi mit type atribut
    // pro SVG je to image/svg+xml
    // strdup a ASI vetsinou ty str* to kopiruji, hledaji do prvniho \0 POZOR NA TO, neni to dobre na BINARNI data treba prave na avif, kde je hodne \0 v binarnich datech
    // nekde na stack overflow bylo napsane ze se posila request na favicon a potom na to, co je napsane v href, ale to nevim ted
    // #0 v GDB je frame nynejsi, to znamena, ten kde se udelal chyba
    // u valgrindu se jde ze spoda nahoru, takze na spode je to "nejstarsi" volani funkce
    // URL je jako PATH, takze pokud tam napisu treba /IMAGES/icon.avif, tak se mi ukaze ta samotna ikona, toto se pouziva i jako utok na hledani webpages, ktere nejsou pristupne publiku
    // kdyz jsem ve slozce X, ktera ma podslozku Y, tak pisu /Y jenom!!!!
    // ta favicon ma hodno hodne velkou tendenci se pokazde cachovat => PROTO SE KVULI TOMU TREBA NEODESLE REQUEST, TAKZE POZOR NA TO, KDYZ NEPRIJDE REQUEST, TAK 
    // TO MUZE BYT TIM, ZE TO JE JENOM CACHENUTY => vymazat cache a zkusit znova, pokazde kdyz zkousim webpage, vymazat cache a zkusit to, aby opravdu prisli
    // vsechny requesty
    // pozot aby na wiresharku bylo zapnute uplne vsechno NE JEN HTTP, na tom jsem udelal velkou chybu a chyba byla takova, ze se udelala z niceho nic NOVA TCP 
    // KONEKCE A POTOM JSEM TO ZJISTIL!!! FAKT PROSIM OPRAVDU POZOR NA TO
    // HTTP 1.1/1 HE TEXT BASED
    // OBSAH JE POMOCI TEXTU POKUD JE TO NORMALNI SOUBOR A POKUD OBRAZEK TAK BINARY
    // !!
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Pragma
    // https://developer.mozilla.org/en-US/docs/Web/API/Cache
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Caching
    // https://en.wikipedia.org/wiki/Web_cache
    
    memcpy(responsebuf, headers, strlen(headers));
    memcpy(responsebuf + strlen(headers), buffer, lengthfile);

    size_t lengthresponse = strlen(headers) + lengthfile;

    struct HTTPS_response *favicon_response = (struct HTTPS_response *)malloc(sizeof(struct HTTPS_response));
    // printf("\n\nRESPONSEBUF: %s, BUFFER: %s", responsebuf, buffer);

    favicon_response->content = (unsigned char *)malloc(RESPONSELEN);
    memset(favicon_response->content, 0, RESPONSELEN);
    memcpy(favicon_response->content, responsebuf, RESPONSELEN); // alokace na heap

    printf("\nPREPARE_FAVICON_RESPONSE: %s", responsebuf);
    fflush(stdout);
    // corrupted top size = heap je poskozen nekdy nastala chyba v memory

    // kitchen-headers => placani vsemoznych hederu za sebou do jedne kategorie jako např. Cach-Control...
    // favicon_response->content = strdup(responsebuf); // nemuzu pouzit strdup, protoze kopiruje string az do \0, v .avif souboru je hodne \0, proto musim 
    // alokovat nejake misto pro ten pointer na heapu a potom to tam zkopirovat
    favicon_response->content_length = lengthresponse;
    favicon_response->communication_socket = HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].comsocket;

    return favicon_response;
}

enum HTML_Enum get_html_enum(char *request) {
    // request na favicon se posila porad i kdyz treba neni na te strance dany, ze ho user chce, firefox dordzuje connections jak jsou, google udela treba 3 connections na jeden webserver
    // sleep(1);
    char *path = extraction_path_files(request);
    size_t len = strlen(path);
    if ( strstr(request, "GET")) { 
        printf("\n\nrequest - GET: %s", request);
        fflush(stdout);

        if (strstr(request, "GET /HTML/formular_tvorba_uctu") != NULL) { // protoze referer
            return HTML_FORMULAR_TVORBA_UCTU; 
        }
        else if (strstr(request, "GET /HTML/formular_prihlaseni") != NULL) {
            return HTML_FORMULAR_PRIHLASENI;
        }
        else if ((*path == '/') && (strlen(path) == 1)) { // prvni request => kdyz webbrowser nevi, na jakou path to ma poslat, posle to na / jakoby root, http server je jako file server v tomhle ohledu
            return HTML_FORMULAR_PRIHLASENI;
        }
        else { // pokud nekdo bude mit sveho klienta, tak tady se muze dostat pres security asi
            // get_dynamic_files_table(path); // vygeneruje se v html_prepare_contents
            return HTML_FILES_HTML;
        }
    }
    else if ( strstr(request, "POST") ) {
        printf("\n\nrequest - POST: %s", request);
        fflush(stdout);

        if ( strstr(request, "formular_tvorba_uctu") ) {
            username_password_extraction(request);
            printf("\n HTML_SPEC %d\n", HTML_spec);
            account_created(ACCOUNTS_USER_DATA_ARRAY[CONNECTION_thread].username, ACCOUNTS_USER_DATA_ARRAY[CONNECTION_thread].password);
            printf("\n HTML_SPEC %d\n", HTML_spec);

            return HTML_spec;
        }
        else if ( strstr(request, "formular_prihlaseni") ){
            Account_spec = login_lookup(ACCOUNTS_USER_DATA_ARRAY[CONNECTION_thread].username, ACCOUNTS_USER_DATA_ARRAY[CONNECTION_thread].password);
            printf("%s %s", ACCOUNTS_USER_DATA_ARRAY[CONNECTION_thread].username, ACCOUNTS_USER_DATA_ARRAY[CONNECTION_thread].password);
            switch (Account_spec) {
                case ACCOUNT_EXIST:
                    // printf("\n\nACCOUNT_EXIST prepare html\n\n");
                    // fflush(stdout);
                    // system("python /home/marek/Documents/FTP_SERVER/PYTHON/dynamic_table.py");
                    return HTML_FILES_HTML;
                    break;
                case ACCOUNT_TAKEN:
                    printf("\n\nACCOUNT_TAKEN prepare html\n\n");
                    return HTML_ACCOUNT_TAKEN;
                    break;
                case ACCOUNT_INVALID_OR_FREE:
                    printf("\n\nACCOUNT_INVALID OR FREE prepare html\n\n");
                    return HTML_INVALID_LOGINS;
                    break;
                default:
                    exit(EXIT_FAILURE);
            }
        }
    }
    else {
        return HTML_UNKNOWN_TYPE;
    }
}

struct HTTPS_response *prepare_html_contents_path(char *path) {
    char headers[HEADERLEN] = {0};

    snprintf(headers, HEADERLEN, 
    "HTTP/1.1 303 See Other\r\n"
    "Location: https://127.0.0.1:8000%s\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Content-Length: 0\r\n\r\n", // konci radek \r\n a to druhe \r\n nasnazuje konec headers!! pozor MUSI TO TAM BYT JINAK TO OPRAVDU NEFUNGUJE
    path);

    struct HTTPS_response *html_tosend = (struct HTTPS_response *)malloc(sizeof(struct HTTPS_response));
    if (html_tosend == NULL) {
        perror("malloc() selhal - #prepare_html_contents# - html_tosend - PATH");
        free_all();
    }
    memset(html_tosend, 0, sizeof(struct HTTPS_response));

    html_tosend->content = strdup(headers);
    html_tosend->content_length = strlen(headers) + 1;
    html_tosend->communication_socket = HTTPS_global_info.COMSOCKARRAY[CONNECTION_thread];

    return html_tosend;

    // POUZIT HTTP LOCATION!!!

    /*
    HTTP 1.0
    request a konec

    HTTP 1.1
    komunikace dlouhodoba a vice requestu => request - response, request - response ...
    HOL (head of line blocking) = prave ze to musi jit takhle za sebou
    pipelining, ale skoro nikdy to nepouziva, protoze pro kazdy request musi prijit primy response

    2xx = OK
    3xx = redirect, kdyz treba po POST nebo potom co se "recource presunul na jinou url" => pokud chci aby se zmenila URL (path), pouziva se Location
    */

    // dalsi request je povinne GET
    // "HTTP/1.1 303 See Other\r\n"
    // "Location: https://127.0.0.1:8000/PATH"
    // "Content-Type: text/html; charset=UTF-8\r\n"
    // "Content-Length: 0"
    
}

struct HTTPS_response *prepare_html_contents(enum HTML_Enum HTML_spec, enum Media_Enum Media_spec, char *path) {
    char *filepath = html_path(HTML_spec, Media_spec, path);
    // system("cat /media/sf_projects_on_vm/FTP_SERVER/HTML/files_html.html");
    // printf("\n\n\n\ntady u system()");
    fflush(stdout);
    FILE *filepointer = fopen(filepath, "r");
    printf("\npath - prepare_html_contents: %s", path);
    if (filepointer == NULL) {
        perror("fopen() selhal - #prepare_html_contents# - filepointer");
        exit(EXIT_FAILURE);
    }

    fseek(filepointer, 0, SEEK_END);
    size_t lengthfile =  ftell(filepointer);
    // printf("\n\nLENGTH: %zu", lengthfile);
    fseek(filepointer, 0, SEEK_SET);

    char htmlcode[lengthfile];
    if ( fread(htmlcode, sizeof(char), lengthfile, filepointer) == 0) {
        perror("fread() selhal");
        exit(EXIT_FAILURE);
    }

    // no-cache, private

    char headers[HEADERLEN] = {0};
    snprintf(headers, HEADERLEN,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Connection: keep-alive\r\n"
    "Cache-Control: no-cache, private\r\n"
    "Content-length: %zu\r\n\r\n", lengthfile);
    size_t headerslen = strlen(headers);

    char responsebuf[RESPONSELEN];
    snprintf(responsebuf, RESPONSELEN, "%s%s", headers, htmlcode);

    size_t lengthresponse = strlen(responsebuf);

    struct HTTPS_response *html_response = (struct HTTPS_response *)malloc(sizeof(struct HTTPS_response));
    
    // printf("PREPARE_HTML_RESPONSE: %s", responsebuf);
    // fflush(stdout);
    
    html_response->content = strdup(responsebuf);
    html_response->content_length = lengthresponse;
    html_response->communication_socket = HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].comsocket;

    html_response->content[html_response->content_length] = '\0';
    return html_response;
}

int check_referer_path_html(char *request) {
    // 1 - PATH
    // 0 - HTML
    if (strstr(request, "Referer: https://127.0.0.1:8000/HTML/formular_prihlaseni.html") && strstr(request, "/tmp/ftp_server/")) { // TOTO ZMENIT POTOM
        return 1;
    }
    else {
        return 0;
    }
}

int request_has_referer(char *request) {
    // 0 - no
    // 1 - yes

    if (strstr(request, "Referer: ")) {
        return 1;
    }
    return 0;
}

// int is_request_path_or_html(char *request) {
//     // 0 = no
//     // 1 = yes

//     if (strstr(request, "/tmp/server/")) {
//         return 1;
//     }
//     return 0;
// }

int is_request_path_or_html(char *request) {
    // 1 - path
    // 0 - html

    if (strstr(request, "PATH_REQUEST")) {
        return 1;
    }
    return 0;
}

// protoze se prepare_html_response() pouziva jenom v HTML: case, tak by to nebylo potreba
struct HTTPS_response *prepare_html_response(char *request, enum HTML_Enum Html_spec, enum Media_Enum Media_spec) {
    // printf("\n\n\n\n\nPREPARE_HTML_RESPONSE: %s", request);
    // fflush(stdout);

    char *path = extraction_path_files(request);

    if (is_request_path_or_html(request)) { // path
        // printf("\n\nprepare_html_response - request_has_referer - is_request_path_or_html - request: %s", request);
        char headers[HEADERLEN] = {0};

        snprintf(headers, HEADERLEN,
        "HTTP/1.1 303 See Other\r\n"
        "Location: https://127.0.0.1:8000/%s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: 0\r\n\r\n", // konci radek \r\n a to druhe \r\n nasnazuje konec headers!! pozor MUSI TO TAM BYT JINAK TO OPRAVDU NEFUNGUJE
        path);

        struct HTTPS_response *html_tosend = (struct HTTPS_response *)malloc(sizeof(struct HTTPS_response));
        if (html_tosend == NULL) {
            perror("malloc() selhal - #prepare_html_contents# - html_tosend - PATH");
            free_all();
        }
        memset(html_tosend, 0, sizeof(struct HTTPS_response));

        html_tosend->content = strdup(headers);
        html_tosend->content_length = strlen(headers) + 1;
        html_tosend->communication_socket = HTTPS_global_info.COMSOCKARRAY[CONNECTION_thread];

        return html_tosend;
    }

    Html_spec = get_html_enum(request); // nejaky random html file

    // prvni nahledova stranka
    if (Html_spec == HTML_FORMULAR_PRIHLASENI && *path == '/' && strlen(path) == 1) {
        char headers[HEADERLEN] = {0};

        snprintf(headers, HEADERLEN,
        "HTTP/1.1 303 See Other\r\n"
        "Location: https://127.0.0.1:8000/HTML/formular_prihlaseni.html\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: 0\r\n\r\n" // konci radek \r\n a to druhe \r\n nasnazuje konec headers!! pozor MUSI TO TAM BYT JINAK TO OPRAVDU NEFUNGUJE
        );

        struct HTTPS_response *html_tosend = (struct HTTPS_response *)malloc(sizeof(struct HTTPS_response));
        if (html_tosend == NULL) {
            perror("malloc() selhal - #prepare_html_contents# - html_tosend - PATH");
            free_all();
        }
        memset(html_tosend, 0, sizeof(struct HTTPS_response));

        html_tosend->content = strdup(headers);
        html_tosend->content_length = strlen(headers) + 1;
        html_tosend->communication_socket = HTTPS_global_info.COMSOCKARRAY[CONNECTION_thread];

        return html_tosend;
    }
    else if (Html_spec == HTML_FORMULAR_PRIHLASENI) {
        return prepare_html_contents(Html_spec, HTML, path);
    }


    if (strstr(request, "POST /HTML/formular_prihlaseni.html")) { // protoze file bud muze byt od POST nebo od GET path
        // printf("\n\nprepare_html_response - request_has_referer - is_request_path_or_html - request: %s", request);
        char headers[HEADERLEN] = {0};

        snprintf(headers, HEADERLEN, 
        "HTTP/1.1 303 See Other\r\n"
        "Location: https://127.0.0.1:8000/HTML/files_html.html\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: 0\r\n\r\n" // konci radek \r\n a to druhe \r\n nasnazuje konec headers!! pozor MUSI TO TAM BYT JINAK TO OPRAVDU NEFUNGUJE
        );

        struct HTTPS_response *html_tosend = (struct HTTPS_response *)malloc(sizeof(struct HTTPS_response));
        if (html_tosend == NULL) {
            perror("malloc() selhal - #prepare_html_contents# - html_tosend - PATH");
            free_all();
        }
        memset(html_tosend, 0, sizeof(struct HTTPS_response));

        html_tosend->content = strdup(headers);
        html_tosend->content_length = strlen(headers) + 1;
        html_tosend->communication_socket = HTTPS_global_info.COMSOCKARRAY[CONNECTION_thread];

        return html_tosend;
        // return prepare_html_contents(Html_spec, HTML, path);
    }
    else if (strstr(request, "POST /HTML/tvorba_uctu.html")) {
        return prepare_html_contents(Html_spec, HTML, path);
    }
    
    printf("\n\n\n\n\n\nrequest QWERTY: %s", request);
    if (strstr(request, "GET /tmp/ftp_server/")) {
        // exit(EXIT_FAILURE);
        return prepare_html_contents(Html_spec, PATH, path); // jenom HTML_FILES_HTML, pokud je to /, tak se PATH jakoby ignoruje
    }
    else {
        return prepare_html_contents(Html_spec, HTML, path); // pokud je to /, tak se PATH jakoby ignoruje
    }
}

struct HTTPS_response *prepare_css_response() {
    char *filepath = "CSS/formular_server.css";

    FILE *filepointer = fopen(filepath, "r");

    if (filepointer == NULL) {
        perror("fopen() selhal");
        exit(EXIT_FAILURE);
    }
    
    fseek(filepointer, 0, SEEK_END);
    size_t lengthfile = ftell(filepointer);
    fseek(filepointer, 0, SEEK_SET);

    char headers[HEADERLEN];
    snprintf(headers, sizeof(headers), 
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/css; charset=utf-8\r\n"
    "Connection: keep-alive\r\n"
    "Cache-Control: no-cache, private\r\n"
    "Content-length: %zu\r\n\r\n", lengthfile);

    char csscode[lengthfile];

    if ( fread(csscode, sizeof(char), lengthfile, filepointer) == 0) {
        perror("fread() selhal");
        exit(EXIT_FAILURE);
    }

    char responsebuf2[RESPONSELEN];
    snprintf(responsebuf2, RESPONSELEN, "%s%s", headers, csscode);

    size_t lengthresponse = strlen(responsebuf2);
    
    printf("\n\nPREPARE_CSS_RESPONSE: %s", responsebuf2);
    fflush(stdout);

    struct HTTPS_response *css_response = (struct HTTPS_response *)malloc(sizeof(struct HTTPS_response));
    css_response->content = strdup(responsebuf2);
    css_response->content_length = lengthresponse;
    css_response->communication_socket = HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].comsocket;

    return css_response;
}

int next_decimal(int length) {
    int result = ( ( (length / 10) * 10 + 10) - length) + length;
    return result;
}

void send_file(char *path) {

    // printf("\n\n\n\nSEND_FILE");
    fflush(stdout);
    int filedescriptor = open(path, O_RDONLY, 0777);

    printf("\nPATH: %s", path);
   
    if ( filedescriptor == -1) {
        perror("open() selhal - send_file()");
        exit(EXIT_FAILURE);
    }

    off_t filesize = lseek(filedescriptor, 0, SEEK_END);
    lseek(filedescriptor, 0, SEEK_SET);

    if (filesize == 0) {
        printf("\nsouboru je prazdny - send_file\n");
        exit(EXIT_FAILURE);
    }

    char read_buffer[filesize];
    ssize_t bytes_read = 0, byte_offset = 0;
    while ( (bytes_read = read(filedescriptor, read_buffer + byte_offset, filesize - byte_offset) ) < filesize) {
        if ( bytes_read == -1) {
            perror("read() selhal - send_file");
            exit(EXIT_FAILURE);
        }

        byte_offset += bytes_read;
    }
    read_buffer[bytes_read] = '\0';

    printf("BYTES READ: %zu", bytes_read);

    size_t lenpath = strlen(path);
    char reversetempname[30];
    int index_reversetempname = 0;
    for (int index = lenpath - 1; path[index] != '/'; index--) {
        reversetempname[index_reversetempname] = path[index];
        index_reversetempname++;
    }

    char name[30];
    for (int index = 0; index < strlen(reversetempname); index++) {
        name[index] = reversetempname[index_reversetempname - 1];
        index_reversetempname--;
    }

    name[strlen(name)] = '\0';

    // printf("\n\nTEMPNAME: %s\n\n\n\n\n\n\n\n\n\n\n\n\n\n", name);
    fflush(stdout);

    char headers[HEADERLEN + 60];
    snprintf(headers, HEADERLEN + 60,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Cache-Control: no-cache, private\r\n"
    "Connection: keep-alive\r\n"
    "Content-length: %ld\r\n"
    "Content-disposition: attachment; filename=\"%s\"\r\n\r\n", filesize, name);

    char response[250 + filesize];
    snprintf(response, 250 + filesize, "%s%s", headers, read_buffer);

    printf("\n\nRESPONSE: %s", response);
    printf("\nCONTENTS: %s\n", read_buffer);
    fflush(stdout);

    
    ssize_t bytes_sent = 0, bytes_now_send = 0;

    size_t size = strlen(response) - bytes_sent;

    int counter = 0;
    while ( bytes_sent < filesize) {
        // bytes_now_send = send(comsocket, response + bytes_sent, size, 0);
        bytes_now_send = SSL_write(HTTPS_global_info.SSL_CONNECTIONS_ARRAY[CONNECTION_thread], response + bytes_sent, size);
        counter++;
        printf("\n\nWHILE LOOP SEND - SEND_FILE()");
        if (bytes_now_send == -1) {
            perror("send() selhal - send_file");
            exit(EXIT_FAILURE);
        }

        bytes_sent += bytes_now_send;
        // printf("\nBytes_sent = %d, Bytes_now_send = %d, size = %d, send() counter = %d", bytes_sent, bytes_now_send, size, counter);
    }
}
char *path_real_path(char *temp_path) {
    char *path_request_find = strstr(temp_path, "PATH_REQUEST");
    if (path_request_find == NULL) {
        fprintf(stderr, "strstr() nenasel PATH_REQUEST - #extraction_path_files#");
        fflush(stderr);
        free_all();
    }
    int path_request_find_index = (int)(path_request_find - temp_path) + strlen("PATH_REQUEST");

    char *real_path = (char *)malloc(strlen(temp_path) - path_request_find_index + 1);
    int real_path_index = 0;
    if (real_path == NULL) {
        perror("malloc() selhal - #extraction_path_files#");
        free_all();
    }
    memset(real_path, 0, strlen(temp_path) - path_request_find_index + 1);

    for (int i = path_request_find_index; i < strlen(temp_path) + 1; i++) {
        real_path[real_path_index++] = temp_path[i];
    }
    real_path[real_path_index] = '\0';
    return real_path;
}

char *extraction_path_files(char *buffer) {
    /*
    0 - POST, GET
    1 - PATH request

    */

    // printf("\n\nextraction path_files: %s", buffer);
    fflush(stdout);
    int path_index = 0;
    char *path = (char *)malloc(100);
    if (path == NULL) {
        perror("malloc() selhal - extraction_path_files");
        free_all();
    }
    memset(path, 0, 100);

    if (strstr(buffer, "POST")) {
        char *start_path = strstr(buffer, "POST");
        if (start_path == NULL) {
            fprintf(stderr, "\nstrstr() nenasel POST v requestu - #extraction_path_files#");
            fflush(stderr);

            free_all();
        }
        int index_start_path = (int)(start_path - buffer) + strlen("POST") + 1;

        for (int i = index_start_path; buffer[i] != ' '; i++) {
            path[path_index++] = buffer[i];
        }
        path[path_index] = '\0';
        printf("\nPATH - POST: %s", path);
        fflush(stdout);
        return path;
    }
    else if (strstr(buffer, "GET")) {
        char *start_path = strstr(buffer, "GET") + strlen("GET ");
        int index_start_path = (int)(start_path - buffer);

        for (int index = index_start_path; buffer[index] != ' '; index++) {
            path[path_index] = buffer[index];
            path_index++;
        }

        path[path_index] = '\0';
        printf("\nPATH - GET - extraction_path_files: %s", path);
        fflush(stdout);

        return path;
    }   
}


void account_created(char *username, char *password) {

    FILE *filepointer = fopen("TXT/accounts.txt", "a");

    if (filepointer == NULL) {
        perror("fopen() selhal");
        exit(EXIT_FAILURE);
    }

    size_t lenusername = strlen(username);
    size_t lenpassword = strlen(password);

    Account_spec = login_lookup(username, password);
    printf("\n\n \x1b[35m ACCOUNT_SPEC: %d \x1b[0m \n\n", Account_spec);
  
    fflush(stdout);

    // if (lenusername > 9 || lenpassword > 9) {
    //     fprintf(stderr, "User zadal spatny length na username nebo na password")
    // }

    switch (Account_spec) {
        case ACCOUNT_EXIST:
            HTML_spec = HTML_ACCOUNT_TAKEN;
            break;
        case ACCOUNT_INVALID_OR_FREE:
            HTML_spec = HTML_FORMULAR_PRIHLASENI;
            break;
        case ACCOUNT_TAKEN:
            HTML_spec = HTML_ACCOUNT_TAKEN;
            break;
        default:
            exit(EXIT_FAILURE);
    }

    // if (Account_spec != ACCOUNT_INVALID_OR_FREE) {
    //     return 1;
    // }
    
    printf("\n\n \x1b[35m USERNAME %s\nPASSWORD %s \x1b[0m \n\n", username, password);
    fflush(stdout);

    char buffer_to_write[50];
    snprintf(buffer_to_write, 50, "%s %s\n", username, password);

    printf("\n\n \x1b[35m Buffer_to_write %s\x1b[0m \n\n", buffer_to_write);
    fflush(stdout);

    size_t bytes_written = fwrite(buffer_to_write, sizeof(char), strlen(buffer_to_write), filepointer);
    fflush(filepointer);

    printf("\nBytes written: %zu\n", bytes_written);
    if (bytes_written == 0) {
        exit(EXIT_FAILURE);
    }

}


enum Media_Enum response_spec(char *buffer) {
    /*
    if ( !strstr(buffer, "/CSS/") && !strstr(buffer, "/IMAGES/") && !strstr(buffer, "/favicon.ico") && !strstr(buffer, "/TXT/") && !strstr(buffer, ".txt")) { // pro jakekoliv txt soubory i kdyz nejsou v /TXT
        printf("\nHTML - response_spec\n");
        printf("\n\n%s", buffer);
        fflush(stdout);
        return HTML;
    }
    */

    // printf("\nresponse_spec()\n");
    if ( strstr(buffer, "GET") ) {
        if (strstr(buffer, "PATH_REQUEST")) {
            printf("\nPATH - response_spec");
            return PATH;
        }   
        else if ( (strstr(buffer, "/CSS/")) ) { // && strstr(buffer, "image/avif") == NULL
            printf("\nCSS - response_spec\n");
            return CSS;
        }
        else if ( strstr(buffer, "/IMAGES/") || strstr(buffer, "/favicon.ico")) { // strstr() je pravda
            // exit(EXIT_FAILURE);
            printf("\nFAVICON - response_spec\n");
            return FAVICON;
        }
        else if ( strstr(buffer, "/TXT/") || strstr(buffer, ".txt")) { // pro jakekoliv soubory i kdyz nejsou v /TXT
            printf("\nTXT - response_spec\n");
            return TXT;
        }
        else {
            printf("\nHTML - response_spec\n");
            printf("\n\n%s", buffer);
            fflush(stdout);
            return HTML;
        }
    }
    else if ( strstr(buffer, "POST") ) {
        if ( strstr( buffer, "formular_prihlaseni") ) {
            printf("\nPOST - response_spec\n");
            username_password_extraction(buffer);
            printf("\nPOST BUFFER: %s", buffer);
            // memcpy(user_data.username, data[0], 10);
            // memcpy(user_data.password, data[1], 10);
            // printf("%s", user_data.username);
            // printf("%s", user_data.password);
        }
        return HTML;
    }
    else {
        printf("\n\n\n\nANOOO\n\n\n");
        fflush(stdout);
        return HTML;
    }  
}

// int end_of_response(char *buf) {
//     char *foundin_buf = strstr(buf, "\r\n\r\n");
//     if ( foundin_buf) {
//         int length_receivedresponse = (int)(foundin_buf - buf);
//         css_already++;
//         if (css_already > 1) {
//             printf("\nbuffer %c\n", buf[strlen(buf) + 1]);
//             printf("\nbuffer %s\n", buf);
//         }
        

//         return length_receivedresponse;
//         // if (buf[length_receivedresponse + 4]) {
//         //     return length_receivedresponse;
//         // }
        
//         return -2;

        
//     }
//     else {
//         return -1;
//     }
// }

enum Account_enum login_lookup(char *username, char *password) {
    int username_indicator = 0;
    printf("\n\n\n\n\n\x1b[32m login_lookup() \x1b[0m\n");
    FILE *fp = fopen("TXT/accounts.txt", "r");

    if (fp == NULL) {
        perror("fopen() selhal - login_lookup");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    fseek(fp, 0, SEEK_SET);


    if (len < 2) {
        printf("\nneco je spatne se souborem\n %d", len);
        return 1;
    }

    char line[20];

    // while( fgets( line, 20, fp) != NULL) {
    //     printf("%s", line);
    // }

    char tempusername[20];
    int i = 1;
    while (fgets(line, 20, fp) != NULL) { // pokud je vse ok, fgets vrati s, pokud je EOF => NULL, pokud je nejaky error => NULL a errno je nastaveno na tu danou chybu
        for (int i = 0; i < strlen(line); i++) { // fgets prida \0!!
            if (line[i] != ' ') {
                tempusername[i] = line[i];
            }
            else {
                break;
            }
        }

        // printf("\n\ni %d\n\n", i);
        // i++;


        // pokud jsem v nejakem while loopu nebo forloopu a nechci porad psat to next, tak muzu napsat until cislo_radku za tim cyklem a potom se muze pokracovat za tim
        char temppassword[20];
        char *start_password = strstr(line, " ") + 1;
        int start_password_index = (int)(start_password - line);
        int x = 0;
        for (int i = start_password_index; i < strlen(line); i++) {
            temppassword[x] = line[i];
            x++;
        }
        temppassword[x - 1] = '\0'; // PRECTE SE TO I S \n PROTO MUSI BYT X - 1 => 12345678 => strlen() == 9 misto 8!!

        // printf("\nusername %s tempusername %s password %s temppassword %s", username, tempusername, password, temppassword);
        //printf("\n\nTEMPUSERNAME: %s TEMPPASSWORD: %s\n\n", tempusername, temppassword);
        if ( strcmp(username, tempusername) == 0 && strcmp(password, temppassword) == 0) {
            // printf("\nje to ano\n");
            fflush(stdout);
            return ACCOUNT_EXIST;
        }
        else if ( strcmp(username, tempusername) == 0) {
            username_indicator++;
            // printf("\n\n\n\n\nHEJ\n\n\n\n");
        }
        //return ACCOUNT_EXIST;
    }

    if (username_indicator >= 1) {
        return ACCOUNT_TAKEN;
    }
    else {
        return ACCOUNT_INVALID_OR_FREE;
    }
}

void username_password_extraction(char *post_request) {
    size_t length = strlen(post_request);

    char *start_crlf = strstr(post_request, "\r\n\r\n");
    int temp_index = (int)(start_crlf - post_request) + 4;

    char *temp_username = strstr(post_request + temp_index, "=");
    int start_username = (int)(temp_username - post_request) + 1;

    // char *start_ampersand = strstr(post_request, "&");
    // int index_ampersand = (int)(start_ampersand - post_request);

    // printf("\nindex ampersand\n%c", index_ampersand);


    char username[10];
    int username_index = 0;
    for (int i = start_username; post_request[i] != '&'; i++) {
        // printf("\n%c", post_request[i]);
        username[username_index] = post_request[i];

        username_index++;
    }
    username[username_index] = '\0';

    char *temp_password = strstr(post_request + start_username, "=");
    int start_password = (int)(temp_password - post_request) + 1;

    char password[10];
    int password_index = 0;
    for (int i = start_password; i < length; i++) {
        password[password_index] = post_request[i];

        password_index++;
    }
    password[password_index] = '\0';

    memcpy(ACCOUNTS_USER_DATA_ARRAY[CONNECTION_thread].username, username, strlen(username));
    memcpy(ACCOUNTS_USER_DATA_ARRAY[CONNECTION_thread].password, password, strlen(password));
    
    // printf("\n\nTady to je username: %s,  password: %s", username, password);
}

char *receiving() {
    size_t SIZE = 256;
    int iteration = 1;
    char *data = (char *)malloc(SIZE);
    pthread_t threadID = pthread_self();

    if (!data) {
        perror("malloc() selhal");
        pthread_cancel(threadID);
    }

    ssize_t bytes_now;
    size_t recv_bytes = 0;
    size_t bytes_pending = -1;
    while (1) {
        // char try_buffer[1024];
        // ssize_t try = recv(comsocket, try_buffer, 1024, MSG_PEEK);
        // try_buffer[try] = '\0';
        // printf("\n\nTRY: %d\nTRY_BUFFER: %s", try, try_buffer);

        // int count;
        // ioctl(comsocket, FIONREAD, &count);

        // printf("\n\n\n\nCOUNT: %d\n\n\n\n", count);

        // bytes_now = recv(comsocket, data + recv_bytes, SIZE - 1, 0);

        // SSL_pending vraci pocet decryptovanych bytu porad v bufferu
        // SSL_read vraci Bytes do bufferu

        bytes_pending = SSL_pending(HTTPS_global_info.SSL_CONNECTIONS_ARRAY[CONNECTION_thread]);
        // callback funkce je prakticky spatny nazev na ni a lepsi nazev by byl call-after function, protoze mame funkci A, ktere predame jeji parametry, ale take pointer na funkci B a pripadne jeji paramtery,
        // aby po skonceni funkce A mohla rovnou neco udelat, spise se to pouziva pri concurency nebo pro tento pripad pro zjisteni deni po kazde zmene

        // callback v openssl je takovy, ze mi si nastavime nasi vlastni funkce (tu callback funkci), kde si muzeme napsat co chceme, potom zavolame funkci na to, abychom vubec ji mohly pouzivat (prida se do ctx)
        // toto ted bude znamenat, ze normalne muzeme pouzivat nasi callback funkci a tato funkce se bude volat AUTOMATICKY od OpenSSL pokazde, co se zmeni nejake makro... apod.
        // get_info_callback() nam jenom vrati nas pointer na nasi funkci, coz bychom si mohli udelat i samy, ale diky OpenSSL mame pristup k internim strukturam apod.
        // nasledne 
        // priklad, kde se vola callback na githubu openssl ve statem, record - s3, cb()

        // statem = stavy handshake, rizeni kroku TLS
        // record = samotny prenos dat
        // s3 = struktura pro TLSv1.2 a starsi pro vnitrni stav samotnych algoritmu

        // OpenSSL je knihovna nabizejici implementaci protokolu SSL/TLS a nastroje pro jejich pracovani a testovani

        if (bytes_pending == 0 && recv_bytes > 0) {
            char *test_content = strstr(data, "\r\n\r\n");
            // printf("%s", data);
            // printf("\n\nDATA: %s\n\n", data);
            // printf("\ndata\n%s", data);
            // printf("%s", data);
            fflush(stdout);
            return data;
        }
        else if (bytes_pending >= 0) { // uz i na zacatku // MUSI TAM BYT >= 0, PROTOZE SSL_PENDING() FUNGUJE !AZ PO! PRVNIM SSL_READ()
            // https://stackoverflow.com/questions/6616976/why-does-this-ssl-pending-call-always-return-zero

            bytes_now = SSL_read(HTTPS_global_info.SSL_CONNECTIONS_ARRAY[CONNECTION_thread], data + recv_bytes, SIZE - 1); // pokud se
            // printf("\nbytes_now: %zu", bytes_now);
            iteration++; // BEZ TOHO SIGSIEV => FATAL SIGNAL
            recv_bytes += bytes_now;

            // problem je ten, ze ja data freenu tady, potom poslu signal thread at se ukonci, ale to muze trvat dele a nemusi to byt hned, takze se muze stat, ze se vrati retrun memory oblasti a ja potom freenu stejnou pametovou oblast podruhe => erro
            // nebo bych mohl udelat pthread_exit(), to to vlakno ukonci ihned, ale pokud treba drzi nejake mutexy, tak je nepusti => muze dojit k deadlock v jinych threads
            if (bytes_now <= 0) {
                // eof je to, ze se neco cte a potom se narazi na to, ze klient z niceho nic prerusi spojeni

                int ret = SSL_get_error(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection, bytes_now);

                // pokud ret > 0 => nic se nestalo
                if (ret <= 0) {
                    fprintf(stderr, "\nSSL_read() selhal - receiving");
                    fflush(stderr);
                    handle_error_thread(threadID);
                }

                // if (bytes_now == 0) {
                //     printf("\npeer ukoncil spojeni\n");
                //     printf("received bytes: %zu", recv_bytes);
                //     printf("\n\ndata: %s", data);
                //     // perror("peer ukoncil spojeni"); // nedavalo by smysl pouzivat perror(), protoze nenastal zadny error, jenom se mi reklo, ze to vratilo nejaky pocet Bytes
                //     // free(data);
                //     fflush(stdout);
                //     handle_error_thread(threadID);
                // } // na firefoxu to bezi ok, ale na google, jak se pripoji novy user, tak ono to posle encrypted alert a potom se posle RST, to je problem s encrypci?
                // else if (bytes_now < 0) { // ale ikdyz se pripojim vicekrat z jednoho browseru, mozna je to problem s comsocketem, ze ho jakoby "recykluji"
                //     printf("\nSSL_read() selhal\n");// misto perror()
                //     fflush(stdout);
                //     // free(data);
                //     handle_error_thread(threadID);
                // }
            }
            // SSL_ERROR_RX_RECORD_TOO_LONG
            // server neposílá TLS sifrovane data

            // 127.0.0.1:8000 => HTTP
            // https://127.0.0.1:8000 => HTTPS =>HTTP encryptovane pres TLS

            char *new_data = realloc(data, SIZE * iteration);

            if (!new_data) {
                perror("realloc() selhal");
                // free(data);
                printf("TADY JSEM\n");
                fflush(stdout);
                pthread_cancel(threadID);
            }
            data = new_data;

            continue;
        }
        else {
            // -1
            fprintf(stderr, "asi se neinicializovaly hodnoty");
            perror("hlaska");
        }
    }
    pthread_cancel(threadID);
}

void handling_response() {
    // every member of thread specific so it's on the private stack

    while (1) {
        printf("\n\n  \x1b[31m HALOOOOO JSEM TADY \x1b[0m");    
        fflush(stdout);
    
        // HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].comsocket, HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection, HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].connection
        char *request = receiving();
        // printf("\n\nrequest: %s", request);
        fflush(stdout);
        Media_spec = response_spec(request);
        // printf("\n\nMedia_spec %d\n\n", Media_spec);
        // printf("pokracuji tady");
        ssize_t bytes_now = 0, bytes_sent = 0;
        switch (Media_spec)
        {
            case HTML: {
                printf("\nHTML request detected\n");

                struct HTTPS_response *html_tosend = prepare_html_response(request, -1, HTML);
             
                printf("\nCONTENTS: %s", html_tosend->content);
                fflush(stdout);

                while( bytes_sent != html_tosend->content_length && html_tosend->content_length != 0) { 
                // bytes_now = send(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].comsocket, (html_tosend->content) + bytes_sent, (html_tosend->content_length) - bytes_sent, 0);
                bytes_now = SSL_write(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection, html_tosend->content, html_tosend->content_length);

                if (bytes_now == -1) {
                    printf("\ntady jsem u bytes_now == -1");
                    perror("send() selhal - http");
                    close(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].comsocket);
                    SSL_shutdown(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection); // aby server alert close_notify => pro efektivni ukonceni SSL/TLS (fungovalo by to i bez toho)
                    exit(EXIT_FAILURE);
                }
                // SSL_free
                bytes_sent += bytes_now;
                }
               
                fflush(stdout);
                // printf("asi tady je chyba?");
                fflush(stdout);
                free(html_tosend);
                break;
            }
            case CSS: {
                // printf("\nCSS request detected\n");
                struct HTTPS_response *css_tosend = prepare_css_response();

                printf("\nCSS - css - request: %s\n", request);
                fflush(stdout);

                while( bytes_sent != css_tosend->content_length && css_tosend->content_length != 0)  {
                    // bytes_now = send(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].communication_socket, (css_tosend->content) + bytes_sent, (css_tosend->content_length) - bytes_sent, 0);
                    bytes_now = SSL_write(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection, css_tosend->content, css_tosend->content_length);

                    if (bytes_now == -1) {
                        perror("send() selhal");
                        close(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].comsocket);
                        exit(EXIT_FAILURE);
                    }

                    bytes_sent += bytes_now;
                 
                    printf("\ninfinite while loop v handling_response() - case 1");
                }
                free(css_tosend);
                break;
            }
            case FAVICON: {
                // printf("\nFAVICON request detected\n");
                struct HTTPS_response *favicon_tosend = prepare_favicon_response();
                printf("\nFAVICON - favicon - request: %s\n", request);
                fflush(stdout);

                while ( bytes_sent < favicon_tosend->content_length && favicon_tosend->content != 0) {
                    // bytes_now = send(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].comsocket, favicon_tosend->content + bytes_sent, favicon_tosend->content_length - bytes_sent, 0);
                    bytes_now = SSL_write(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection, favicon_tosend->content, favicon_tosend->content_length);

                    if (bytes_now == -1) {
                        perror("send() selhalo");
                        close(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].comsocket);
                        exit(EXIT_FAILURE);
                    }

                    bytes_sent += bytes_now;
                    // printf("infinite while loop v handling_response() - case 2");
                }
                free(favicon_tosend);
                // printf("\nposlano");
                break;
            }
            case TXT: {
                printf("\n\n\n\nPOSILA SE SOUBOR\n\n\n\n, %s", request);
                printf("\n\n \x1b[34m GET - response_spec  \x1b[0m \n");
                fflush(stdout);
               
                char *path = extraction_path_files(request);
                printf("\n\n\n\nPATH: %s", path);
                send_file(path);
                printf("\n\nhand res TXT\n");
                break;
            }
            case PATH: {
                printf("\n\n\nPATH - dynamic_table!");
                fflush(stdout);

                char *temp_path = extraction_path_files(request);
                char *path = path_real_path(temp_path);
                struct HTTPS_response *dynamic_table_to_send = prepare_html_contents_path(path);

                printf("\n\nCONTENTS: %s", dynamic_table_to_send->content);
                fflush(stdout);

                ssize_t bytes_now, bytes_sent = 0;
                while (1) {
                    bytes_now = SSL_write(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection, dynamic_table_to_send->content+bytes_sent, dynamic_table_to_send->content_length-bytes_sent);

                    bytes_sent += bytes_now;
                    if (bytes_now <= 0) {
                        // if (SSL_get_error(HTTPS_global_info.THREADSPECIFIC_ARRAY[CONNECTION_thread].specific_ssl_connection, bytes_now) != SSL_ERROR_NONE) {
                        //     fprintf(stderr, "SSL_write() selhal - #handling_response# - PATH");
                        //     fflush(stderr);
                        //     free_all();
                        // }
                        // else {
                            // break;
                        // }
                        break;
                    }
                }
                break;
            }
        }
    }
}

// AVE CHRISTUS REX!