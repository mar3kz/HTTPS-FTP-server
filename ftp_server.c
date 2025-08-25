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
#include <pthread.h>
#include <event2/event.h> // libevent je knihovna, ktera slouzi k tomu, ze kazdy file descriptor/signal apod. kdyz se na nem stane neco noveho, tak nam to da vedet => multisynchronnous
#include <event2/buffervent.h>
#include <mqueue.h> // pro komunikaci mezi procesy/threads
#include <stdint.h> // uint32_t
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
int CONNECTION = 0;
#define CONTROL_PORT 2100
#define DATA_PORT 2000

struct response {
    char *content;
    size_t content_length;
    int communication_socket;
};

struct user_data_post {
    char username[10];
    char password[10];

} user_data = { .username = {0}, .password = {0} };
typedef enum Media_enum {
    HTML = 0,
    CSS = 1,
    FAVICON = 2,
    TXT = 3
} Media_Spec;
Media_Spec Media_spec;

typedef enum HTML_enum {
    HTML_FORMULAR_PRIHLASENI = 0,
    HTML_FORMULAR_TVORBA_UCTU = 1,
    HTML_FILES_HTML = 2,
    HTML_INVALID_LOGINS = 3,
    HTML_ACCOUNT_TAKEN = 4,
    HTML_UNKNOWN_TYPE = 5,
} HTML_Spec;
enum HTML_enum HTML_spec = HTML_FORMULAR_PRIHLASENI;

typedef union Html_Path_Union{
    char *path_prihlaseni;
    char *path_tvorba;
    char *path_files;
    char *path_invalid;
    char *path_account;
    char *path_unknown;
} Html_path_union;
Html_path_union html_path_union;

typedef enum Account_enum {
    UNSET = -1,
    ACCOUNT_EXIST = 0,
    ACCOUNT_TAKEN = 1,
    ACCOUNT_INVALID_OR_FREE = 2,
} Account_Spec;
Account_Spec Account_spec = UNSET;

typedef enum Ftp_Data_Representation {
    ASCII = 0,
    IMAGE = 1,
} Ftp_Data_Repre;
Ftp_Data_Repre ftp_data_repre = ASCII;

typedef struct Ftp_User_Info {
    char *username;
    char *password;
    char *last_path;
    
    int user_loggedin;
    Ftp_Data_Repre data_represantation;
}
struct Ftp_User_Info ftp_user_info = {.username = NULL, .password = NULL, .user_loggedin = 0};

// struct Handling_response_struct {
    // int httpcomsocket;
    // // pthread_t threadID; // zbytecne, protoze samo vlakno muze udelat pthread_self()
    // int connection;
// };

pthread_t *ARRAYTHREAD; // globalni pole - neni soucasti struct
int *COMARRAY; // potom soucasti struct
SSL **CONNECTIONS_ARRAY; // potom soucasti struct
struct event_base **EVENT_CONTEXT;

// global variable so the values will change with every thread, thanks to repetitive calling in main()
struct Thread_info {
    SSL **ssl_array_tf; // NESMIM ZAPOMENOUT TO INICIALIZOVAT!! toto je jakoby jenom jako sablona a kazda instance se musi alokovat samostatne
    int *communication_array_tf; // ulozi se to do BSS segmetu, protoze to je jenom deklarovane, ale ne inicializovane, pokud ta struct obsahuje
    int connection_tf; // jenom samostatne promenne staci to alokovat "staticky" jenom struct x y; pokud ale obsahuje pointery (pole) apod. tak ty musim alokovat zvlast!!
};
struct Thread_info thread_info;

// "private" struct to group information needed to send data/serve each connection and then passing it on the private stack, so the values will not change
// threads share a lot of things but they have its ID, stack, signal mask (collection of which signals are blocked for each thread), cancel state
typedef struct Thread_specific {
    int connection_number;
    int communication_socket;
    pthread_t thread_id;
    SSL *specific_ssl_connection;
} Thread_specific;

// struct Handling_response_struct info;

// SSL *ssl_connection = NULL; // SSL je datova struktura, ktera obsahuje real-time informace o kazde SSL/TLS konekce
SSL_CTX *ctx = NULL; // SSL_CTX je datova struktura obsahujici veskere informace a nastaveni o SSL/TLS konekci, muze byt pouzivana jako sablona pro dalsi HTTPS konekce

// SSL datovy typ je ve skutecnosti ssl_st struktura, ale je to interni struktura, takze kompilator nezna jeji velikost a nevi, jak s ni ma zachazet
// ale protoze to bychom museli si pridavat ty objekty samotne, tak udelame pole takove, ze kazda polozka bude pointer na objekt SSL*
// taky bychom mohli udelat sizeof(te struktury, ze ktere je SSL), ale ta se nachazi v openssl/ssl/ssl_local.h a to je interni knihovna, ke ktere muzeme mit pristup
// ale kod by byl hodne zavisly na verzi openssl
// globalni promenna nesmi byt dynamicky alokovana

enum Ftp_type {
    CONTROL = 0,
    DATA = 1,
},

struct Ftp_Sockets {
    int ftp_control_socket;
    int ftp_control_com;
    int ftp_data_socket;
    int ftp_data_com;

    enum Ftp_Sockets type;
};
struct Ftp_Sockets ftp_sockets = {.type = CONTROL};

struct mq_attr attributes = {
        .mq_flags = O_NONBLOCK, // tady muze byt jenom O_NONBLOCK
        .mq_maxmsg = 8, // max messages, kolik jich muze byt v queue
        .mq_msgsize = 256, // Bytes => velikost
        .mq_curmsgs = 0, // current messages v queue
};

struct Ptr_To_Bufevents {
    struct Ftp_Sockets *ptr;
    char *command;
};


int count = 0;
int css_already = 0;

struct sockaddr_in server_control_info;
struct sockaddr_in server_data_info;

void sending_response(char *response, size_t lengthresponse, int comsocket);
void create_http_response(int comsocket);
char *printing_request(int comsocket);
char *receiving(int comsocket, SSL *ssl_object, int CONNECTION);
int next_decimal(int length);
enum Media_enum response_spec(char *buffer, int comsocket);
void handling_response(struct Thread_specific thread_obj);
char *printing_request(int scomsocket);
char *compact_request(char *buffer);
int end_of_response(char *buf);
struct response *prepare_html_response(int comsocket, char *request);
struct response *prepare_css_response(int comsocket);
struct response *prepare_favicon_response(int comsocket);
enum Account_enum login_lookup(char *username, char *password);
char *html_path(enum HTML_enum enum_var);
void username_password_extraction(char *post_request);
int is_empty(void *buf, size_t size);
char *extraction_path_files(char *buffer, int comsocket);
void send_file(char *path, int comsocket, int CONNECTION);
int account_created(char *username, char *password);
void initialization_of_openssl(void);
void handle_error();
void handle_error_thread(pthread_t thread_ID);
void *wrapper_handling_response(void *arg);
void cb(SSL *CONNECTION, int where, int ret); // musi zustat v tomto tvaru, jinak vsude muze byt struct Thread_info
int cb_alpn(SSL *ssl_connection, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int intlen, void *arg);
void *select_ftp(void *ftp_sockets);

// ~ NOT, | OR, ^ XOR, & AND, >> right shift, << left shift

/*
https://github.com/openssl/openssl/blob/master/ssl/record/rec_layer_s3.c
https://github.com/openssl/openssl/blob/53e5071f3402ef0ae52f583154574ddd5aa8d3d7/ssl/ssl_sess.c#L1392
https://github.com/openssl/openssl/blob/master/ssl/d1_msg.c
https://github.com/openssl/openssl/blob/53e5071f3402ef0ae52f583154574ddd5aa8d3d7/include/openssl/ssl.h.in#L1079
*/

// SSL_ST_MASK = 4095 (na dec) - 0FFF

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

void *wrapper_handling_response(void *arg) {
    // invalid type of argument of unary `*` => snazim se dereferencovat neco co neni typu yyy * (neco, co neni ukazatel)
    // & give me address of!
    // * give me a value on the memory address of!
    // * => JE JENOM KDYZ CHCI DEREFERENCOVAT !POINTER!

    // nastavim, ze vlakno muze ihned skoncit
    int oldstate;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ASYNCHRONOUS, &oldstate) != 0) {
        perror("pthread_setcancelstate");
        exit(EXIT_FAILURE);
    }

    int connection = ((struct Thread_info *)arg)->connection_tf; // connection
    int comsocket = ((struct Thread_info *)arg)->communication_array_tf[connection]; // dereferencovani pointeru - COMARRAY 
    pthread_t thread = pthread_self(); // ARRAYTHREAD
    SSL *ssl_connection = ((struct Thread_info *)arg)->ssl_array_tf[connection];

    Thread_specific thread_specific;
    thread_specific.connection_number = connection;
    thread_specific.communication_socket = comsocket;
    thread_specific.thread_id = thread;
    thread_specific.specific_ssl_connection = ssl_connection;


    printf("\n===Wrapper===\n");
    printf("THREADID: %lu\n", thread);
    printf("comsocket %d\n", comsocket);
    printf("thread %lu\n", thread);
    printf("connection %d\n", connection);
    fflush(stdout);

    // SSL *obj = CONNECTIONS_ARRAY[CONNECTION];
    /*
    /home/marek/Documents/FTP_SERVER/ftp_server.c:159:16: error: initialization of ‘SSL *’ {aka ‘struct ssl_st *’} from incompatible pointer type ‘SSL **’ {aka ‘struct ssl_st **’} [-Wincompatible-pointer-types]
    159 |     SSL *obj = &CONNECTIONS_ARRAY[CONNECTION];
        |                ^

    jenom mi to vysvetli, ja myslel, ze tim CONNECTIONS_ARRAY[CONNECTION] ziskam ty data a kdyz to chce pointer na SSL, tak CONNECTIONS_ARRAY[CONNECTION] neni pointer ale jenom ta hodnota? nebo protoze je to dynamicky alokovane, tak array[x] je to ze dostanu kazdy prvek a kdyz je to dynamicky alokovane to by znamenalo pointe, tak to & je tedy nepotrebne?
    */

    SSL_set_fd(ssl_connection, comsocket); // nastavi a "presmeruje" komunikaci na konkretni bod

    // staticke pole je jakoby blok pameti hned u sebe a jsou tam samotna ty data, ale kdyz je dynamicky alokovane pole, tak to znaci k tomu, ze nevime kolik presne prvku toho pole budeme mit, proto by davalo smysl do toho pole ukladat jen memory adresy tich samotnych prvku
    // staticke pole ma v sobe char, ale dostaneme se k tomu pres pointer na prvni prvek pole
    // dynamicke pole ma v sobe adresu na samotny prvek a dostaneme se k tomu pomoci pointeru


    // 0A00009C = HTTP pozadavek prisel i kdyz mel prijit pozadavek HTTPS => neni to sifrovane
    // if (SSL_accept(ssl_CONNECTION) <= 0) { // ceka az client zacne SSL/TLS handshake
    //     fprintf(stderr, "SSL/TLS se nepodarilo zacit");
    //     handle_error_thread(thread);
    // }
    int result = SSL_accept(ssl_connection);

    int errcode = SSL_get_error(ssl_connection, result);
    printf("\nerror%d\n", errcode);
    ERR_print_errors_fp(stderr); // zadna return value
    
    // handle_error();

    printf("tady jsem");
    handling_response(thread_specific);
    return "result";
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

void signal_handler() {
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

void send_server_st_reply(int ftp_control_com) {

}

int make_port_connection(uint32_t address, short int port, struct Ftp_Sockets *ptr) {
    struct sockaddr_in client_addr_port;

    client_addr_port.sin_family = AF_INET; // address family
    client_addr_port.sin_port = port;
    client_addr_port.sin_addr = address;

    int socket = connect(ptr->ftp_data_socket, (struct sockaddr *)client_addr_port, sizeof(struct sockaddr_in));
    ptr->ftp_data_com = socket;

    return fto_data_com;
}

short int return_port(char **metadata_command) {
    short int port;
    unsigned char *port_array = malloc(sizeof(unsigned char ) * 2);
    for (int i = 4, i_port_arr = 0; i < 6; i++) {
        port_array[i_port_arr++] = atoi(metadata_command[i]); // ASCII to Int
    }
    memcpy(&port, port_array, sizeof(unsigned char ) * 2); // takhle se kopiruji data celeho array do jedne promenne

    return htons(port); // aby uz to bylo na network 
}

uint32_t return_address(char **metadata_command) {
    uint32_t address;
    unsigned char *address_array = (unsigned char *)malloc(4);

    for (int i = 0, adress_array_i = 0; i < 5; i++) {
        address_array[address_array_i++] = metadata_command[i]; 
    }
    memcpy(&address, address_array, sizeof(unsigned char ) * 4);

    return htons(address);
}

char **metadata_command(char *command, struct Ftp_Sockets *ptr) {
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

char *extract_username_password(char *command_user_pass) {
    char *info = (char *)malloc(sizeof(char) * 9); // 8 chars + \0, protoze max username a passwod je 8 chars (jako i z http serveru), 9 chars => 8 chars + \0 
    memset(info, 0, sizeof(char) * 9); // automaticky NULL terminated

    char *space = strstr(" ", command_user_pass);
    int space_i = (int)(space - command_user_pass);

    char *end = strstr("\r", command_user_pass); // CRLF konci kazdy FTP command (Telnet)
    int end_i = (int)(end - command_user_pass);

    for (int i = space_i + 1, info_i = 0; i < end_i; i++) {
        info[info_i++] = command_user_pass[i];
    }
    info[info_i] = '\0'; // explicitni NULL terminator, i kdyz by to melo fungovat i bez toho, protoze tam je to memset()

    return info;
}
int available_commands(char *text) {
    // linux pouziva pro novy radek (\n) - Line Feed (0x0aA)
    // getline() bere celou radku ze souboru (dokud nenarazi na \n), getdelim() cte do te doby, nez se nenajde specifikovany delimiter
    FILE *f_stream = fopen("./TXT/available_commands.txt", "r");

    char *command_from_text = (char *)malloc(5);
    memset(command_from_text, 0, 5); // automaticky NULL terminating

    for (int i = 0; i < 5; i++) {
        command_from_text[i] = text[i];
    }

    if (f_stream == NULL) {
        perror("fopen() neotevrel soubor FTP_SERVER/TXT/available_commands.txt - is_command_or_data");
    }

    size_t len = 0;
    char *line = NULL;

    ssize_t chars_read;
    while ( (chars_read = getline(&line, &len, f_stream)) != -1) { // pokud -1 => EOF a EOF indicator set => feof(), vraci se pocet chars i s delimiterem, ale bez \0
        line[chars_read - 1] = '\0';
        if ( strcmp(line, command_from_text) != 0) { // nerovnaji se
            return 0; // false
        }
    }
    return 1; // true
}
enum Ftp_Type is_command_or_data(int comsocket) {
    char *data = (char *)malloc(31); // maximalni delka zpravy od ftp serveru => 30 chars + \0
    memset(data, 0, 31); // automaticky NULL terminated
    recv(comsocket, data, 31, MSG_PEEK); // to, co se precte se neodebere ze TCP stack internal bufferu

    if ( available_commands(data) && strstr("\r\n", text) != NULL) {
        return CONTROL;
    }
    return DATA;
}


char **execute_commands(char *command, int comsocket, struct Ftp_Sockets *ptr) {
    if (strstr("USER", command) != NULL) {
        char *username = extract_username_password(command);
    }
    else if (strstr("PASS", command) != NULL) {
        char *password = extract_username_password(command);
        Account_Spec result = login_lookup        
    }
    if (strstr("NOOP", command) != NULL) {
        send_ftp_code("200 - command okay", comsocket);
        return NULL; // muzeme vratit NULL, protoze void * pointer ((void *)0) muze nabyvat jakehokoliv typu
    }
    else if (strstr("TYPE", command) != NULL) {
        if (strstr("Image", command) != NULL) {
            data_representation = IMAGE;
        }
        else {
            data_representation = ASCII_N;
        }
    }
    else if (strstr("QUIT", command) != NULL) {
        current_user = NULL;
    }
    else if (strstr("RETR", command) != NULL) {
        send_file_bypath();
    }
    else if (strstr("STOR", command) != NULL) {
        char *st_space = strstr(" ", command);
        int i_st_space = (int)(st_space - command);

        char *path = (char *)malloc(strlen(command) - i_st_space + 1);
        int path_i = 0;
        for (int i = i_st_space + 1; i < strlen(command) + 1; i++) {
            path[path_i++] = command[i];
        }
        path[path_i] == '\0';

        // get_file from data and save it
    }
    else if (strstr("PORT", command) != NULL) {
        // send this information
        char **array = metadata_command(command, ptr);
        // x1,x2,x3,x4,p1,p2

        short int port = return_port(array);
        uint32_t address = return_address(array);
        int ftp_data_com = make_port_connection(address, port, ptr);
    }
    else if (strstr("PASV", command)) {
        const char *address = (const char *)malloc(INET_ADDRSTRLEN); // 255.255.255.255 => 15 + \0 => INET_ADDRSTRLEN
        if ( !inet_ntop(server_data_info.sin_family, &server_data_info.sin_addr.s_addr, address, INET_ADDRSTRLEN)) {
            perror("inet_ntop() selhalo - execute_commands");
        }
        
        for (int i = 0; i < INET_ADDRSTRLEN; i++) {
            if (address[i] == '.') {
                address[i] = ',';
            }
        }
        unsigned char *port_array = &server_data_info.sin_port;
        int st_Byte_port = port_array[0];
        int nd_Byte_port = port_array[1];

        char *reply = (char *)malloc(50);
        memset(reply, 0, 50);

        snprintf(reply, 49, "227 Entering Passive Mode (%s,%d,%d)", address, st_Byte_port, nd_Byte_port); // prida i \0
    }
}

void bufevent_read_cb_control(struct bufferevent *buf_event, short events, void *ptr_arg) {
    // v bufferu muzou byt vice TCP segmentu (data z TCP segmentu)
    struct Ftp_Sockets *ftp_sockets_p = (struct Ftp_Sockets *)ptr_arg;

    unsigned char *command = (unsigned char *)malloc(256);
    ssize_t bytes_received = 0;
    size_t bytes_received_total;

    // UDP dela to, ze pokud supplied buffer je mensi nez samotna zprava, tak se naplni buffer a potom se zbytek dat orizne, zatimco TCP toto nedela a data cekaji v TCP stack bufferu
    // ftp commands jsou ukonceny CRLF jako v Telnetu (\r\n)
    char *possible_crlf;
    while ( (bytes_received = recv(ftp_sockets_p->control_com, command + bytes_received_total, 256 - bytes_received_total, 0)) != 0) { // return value 0 = EOF/ 0 bytes prislo
        if (bytes_received == -1) {
            perror("recv() selhal - receive_code_data");
            exit(EXIT_FAILURE);
        }
        else if (possible_crlf = strstr("\r\n", command)) { // \r\n, takhle se zakoncuji FTP prikazy \r == 13 dec, \n == 10 dec
            int crlf_i = (int)(possible_crlf - command); // pokud by byly vice commands, tak se to muze udelat pomoci MSG_PEEK, zkusit nejakou delku a potom opravdu to precist apod.
            execute_commands(command, ftp_sockets_p);
        }
        bytes_received_total += bytes_received;
    }
}

void send_control(int control_com, char *buf) {
    ssize_t bytes_total = 0;
    size_t bytes_sent;
    while ( bytes_sent = send(control_com, buf + bytes_total, (strlen(buf) + 1) - bytes_total, 0) ) {
        if (bytes_sent == -1) {
            perror("send() selhal - bufevent_write_cb_control");
            exit(EXIT_FAILURE);
        }
        bytes_total += bytes_sent;
    }
}

void bufevent_write_cb_control(struct bufferevent *buf_event, short events, void *ptr_arg) {
    // control/data connection
    // based on that either send file or send an ftp code
    struct Ftp_Sockets *ftp_sockets_p = (struct Ftp_Sockets *)ptr_arg;

    switch(ftp_user_info.user_loggedin) {
        case 0:
            if (ftp_user_info.username == NULL) {
                char *buf = "Name (!AVE CHRISTUX REX FTP SERVER!) Name: ";
                send_control(ftp_sockets_p->control_com, buf);
            }
            else if (ftp_user_info.password == NULL) {
                char *buf = "Password: ";
                send(ftp_sockets_p->control_com, buf);
            }
            // false
            break;
        case 1:
            // true
            break;
        default:
            fprintf(stderr, "spatna hodnota u user_loggedin - bufevent_write_cb_control");
            exit(EXIT_FAILURE);
            break;
    }
    ;

    // pokud user logged in, tak pokracovat, pokud ne, tak poslat USER, PASS
}

void *handle_ftp_connections(void *temp_p) {
    struct Ftp_Sockets *ftp_sockets_p = (struct Ftp_Sockets *)temp_p;

    // int ftp_control_com = ftp_sockets_p->ftp_control_com; // nebude zmateni, kompilator vi, ze nalevo je promenna a napravo je clen struktury, proto si to nepoplete
    // // kdyz nevime delku zpravi, tak bud musime poslat pred samotnou zpravou, kolik Bytes to bude chtit nebo udelame non-blocking socket => libevent
    // ftp_sockets_p->control_or_data = CONTROL;

    struct event_base *evbase = event_base_new(); // default settings

    if (evbase == NULL) {
        perror("event_base_new() selhal - data_connection");
        exit(EXIT_FAILURE);
    }

    struct bufferevent *buf_event = bufferevent_socket_new(evbase, ftp_control_com, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE | BEV_OPT_UNLOCK_CALLBACKS); // thread safe

    bufferevent_setcb(buf_event, bufevent_read_cb_control, bufevent_write_cb_control, NULL, ftp_sockets_p); // prvni NULL je pro eventcb, coz by melo byt ale stejny cb jako u event_base, ftp_sockets_p je pointer na argumenty ke vsem temto funkcim

    // edge-trigger event a level event trigger
    // toto se pouziva i digitalnich obvodech, ale v trochu jinem svetle, ale predstavme si 0 a 1 a stav mezi nimi, zkracene to znamena kdyz mame nejake event (hodnotu 0 nebo 1), tak u level event trigger dostaneme notifikaci s tim, ze event byl spusten a tato notifikace nam zustane porad nekde ulozena (u epoll revents nebo u libevent), ale porad tam bude napsane, ze je mozno neco udelat, ale kdyz to bude edge trigger, tak dostaneme jenom tu notifikaci o tom, ze neco je pripravene a tuto notifikaci dostaneme jenom jednou do te doby nez treba ten socket neprecteme z neho vsechny data a potom az muzeme dostat dalsi upozorneni od onoho socketu, takovy nonblocking upozorneni

    struct event *event_read = event_new(evbase, ftp_control_com, EV_READ | EV_WRITE, event_callback, NULL); // initialized event
    event_add(event_read, NULL); // event pending, to druhe je pro timeval struct pro timeval struct, proto, aby se v event loopu cekalo na ten timeout a potom se reklo, jestli se ten event opravdu stal nebo ne

    event_base_loop(event_base, EVLOOP_NONLOCK | EVLOOP_NO_EXIT_ON_EMPTY); // bude cekat nez se nejake eventy udelaji ready a pokud zadne nebudou ready, tak se z tohoto loopu nevyskoci
}
// BUFFEREVENT ZNAMENA ZE SE TO BUDE PSAT ZA NAS, HIGH-LEVEL API
void *data_connection(void *temp_p) {
    struct Ftp_Sockets *ftp_sockets_p = (struct Ftp_Sockets *)temp_p;

    int ftp_data_com = ftp_sockets_p->ftp_data_com; // nebude zmateni, kompilator vi, ze nalevo je promenna a napravo je clen struktury, proto si to nepoplete

    struct event_base *evbase = event_base_new(); // struct holding events
    
    if (event_base == NULL) {
        perror("event_base_new() selhalo");
        exit(EXIT_FAILURE);
    }

    struct bufferevent *buf_event = bufferevent_socket_new(); // umozni nam ziskat eventy o sockety 





}

void *select_ftp(void *ftp_sockets) {
    // accept ma uz zabudovany pocet file descriptoru, ktere obslouzi, a to je 1024, je to pole typu long, kde kazdy bit je jeden file descriptor => bit. 256 => file descriptor 256
    // na jeden long je to 64 bitu (8 Bytes) => 1024 / 64 = 16, vetsinou tato maska je 16 Bytes velka
    
    // kdyz dereferencujeme void * pointer, tak kompilator nevi, kolik Bytes musi dereferencovat => warning, ale nemuzeme udelat, protoze si to kompilator nezapamatuje => casting je JEN ONE TIME THING, museli bychom typecastovat u kazdeho, proto radsi udelam novy pointer
    // (struct Ftp_Sockets *)ftp_sockets;
    struct Ftp_Sockets *ftp_sockets_p = (struct Ftp_Sockets *)ftp_sockets;
    printf("\n\nHALOOOO, ted jsem tady\n\n\n\n");

    // struct timeval nema zadne pocatecni hodnoty, proto se to musi nastavit obe
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    fd_set readbitmask;
    FD_ZERO(&readbitmask);

    FD_SET(ftp_sockets_p->ftp_control_socket, &readbitmask);
    FD_SET(ftp_sockets_p->ftp_data_socket, &readbitmask);

    void *(*handle_ftp)(void *) = &handle_ftp_connections;
    // void *(*f_data_con)(void *) = &data_connection;

    // read, write, exception
    // kousek na tom socketu prijme, kousek na tom socketu zapise, moc se nedeje, je to exception treba out of band data u TCP
    int nfds = ftp_sockets_p->ftp_data_socket > ftp_sockets_p->ftp_control_socket ? ftp_sockets_p->ftp_data_socket : ftp_sockets_p->ftp_control_socket;
    nfds++;
    int rv = select(nfds, &readbitmask, NULL, NULL, &timeout);
    
    printf("%d", rv);
    fflush(stdout);
    // select vraci total pocet vsech file desciptoru, ktere jsou volne na operaci (v ramci daneho fd_setu)
    // pokud se tento if statement nestane, tak ono prijde SYN => SYN queue, odesle se SYN + ACK => client je touto dobou uz pripojeny, posle ACK, ted je server pripojeny, ale je to pripojene jenom na kernel level, protoze server neudelal accept()! => z tohoto muze byt velky problem => SYN flood, connection pool flooding => DoS
    if (rv == 2) {
        printf("\n\n\nANO, JE TO VSE OK\n\n\n\n\n");
        fflush(stdout);

        ftp_sockets_p->ftp_data_com = -1;

        ftp_sockets_p->ftp_control_com = accept(ftp_sockets_p->ftp_control_socket, NULL, NULL);
        pthread_t thread_control;

        if ( (thread_control = (pthread_create(thread_control, NULL, handle_ftp, (void *)ftp_sockets))) !=  0) {
            perror("pthread_create() selhal - select_ftp");
            exit(EXIT_FAILURE);
        }

        // ftp_sockets_p->ftp_data_com = accept(ftp_sockets_p->ftp_data_socket, NULL, NULL);
        // printf(":%d :%d", ftp_sockets_p->ftp_control_com, ftp_sockets_p->ftp_data_com);
        // fflush(stdout);
        return NULL;
    }
    else {
        exit(EXIT_FAILURE);
    }
    printf("\n\n\n\nnestalo se\n\n\n\n");

    return NULL;
}

int main()
{
    // client ma toho vice na praci, protoze si musi nastavit taky kontext (jako server), nastavit sifry (jako server), musi mit logiku na overovani toho certifikatu,
    // kdyztak pridat nejake flags (jako server)
    // pokud client pouziva BIO, tak si musi cely handshake delat sam, pokud pouziva klasicke SSL_connect, tak se to udela automaticky

    // char *x = (char*)malloc(10);
    // na heapu bude 10 Bytes a protoze je to char *x, tak pole &x[0] bude pointer na char, takze jakoby pointer na char a char zaroven
    // a protoze malloc vraci void * protoze to nejspise podporuje filosofii, tady mas kus pameti, delej si s ni co chces
    // tak protoze mi dostaneme pointer na uplny zacatek, tak je potreba specifikovat na jaky datovy typ ten pointer bude ukazovat
    // char *x = (char *)malloc(10);

    initialization_of_openssl();

    const SSL_METHOD *method = TLS_server_method(); // SSL_METHOD je datova struktura popisujici internalni informace o protokolech, ktere se pouziji
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

    
    memset(&server_control_info, 0, sizeof(struct sockaddr_in));
    server_control_info.sin_family = AF_INET;
    server_control_info.sin_port = htons(CONTROL_PORT);

    
    memset(&server_data_info, 0, sizeof(struct sockaddr_in));
    server_data_info.sin_family = AF_INET;
    server_data_info.sin_port = htons(DATA_PORT);

    // muze se do davat rovnou do te struktury, protoze ma jen jednoho clena a tam se kopiruji ty data a zrovna to vyjde na tu delku, ale kdyby tam byly dva cleny, tak je lepsi tam uvest samotneho clena te struktury
    if ( inet_pton(server_control_info.sin_family, "127.0.0.1", &server_control_info.sin_addr) <= 0) {
        perror("inet_pton() selhal - ftp_control");
        exit(EXIT_FAILURE);
    }

    if ( inet_pton(server_data_info.sin_family, "127.0.0.1", &server_data_info.sin_addr) <= 0) {
        perror("inet_pton() selhal - ftp_data");
        exit(EXIT_FAILURE);
    }

    int ftp_control_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (ftp_control_socket == -1) {
        perror("socket() selhal - ftp_control");
        exit(EXIT_FAILURE);
    }

    int ftp_data_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (ftp_data_socket == -1) {
        perror("socket selhal - ftp_data");
        exit(EXIT_FAILURE);
    }

    int optvalftp = 1;
    if ( setsockopt(ftp_control_socket, SOL_SOCKET, SO_REUSEADDR, &optvalftp, sizeof(int)) == -1) {
        perror("setsockopt() selhal - ftp_control");
        exit(EXIT_FAILURE);
    }
    if ( setsockopt(ftp_data_socket, SOL_SOCKET, SO_REUSEADDR, &optvalftp, sizeof(int)) == -1) {
        perror("setsockopt() selhal - ftp_data");
        exit(EXIT_FAILURE);
    }

    if ( bind(ftp_control_socket, (struct sockaddr *)&server_control_info, sizeof(struct sockaddr)) == -1) {
        perror("bind() selhal - ftp_control");
        exit(EXIT_FAILURE);
    }
    if ( bind( ftp_data_socket, (struct sockaddr *)&server_data_info, sizeof(struct sockaddr)) == -1) {
        perror("bind() selhal - ftp_data");
    }

    // clock_t time = clock() / CLOCKS_PER_SEC;

    if ( listen(ftp_control_socket, BACKLOG) == -1) {
        perror("listen() selhal - ftp_control");
        exit(EXIT_FAILURE);
    }
    if ( listen(ftp_data_socket, BACKLOG) == -1) {
        perror("listen() selhal - ftp_data");
        exit(EXIT_FAILURE);
    }

    ftp_sockets.ftp_control_socket = ftp_control_socket;
    ftp_sockets.ftp_control_com = -1;
    ftp_sockets.ftp_data_socket = ftp_data_socket;
    ftp_sockets.ftp_data_com = -1;

    pthread_t ftp_threadID;
    if (pthread_create(&ftp_threadID, NULL, select_ftp, (void *)&ftp_sockets) != 0) {
        perror("pthread_create() selhal - ftp");
        exit(EXIT_FAILURE);
    }

    int ftp_control_com = ftp_sockets.ftp_control_com;
    int ftp_data_com = ftp_sockets.ftp_data_com;
    // je potreba toto udelat pro vice konekci, ted je to jen pro jednu
    // int ftp_control_com;
    // int ftp_data_com;
    // if (select_ftp(ftp_control_socket, ftp_data_socket) == EXIT_SUCCESS) { // 0
    //     ftp_control_com = accept(ftp_control_socket, NULL, NULL);

    //     ftp_data_com = accept(ftp_data_socket, NULL, NULL);
    // }






    struct sockaddr_in http_server_info;
    memset(&http_server_info, 0, sizeof(http_server_info));

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

    if ( setsockopt(http_socket, SOL_SOCKET, SO_REUSEADDR, &option_value, sizeof(option_value)) == -1) {
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

    ARRAYTHREAD = (pthread_t *) calloc(MAX_THREADS, sizeof(pthread_t));
    CONNECTIONS_ARRAY = (SSL **)calloc(MAX_THREADS, sizeof(SSL *));
    COMARRAY = (int *) calloc(MAX_THREADS, sizeof(int));
    EVENT_CONTEXT = (struct event_base **) calloc(MAX_THREADS, sizeof(struct event_base *));

    if (ARRAYTHREAD == NULL) { // nebo !ARRAYTHREAD
        perror("calloc() selhal - ARRAYTHREAD");
        exit(EXIT_FAILURE);
    }

    if (CONNECTIONS_ARRAY == NULL) { // nebo !CONNECTIONS_ARRAY
        perror("calloc() selhal - CONNECTIONS_ARRAY");
        exit(EXIT_FAILURE);
    }

    if (COMARRAY == NULL) {
        perror("calloc() selhal - COMARRAY");
        exit(EXIT_FAILURE);
    }

    if (EVENT_CONTEXT == NULL) {
        perror("calloc() selhal - EVENT_CONTEXT");
        exit(EXIT_FAILURE);
    }

    // vezmi muj pointer comarray a chci aby se k tim datum v teto memory oblasti, ktera je ulozena prave v tomto pointeru, choval jako pointer na int>!
    // pointer na int => pointer (comarray) na pole int!!!
    // array[x] dostanu SAMOTNY ten prvek, je to alternativa *(array + x)

    // !!
    // SSL samotny objekt v OpenSSL NEEXISTUJE a nemel by se pouzivat, jenom POINTER NA SSL/POLE POINTERU NA SSL!!
    // nedokoncena struktura (opague type) = struktura, ktera neni viditelna v hlavickach a struktura, jejiz obsah je neznamy pri prekladu, pointer uz endela problemys opaque type
    // !!

    for(;;) {
        printf("\n\nAVE CHRISTUS REX\n\n");
        fflush(stdout);
        int httpcomsocket = accept(http_socket, (struct sockaddr *)&httpclient_info, &httpclient_infolen);

        // int *array = mallo()..., tak to pole se sklada z normalnich intu, ktere jsou ulozene na heapu hned za sebou, proto treba u realloc() se ukazuje na novou
        // memory lokaci, aby to bylo hezky za sebou, ALE my dostaneme POINTER ns tuto memory oblast, coz JE POINTER na int! 
        // ale pro ukladani muzeme jenom specifikovat ten pointer, nejaky offset a samotnou int hodnotu, protoze to je pole plne normalmich hodnot int
        COMARRAY[CONNECTION] = httpcomsocket;

        if (COMARRAY[CONNECTION] != httpcomsocket) {
            fprintf(stderr, "prirazovani hodnoty do pole COMARRAY nebylo uspesne");
            handle_error();
        }

        CONNECTIONS_ARRAY[CONNECTION] = SSL_new(ctx); // vytvori novou SSL strukturu, ktera v sobe drzi real time informace o pripojeni, pouziva malloc!
        if (CONNECTIONS_ARRAY[CONNECTION] == NULL) {
            handle_error();
        }

        SSL_set_accept_state(CONNECTIONS_ARRAY[CONNECTION]); // explicitni oznaceni, ze tento kod bude pracovat jako server

        printf("\n\n\n\n\n\n\n\nnovy userrrrr\n\n\n\n");
        fflush(stdout);
        if (httpcomsocket == -1) {
            perror("accept() selhal - http");
            return EXIT_FAILURE;
        }
        
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

        thread_info.ssl_array_tf = (SSL **)calloc(MAX_THREADS, sizeof(SSL *));
        thread_info.communication_array_tf = (int *)calloc(MAX_THREADS, sizeof(int));
        
        pthread_mutex_t lock_thread_info; // mezi lock a unlock se ta promenna neda updatnout nikoliv jinym a kdyby jo, tak by thread blokoval, nez se to odemkne!
        pthread_mutex_lock(&lock_thread_info);
        // ssl_array[CONNECTION] pointer ukazuje na stejnou memory oblast jako CONNECTIONS_ARRAY[CONNECTION]! pokud free(CONNECTIONS_ARRAY), tak ssl_array garbage values!
        thread_info.ssl_array_tf[CONNECTION] = CONNECTIONS_ARRAY[CONNECTION];
        // kopiruji se samotne hodnoty, nikoliv ukazatele, pokud uz nebude comarray, tak COMMUNICATION_array bude v poradku, protoze se predavaji samostatne hodnoty, ne jen ukazatele!
        thread_info.communication_array_tf[CONNECTION] = COMARRAY[CONNECTION];
        thread_info.connection_tf = CONNECTION;
        pthread_mutex_unlock(&lock_thread_info); // odemceno

        // info.httpcomsocket = httpcomsocket;
        // info.CONNECTION = CONNECTION;
        
        if (pthread_create(&ARRAYTHREAD[CONNECTION], NULL, wrapper_handling_response, (void *)&thread_info) != 0) { // pointer na konkretni thread, pointer na strukturu s atributy na thread, pointer na funkci, kterou thread bude konat void* (*f_pointer)(int) = function;, pointer na arg (void *)
            exit(EXIT_FAILURE);
        }

        printf("\n===MAIN===\n");
        printf("comsocket: %d\n", httpcomsocket);
        printf("threadID: %lu\n", ARRAYTHREAD[CONNECTION]);
        printf("CONNECTION: %d\n", CONNECTION);
        fflush(stdout);

        // nebudu moct vedet, jaky bude jeho return value, ale po skonceni tohoto threadu se jeho recources uvolni samy
        // temp
        if (pthread_detach(ARRAYTHREAD[CONNECTION]) != 0) {
            perror("pthread_detach() selhal");
            exit(EXIT_FAILURE);
        }

        // asi do ssl_CONNECTION se neukladaji udaje

        if (CONNECTION == (MAX_THREADS - 1) ) {
            MAX_THREADS += 5;
            
            pthread_t *temp_arraythread = (pthread_t *)realloc(ARRAYTHREAD, sizeof(pthread_t) * MAX_THREADS);
            SSL **temp_connections_array = (SSL **)realloc(CONNECTIONS_ARRAY, sizeof(SSL *) * MAX_THREADS);
            int *temp_comarray = (int *)realloc(COMARRAY, sizeof(int) * MAX_THREADS);

            SSL **ssl_array_tf_temp = realloc(thread_info.ssl_array_tf, sizeof(SSL *) * MAX_THREADS);
            int *communication_array_tf_temp = realloc(thread_info.communication_array_tf, sizeof(int) * MAX_THREADS);

            struct event_base **event_context_temp = realloc(EVENT_CONTEXT, sizeof(struct event_base *) * MAX_THREADS); // realloc() stary blok memory automaticky uvolni, nemusim to delat manualne!
            EVENT_CONTEXT = event_context_temp;

            if (!temp_arraythread || !temp_connections_array || !temp_comarray || !ssl_array_tf_temp || !communication_array_tf_temp || !event_context_temp) {
                perror("realloc() selhal");
                fflush(stdout);
                exit(EXIT_FAILURE);
            }

            ARRAYTHREAD = temp_arraythread;
            CONNECTIONS_ARRAY = temp_connections_array;
            COMARRAY = temp_comarray;

            thread_info.ssl_array_tf = ssl_array_tf_temp;
            thread_info.communication_array_tf = communication_array_tf_temp;
        }

        // close(httpcomsocket);
        CONNECTION++;
        printf("deje se neco?");
        fflush(stdout);
    }
    return EXIT_SUCCESS;
}

char *html_path(enum HTML_enum enum_var) {
    switch (enum_var) {
        case HTML_FORMULAR_PRIHLASENI:
            // memcpy(html_path_union.path_prihlaseni, "/home/marek/Documents/FTP_SERVER/HTML/formular_prihlaseni.html", strlen("/home/marek/Documents/FTP_SERVER/HTML/formular_prihlaseni.html"));
            html_path_union.path_prihlaseni = strdup("/home/marek/Documents/FTP_SERVER/HTML/formular_prihlaseni.html");
            return html_path_union.path_prihlaseni;
            break;
        case HTML_FORMULAR_TVORBA_UCTU:
            html_path_union.path_tvorba = strdup("/home/marek/Documents/FTP_SERVER/HTML/formular_tvorba_uctu.html");
            return html_path_union.path_tvorba;
            break;
        case HTML_FILES_HTML:
            html_path_union.path_files = strdup("/home/marek/Documents/FTP_SERVER/HTML/files_html.html");
            return html_path_union.path_files;
            break;
        case HTML_INVALID_LOGINS:
            html_path_union.path_invalid = strdup("/home/marek/Documents/FTP_SERVER/HTML/invalid_logins.html");
            return html_path_union.path_invalid;
            break;
        case HTML_ACCOUNT_TAKEN:
            printf("\n\n\nCOZE JAK TO ZE TADY\n\n\n");
            html_path_union.path_account = strdup("/home/marek/Documents/FTP_SERVER/HTML/account_taken.html");

            return html_path_union.path_account;
            break;
        case HTML_UNKNOWN_TYPE:
            html_path_union.path_unknown = strdup("/home/marek/Documents/FTP_SERVER/HTML/neznamy_typ_requestu.html");
            return html_path_union.path_unknown;
            break;
        default:
            printf("\nHTML_spec enum je bud moc maly nebo moc velky: %d\n", enum_var);
            exit(EXIT_FAILURE);
    }
}
struct response *prepare_favicon_response(int comsocket) {
    printf("\n\n\n\n\n\n\nHEJ FAVICON\n\n\n\n\n\n");
    char wd[50];
    getcwd(wd, sizeof(wd));
    printf("\n%s\n", wd);
    struct stat info;
    if ( stat("/home/marek/Documents/FTP_SERVER/IMAGES/icon.avif", &info) == -1) {
        perror("stat() selhal");
        exit(EXIT_FAILURE);
    }
    size_t lengthfile = info.st_size;
    printf("\nLengthfile: %zu\n", lengthfile);
    FILE *filepointer = fopen("/home/marek/Documents/FTP_SERVER/IMAGES/icon.avif", "rb"); // icon.avif

    if (filepointer == NULL) {
        perror("fopen() selhal - favicon.ico");
        exit(EXIT_FAILURE);
    }

    unsigned char *buffer = (unsigned char *)malloc(lengthfile);

    if ( buffer == NULL) {
        perror("malloc() selhal");
        exit(EXIT_FAILURE);
    }

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
    "Cache-Control: no-cache, no-store\r\n"
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

    struct response *favicon_response = (struct response *)malloc(sizeof(struct response));
    // printf("\n\nRESPONSEBUF: %s, BUFFER: %s", responsebuf, buffer);

    favicon_response->content = (unsigned char *)malloc(RESPONSELEN);
    memset(favicon_response->content, 0, RESPONSELEN);
    memcpy(favicon_response->content, responsebuf, RESPONSELEN); // alokace na heap

    // corrupted top size = heap je poskozen nekdy nastala chyba v memory

    // kitchen-headers => placani vsemoznych hederu za sebou do jedne kategorie jako např. Cach-Control...
    // favicon_response->content = strdup(responsebuf); // nemuzu pouzit strdup, protoze kopiruje string az do \0, v .avif souboru je hodne \0, proto musim 
    // alokovat nejake misto pro ten pointer na heapu a potom to tam zkopirovat
    favicon_response->content_length = lengthresponse;
    favicon_response->communication_socket = comsocket;

    return favicon_response;
}

struct response *prepare_html_response(int comsocket, char *request) {
    if ( strstr(request, "GET")) {
        if (strstr(request, "formular_tvorba_uctu") ) {
            HTML_spec = HTML_FORMULAR_TVORBA_UCTU; 
        }
        else {
            HTML_spec = HTML_FORMULAR_PRIHLASENI;
        }
    }
    else if ( strstr(request, "POST") ) {
        if ( strstr(request, "formular_tvorba_uctu") ) {
            username_password_extraction(request);
            printf("\n HTML_SPEC %d\n", HTML_spec);
            account_created(user_data.username, user_data.password);
            printf("\n HTML_SPEC %d\n", HTML_spec);
        }
        else if ( strstr(request, "formular_prihlaseni") ){
            Account_spec = login_lookup(user_data.username, user_data.password);
            printf("%s %s", user_data.username, user_data.password);
            switch (Account_spec) {
                case ACCOUNT_EXIST:
                    HTML_spec = HTML_FILES_HTML;
                    printf("\n\nACCOUNT_EXIST prepare html\n\n");
                    system("python /home/marek/Documents/FTP_SERVER/PYTHON/dynamic_table.py");
                    break;
                case ACCOUNT_TAKEN:
                    printf("\n\nACCOUNT_TAKEN prepare html\n\n");
                    HTML_spec = HTML_ACCOUNT_TAKEN;
                    break;
                case ACCOUNT_INVALID_OR_FREE:
                    printf("\n\nACCOUNT_INVALID OR FREE prepare html\n\n");
                    HTML_spec = HTML_INVALID_LOGINS;
                    break;
                default:
                    exit(EXIT_FAILURE);
            }
        }
    }
    else {
        HTML_spec = HTML_UNKNOWN_TYPE;
    }
    char *filepath = html_path(HTML_spec);
    FILE *filepointer = fopen(filepath, "r");
    if (filepointer == NULL) {
        perror("fopen() selhal - filepointer");
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

    char headers[HEADERLEN];
    snprintf(headers, HEADERLEN,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Connection: keep-alive\r\n"
    "Cache-Control: no-store\r\n"
    "Content-length: %zu\r\n\r\n", lengthfile);
    size_t headerslen = strlen(headers);

    char responsebuf[RESPONSELEN];
    snprintf(responsebuf, RESPONSELEN, "%s%s", headers, htmlcode);

    size_t lengthresponse = strlen(responsebuf);

    struct response *html_response = (struct response *)malloc(sizeof(struct response));
    printf("%s", responsebuf);
    html_response->content = strdup(responsebuf);
    html_response->content_length = lengthresponse;
    html_response->communication_socket = comsocket;

    html_response->content[html_response->content_length] = '\0';
    return html_response;
}

struct response *prepare_css_response(int comsocket) {
    char *filepath = "/home/marek/Documents/FTP_SERVER/CSS/formular_server.css";

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
    "Cache-Control: no-store\r\n"
    "Content-length: %zu\r\n\r\n", lengthfile);

    char csscode[lengthfile];

    if ( fread(csscode, sizeof(char), lengthfile, filepointer) == 0) {
        perror("fread() selhal");
        exit(EXIT_FAILURE);
    }

    char responsebuf2[RESPONSELEN];
    snprintf(responsebuf2, RESPONSELEN, "%s%s", headers, csscode);

    size_t lengthresponse = strlen(responsebuf2);
    
    struct response *css_response = (struct response *)malloc(sizeof(struct response));
    css_response->content = strdup(responsebuf2);
    css_response->content_length = lengthresponse;
    css_response->communication_socket = comsocket;

    return css_response;
}

int next_decimal(int length) {
    int result = ( ( (length / 10) * 10 + 10) - length) + length;
    return result;
}

void send_file(char *path, int comsocket, int CONNECTION) {

    printf("\n\n\n\nSEND_FILE");
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

    printf("\n\nTEMPNAME: %s\n\n\n\n\n\n\n\n\n\n\n\n\n\n", name);
    fflush(stdout);

    char headers[HEADERLEN + 60];
    snprintf(headers, HEADERLEN + 60,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Cache-Control: no-cache\r\n"
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
        bytes_now_send = SSL_write(CONNECTIONS_ARRAY[CONNECTION], response + bytes_sent, size);
        counter++;
        printf("\n\nWHILE LOOP SEND - SEND_FILE()");
        if (bytes_now_send == -1) {
            perror("send() selhal - send_file");
            exit(EXIT_FAILURE);
        }

        bytes_sent += bytes_now_send;
        printf("\nBytes_sent = %d, Bytes_now_send = %d, size = %d, send() counter = %d", bytes_sent, bytes_now_send, size, counter);
    }
}

char *extraction_path_files(char *buffer, int comsocket) {

    char *start_path = strstr(buffer, "GET") + strlen("GET ");
    int index_start_path = (int)(start_path - buffer);

    char *path = (char *)malloc(100);
    int index_path = 0;
    for (int index = index_start_path; buffer[index] != ' '; index++) {
        path[index_path] = buffer[index];
        index_path++;
    }

    path[index_path] = '\0';

    return path;
}


int account_created(char *username, char *password) {

    FILE *filepointer = fopen("/home/marek/Documents/FTP_SERVER/TXT/accounts.txt", "a");

    if (filepointer == NULL) {
        perror("fopen() selhal");
        exit(EXIT_FAILURE);
    }

    size_t lenusername = strlen(username);
    size_t lenpassword = strlen(password);

    Account_spec = login_lookup(username, password);
    printf("\n\n \x1b[35m ACCOUNT_SPEC: %d \x1b[0m \n\n", Account_spec);
  
    fflush(stdout);

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
    }

    if (Account_spec != ACCOUNT_INVALID_OR_FREE) {
        return 1;
    }
    
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

    return 0;
}


enum Media_enum response_spec(char *buffer, int comsocket) {
    
    printf("\nresponse_spec()\n");
    if ( strstr(buffer, "GET") ) {
        if ( !strstr(buffer, "/CSS/") && !strstr(buffer, "/IMAGES/") && !strstr(buffer, "/favicon.ico") && !strstr(buffer, "/TXT/") && !strstr(buffer, ".txt")) { // pro jakekoliv txt soubory i kdyz nejsou v /TXT
            printf("\nHTML - response_spec\n");
            return HTML;
        }
        else if ( (strstr(buffer, "/CSS/")) ) { // && strstr(buffer, "image/avif") == NULL
            printf("\nCSS - response_spec\n");
            return CSS;
        }
        else if ( strstr(buffer, "/IMAGES/") || strstr(buffer, "/favicon.ico")) {
            // exit(EXIT_FAILURE);
            printf("\nFAVICON - response_spec\n");
            return FAVICON;
        }
        else if ( strstr(buffer, "/TXT/") || strstr(buffer, ".txt")) { // pro jakekoliv soubory i kdyz nejsou v /TXT
            printf("\nTXT - response_spec\n");
            return TXT;
        }
    }
    else if ( strstr(buffer, "POST") ) {
        if ( strstr( buffer, "formular_prihlaseni") ) {
            printf("\nPOST - response_spec\n");
            username_password_extraction(buffer);
            printf("\nPOST BUFFER%s", buffer);
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

int end_of_response(char *buf) {
    char *foundin_buf = strstr(buf, "\r\n\r\n");
    if ( foundin_buf) {
        int length_receivedresponse = (int)(foundin_buf - buf);
        css_already++;
        if (css_already > 1) {
            printf("\nbuffer %c\n", buf[strlen(buf) + 1]);
            printf("\nbuffer %s\n", buf);
        }
        

        return length_receivedresponse;
        // if (buf[length_receivedresponse + 4]) {
        //     return length_receivedresponse;
        // }
        
        return -2;

        
    }
    else {
        return -1;
    }
}

enum Account_enum login_lookup(char *username, char *password) {
    int username_indicator = 0;
    printf("\n\n\n\n\n\x1b[32m login_lookup() \x1b[0m\n");
    FILE *fp = fopen("/home/marek/Documents/FTP_SERVER/TXT/accounts.txt", "r");

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

    memcpy(user_data.username, username, strlen(username));
    memcpy(user_data.password, password, strlen(password));
    
    // printf("\n\nTady to je username: %s,  password: %s", username, password);
}

char *receiving(int comsocket, SSL *ssl_object, int CONNECTION) {
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

        bytes_pending = SSL_pending(CONNECTIONS_ARRAY[CONNECTION]);
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
            printf("%s", data);
            // printf("\n\nDATA: %s\n\n", data);
            // printf("\ndata\n%s", data);
            printf("%s", data);
            fflush(stdout);
            return data;
        }
        else if (bytes_pending >= 0) { // uz i na zacatku
            bytes_now = SSL_read(ssl_object, data + recv_bytes, SIZE - 1); // pokud se
            printf("\nbytes_now: %zu", bytes_now);
            iteration++; // BEZ TOHO SIGSIEV => FATAL SIGNAL
            recv_bytes += bytes_now;

            // problem je ten, ze ja data freenu tady, potom poslu signal thread at se ukonci, ale to muze trvat dele a nemusi to byt hned, takze se muze stat, ze se vrati retrun memory oblasti a ja potom freenu stejnou pametovou oblast podruhe => erro
            // nebo bych mohl udelat pthread_exit(), to to vlakno ukonci ihned, ale pokud treba drzi nejake mutexy, tak je nepusti => muze dojit k deadlock v jinych threads
            if (bytes_now <= 0) {
                // eof je to, ze se neco cte a potom se narazi na to, ze klient z niceho nic prerusi spojeni
                if (bytes_now == 0) {
                    printf("\npeer ukoncil spojeni\n");
                    printf("received bytes: %zu", recv_bytes);
                    printf("\n\ndata: %s", data);
                    // perror("peer ukoncil spojeni"); // nedavalo by smysl pouzivat perror(), protoze nenastal zadny error, jenom se mi reklo, ze to vratilo nejaky pocet Bytes
                    // free(data);
                    fflush(stdout);
                    handle_error_thread(threadID);
                } // na firefoxu to bezi ok, ale na google, jak se pripoji novy user, tak ono to posle encrypted alert a potom se posle RST, to je problem s encrypci?
                else if (bytes_now < 0) { // ale ikdyz se pripojim vicekrat z jednoho browseru, mozna je to problem s comsocketem, ze ho jakoby "recykluji"
                    printf("\nSSL_read() selhal\n");// misto perror()
                    fflush(stdout);
                    // free(data);
                    handle_error_thread(threadID);
                }
                
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

void handling_response(struct Thread_specific thread_obj) {
    // every member of thread specific so it's on the private stack
    int connection = thread_obj.connection_number;
    int comsocket = thread_obj.communication_socket;
    pthread_t threadID = pthread_self();
    SSL *ssl_connection = thread_obj.specific_ssl_connection;


    while (1) {
        printf("\n\n  \x1b[31m HALOOOOO JSEM TADY \x1b[0m");    
        fflush(stdout);
        count++;
    
        char *request = receiving(comsocket, ssl_connection, connection);
        printf("%s", request);
        fflush(stdout);
        Media_spec = response_spec(request, comsocket);
        // printf("\n\nMedia_spec %d\n\n", Media_spec);
        printf("pokracuji tady");
        ssize_t bytes_now = 0, bytes_sent = 0;
        switch (Media_spec)
        {
            case HTML:
                printf("\nHTML request detected\n");
                int log_fd = open("/home/marek/Documents/FTP_SERVER/log.txt", O_RDWR | O_CREAT, S_IRWXU);

                struct response *html_tosend = prepare_html_response(comsocket, request);
             
                while( bytes_sent != html_tosend->content_length && html_tosend->content_length != 0) { 
                // bytes_now = send(comsocket, (html_tosend->content) + bytes_sent, (html_tosend->content_length) - bytes_sent, 0);
                bytes_now = SSL_write(ssl_connection, html_tosend->content, html_tosend->content_length);

                if (bytes_now == -1) {
                    printf("\ntady jsem u bytes_now == -1");
                    perror("send() selhal - http");
                    close(comsocket);
                    SSL_shutdown(ssl_connection); // aby server alert close_notify => pro efektivni ukonceni SSL/TLS (fungovalo by to i bez toho)
                    exit(EXIT_FAILURE);
                }
                // SSL_free
                bytes_sent += bytes_now;
                }
               
                fflush(stdout);
                printf("asi tady je chyba?");
                fflush(stdout);
                free(html_tosend);
                break;
            case CSS:
                printf("\nCSS request detected\n");
                int log_fd2 = open("/home/marek/Documents/FTP_SERVER/log.txt", O_RDWR | O_CREAT, S_IRWXU);
                struct response *css_tosend = prepare_css_response(comsocket);

                while( bytes_sent != css_tosend->content_length && css_tosend->content_length != 0)  {
                    // bytes_now = send(comsocket, (css_tosend->content) + bytes_sent, (css_tosend->content_length) - bytes_sent, 0);
                    bytes_now = SSL_write(ssl_connection, css_tosend->content, css_tosend->content_length);

                    if (bytes_now == -1) {
                        perror("send() selhal");
                        close(comsocket);
                        exit(EXIT_FAILURE);
                    }

                    bytes_sent += bytes_now;
                 
                    printf("\ninfinite while loop v handling_response() - case 1");
                }
                free(css_tosend);
                break;
            case FAVICON:
                printf("\nFAVICON request detected\n");
                struct response *favicon_tosend = prepare_favicon_response(comsocket);

                while ( bytes_sent < favicon_tosend->content_length && favicon_tosend->content != 0) {
                    // bytes_now = send(comsocket, favicon_tosend->content + bytes_sent, favicon_tosend->content_length - bytes_sent, 0);
                    bytes_now = SSL_write(ssl_connection, favicon_tosend->content, favicon_tosend->content_length);

                    if (bytes_now == -1) {
                        perror("send() selhalo");
                        close(comsocket);
                        exit(EXIT_FAILURE);
                    }

                    bytes_sent += bytes_now;
                    // printf("infinite while loop v handling_response() - case 2");
                }
                free(favicon_tosend);
                // printf("\nposlano");
                break;
            case TXT:
                printf("\n\n\n\nPOSILA SE SOUBOR\n\n\n\n");
                printf("\n\n \x1b[34m GET - response_spec  \x1b[0m \n");
                fflush(stdout);
               
                char *path = extraction_path_files(request, comsocket);
                printf("\n\n\n\nPATH: %s", path);
                send_file(path, comsocket, connection);
                printf("\n\nhand res TXT\n");
                break;
        }
    }
}
// AVE CHRISTUS REX!