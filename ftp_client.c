// AVE CHRISTUS REX!
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h> // operation on files
#include <netinet/in.h> // network internet => getaddrinfo, addrinfo, konstanty pro protokoly apod
#include <arpa/inet.h> // arpa internet, internet => prace s IP adresami, prevody apod.
#include <netdb.h> // prace s DNS preklady apod. => gethostbyname, addrinfo, getaddrinfo
#include <sys/socket.h> // nejzakladnejsi funkce k socket API
#include <unistd.h> // getuid, sleep
#include <pwd.h> // password structure => v ni je home directory, getpwuid
#include <dirent.h> // pro cteni slozek
#include <sys/stat.h> // stat, lstat, fstat
#include <pthread.h>
#include <time.h> // clock() - vraci tics od zacatku programu
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <event2/event.h>
#include <event2/util.h> // EVUTIL_SOCKET_ERROR()
#include <event2/buffer.h> // evbuffer_get_length()...
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <mqueue.h>
#include <errno.h>
#include <signal.h>
#include <netinet/tcp.h> // TCP_NODELAY
#include <sys/types.h>
#include <sys/wait.h>

#define BACKLOG 5
#define CONTROL_PORT 2100
#define DATA_PORT 2000
#define MAX_LEN 256
#define STDIN 0
#define NFDS 4 // number of file descriptors
#define CONTROL_QUEUE_NAME "/control_queue_client"
#define DATA_QUEUE_NAME "/data_queue_client"
int num = 1;
int QUEUE_MESSAGE_LEN;
int BUFEVENT_DATA_LEN = 512;

struct mq_attr global_mq_setting;

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
    printf("QUEUE_MESSAGE_LEN: %ld", bytes);

    global_mq_setting.mq_flags = 0;
    global_mq_setting.mq_maxmsg = 4;
    global_mq_setting.mq_msgsize = bytes;
    global_mq_setting.mq_curmsgs = 0;

    QUEUE_MESSAGE_LEN = bytes;

    free(buf);
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

typedef struct Ftp_Dtp_Data {
    char *path;
    char *owner;
    char *type;
    size_t file_length;
} ftp_dtp_data;
ftp_dtp_data obj;

// AF_INET = Address Family Internet
// sin = socket internet

// inet_pton => prevadi text na bitovou verzi
// htons => meni poradi bitu na network format (big endian)

// big endian = MSB na nejnizsi memory adrese
// little endian = MSB na nejvyssi memory adrese

// IPv4 = 32 bits => 4 Bytes
// port = 16 bits => 2 Bytes

// IPv6 = 128 bits => 16 Bytes
// port = 16 bits => 2 Bytes

// IPv4 => 4 oktety = 4 * 8 bits
// IPv6 => 8 bloku po 16 bits, oddelene dvojteckou

/*
struct sockaddr {
    unsigned short    sa_family;    // address family, AF_xxx
    char              sa_data[14];  // 14 bytes of protocol address
};

i kdyz tato struktura pouziva char, ktery ma range -127->128, 7 bits se pouzivaji na data, 8. je na znamenko
proc se nepouziva unsigned char, ktery ma range 0-255?
protoze je to kvuli kompatibilite a historii, Byte s rangi -127->128 se pouziva jako "raw Byte", coz znamena ze se nehledi na znamenko a pouzije se samotna hodnota
*/

// ja si bud muzu naplnit samotne struktury sam, nebo si udelam strukturu addrinfo, tam si specifikuji ty parametry, podle kterych chci aby se mi vyplnil
// ten linked list tich adres a portu apod.

// communication domain = komunikacni domena => rodina protokolu

// Linus Torvalds udelal kernel a nemel pristroje jako kompilator apod
// GNU projekt Richard Stallman udelali nastroje, ale nemeli moc funkcni kernel
// => GNU/Linux = Torvalds => linux ma kernel system calls, Stallman ma glibc, kompilator, nastroj apod. knihovnu pro user-space => normalni funkce pro C


/*
Rule of Thumb: standard library functions handling strings will always append the null character. The only exception is strncpy. – 
Paul Ogilvie
Commented Mar 28, 2019 at 7:40

https://stackoverflow.com/questions/69204707/why-cant-i-use-n-scanset
*/

// pokud chceme zjistit, kolik casu ubehlo od nejake akce v C, tak musime implementovat funkci clock(), ktera vraci umelou jednotku tics a pokud udelame interval mezi dvema eventy zmerime tyto jednotky a potom je vydelime konstantou, ktera nam urcuje pocet techto umelych jednotek za sekundu, tak zjistime celkovy pocet sekund

struct Node_Linked_List {
    char *path;
    char **dir_names;
    // int *yes_no_states; // nemusi to byt, protoze files se poslou hned
    int no_states; // ve skutecnosti to nebude "prava staticka" promenna, protoze se alokuje pomoci malloc(), takze bude ulozena na heap
    struct Node_Linked_List *next_node;
    struct Node_Linked_List *previous_node;
};
struct Node_Linked_List *root_node;
char *root_node_path;

struct Ftp_Sockets {
    int ftp_control_socket;
    int ftp_control_com; // client ma jenom jeden socket na komunikacis
    int ftp_data_socket;
    int ftp_data_com;
    // int ftp_data_socket_or_com; // zalezi jestli ftp_data_socket se bude povazovat za ftp_data_com podle aktivni/pasivni mode
};

// struct Account_Information {
//     char *username;
//     char *password;
// };
// struct Account_Information account_information;

// enum Ftp_Code_Login {
//     FAILED_SECURITY = 535,
//     INVALID_USERNAME_PASSWORD = 430,
//     USER_LOGGEDIN = 230,
// };
// enum Ftp_Code_Login ftp_code_login;

// enum Ftp_Commands {
//     USER, // 0
//     PASS,
//     QUIT,
//     PORT,
//     PASV,
//     RETR,
//     STOR,
//     NOOP,
//     TYPE, // 8
//     CHDD
// };
// enum Ftp_Commands ftp_commands;

enum Ftp_Data_Representation {
    ASCII = 0,
    IMAGE = 1,
};

// pokud nejaky objekt je staticky a chci ho nainicializovat, tak musi mit staticke promenne, jinak muze mit pointery na NULL s tim, ze se to potom nainicializuje, ale je to staticke
struct Ftp_User_Info {
    char *username;
    char *password;
    char *filename_to_save;
    char *last_path;
    char *curr_dir;
    char *dd; // default directory
    char *user_request;

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
};

struct Ftp_User_Info ftp_user_info = {
    .username = NULL,
    .password = NULL,
    .filename_to_save = NULL,
    .last_path = NULL,
    .curr_dir = "/tmp/ftp_server", // MUSI BYT NASTAVENO NA NULL A AZ POTOM SE NASTAVIT, PROTOZE TOTO JE STRING LITERAL A POKUD BYCH HO CHTEL UDELAT FREE, TAK TO VYHODI SIGSEV, PROTOZE TO NENI MALLOCOVANA MEMORY ZUSTANE V MEMORY DO KONCE PROCESU! TAKZE STRING LITERAL JE V READ-ONLY CASTI, TO JDE VIDET V ASAN A NIKDY NEMUZE BYT JAKO MEMORY LEAK I KDYZ TEN POINTER POTOM TREBA POINTUJE JINAM, TAK SE TO JAKOBY ZTRATI TA PUVODNI REFERENCE, ALE NENI TO MEMORY LEAK, PROTOZE TO JE STRING LITERAL
    .dd = NULL,
    .user_request = NULL,

    .ftp_sockets_obj = {
        .ftp_control_socket = -1,
        .ftp_control_com = -1,
        .ftp_data_socket = -1,
        .ftp_data_com = -1,
    },

    .control_queue = -1,
    .data_queue = -1,

    .evbase_data = NULL,
    .evbase_control = NULL,
    .bufevent_data = NULL,
    .bufevent_control = NULL,

    .event_timeout_control = NULL,
    .event_timeout_data = NULL,

    .server_control_info = {0},
    .server_data_info = {0},

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
};

// struct linger so_linger = {.l_onoff = 1, .l_linger = 3}; // pocka se na poslani vsech dat, 3 sekundy





char **make_path_lk(char **dir_names, int dir_count, char *path) {
    // protoze v tom linked list bude pointer na pointer jenom slov (tich slozek), potom tahle path, my ty paths spojime na cele path, abychom vedeli, kam potom zase jit

    char **full_paths = (char **)calloc(dir_count, sizeof(char *));

    // cd ~/Desktop/ a cd ~/Desktop je uplne to stejne, neni tam zadny rozdil
    for (int i = 0; i < dir_count; i++) {
        char temp_path[256] = {0};
        snprintf(temp_path, 255, "%s/%s", path, dir_names[i]); // ta velikost muze byt klidne hodne mnohem vetsi nez opravdu to, co se tam zapise, je to jenom maximalni delka Bytes, 1 Byte pro \0, \0 se pridava automaticky

        full_paths[i] = (char *)malloc(strlen(temp_path));
        strcpy(full_paths[i], temp_path);
    }

}

char *change_path_curr_prev(char *path) {
    // /home/marek/.. => /home

    // /home/marek/..
    //             .

    printf("\nTED TADY HALO, AVE CHRISTUS REX");


    char *prev_p = strstr(path, "..");
    int prev_i = (int)(prev_p - path);
    int path_len = prev_i + 2;

    int raw_prev_i = prev_i - 1; // bez /

    char *action_buf = (char *)malloc(path_len); // .\0
    memset(action_buf, 0, prev_i);
    snprintf(action_buf, prev_i, "%s", path); // ted je v action bufferu path
    memset(action_buf + prev_i, 0, 2); // nahrazuji se ty dve tecky

    int reverse_i = 0;
    for (int i = prev_i + 1; i >= 0; i--) { // prev_i + 1, protoze ta prvni tecka je ten index, ktery ziskame, 0 je samotny zacatek toho stringu
        action_buf[reverse_i] = path[i];
        reverse_i++;
        // printf("\n\n char action buf %c, char path %c\n\n", path[i]);
        // fflush(stdout);
    }
    // nemusim ukoncovat ten buffer, protoze 0 Bytes = NULL terminator
    // printf("\npred tim nez se to vrati: %s\n", action_buf); // prevraceny string

    // ../potkesD/keram/emoh
    //   .       .
    // o tento rozdil mene alokuji ten buffer, aby to bylo efektivni

    char *first_slash_reverse = strstr(action_buf, "/"); // tak bychom meli najit ten druhy slash v te ceste
    int first_slash_reverse_i = (int)(first_slash_reverse - action_buf);

    char *second_slash_reverse = strstr(action_buf + strlen("../"), "/");
    int second_slash_reverse_i = (int)(second_slash_reverse - action_buf);

    int difference = second_slash_reverse_i - first_slash_reverse_i;

    char *final_buffer = (char *)malloc(path_len - difference + 1); // + 1 pro \0
    memset(final_buffer, 0, path_len - difference + 1);

    int final_buffer_i = 0;
    for (int i = prev_i + 1; i >= second_slash_reverse_i; i--) {
        final_buffer[final_buffer_i] = action_buf[i];
        final_buffer_i++;
    }
    // nemusim to ukoncovat pomoci \0, protoze 0 Byte = NULL terminator

    printf("\n\nfinal_buffer: %s\n\n", final_buffer);
    
    
    return final_buffer;
}

void free_all() {
    // info signal, signal SIGINT posle SIGINT procesu
    printf("\n\n\n\n\n\nTED SE SPUSTIL FREE_ALL()\n");
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
    if ( ftp_user_info.user_request != NULL) {
        free(ftp_user_info.user_request);
    }
    if ( ftp_user_info.curr_dir != NULL) {
        free(ftp_user_info.curr_dir);
    }
    
    // sk_SSL_COMP_free(SSL_COMP_get_compression_methods());

    // CRYPTO_cleanup_all_ex_data();
    // EVP_cleanup();
    // CONF_modules_unload(1);
    // ERR_free_strings();
    // EVP_PBE_cleanup();
    // CONF_modules_free();

    // // EVP_CIPHER_CTX_free();

    // OPENSSL_cleanup();
    // OPENSSL_thread_stop();
    // // ERR_remove_thread_state();
    _exit(EXIT_FAILURE);
    exit(EXIT_FAILURE);
    _Exit(EXIT_FAILURE);
}

void save_file(char *path, char *data, size_t bytes_len) {
    // O => open() flags
    // S => file mode bits
    // F => fcntl() prikazy

    // pokud to nebude k otevreni, tak by to melo file permissions 4777 // umask nemuze NIJAK ovlivnit setuid bit
    // open(path, O_CREAT | O_APPEND | O_RDONLY, S_IRWXU | S_IRWXG, S_IRWXO, S_ISUID); // 4777 => spusteni s pravy vlastnika, vsichny read, write, execute

    // /media/sf_projects_on_vm/FTP_SERVER/file.txt
    printf("\n\n\n\n\n\nPATH TADY V SAVE FILE: %s\n", path);
    fflush(stdout);

    int fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0777); // kdyz tady neni specifikovano, v jakem modu se to bude cist, tak to vyhodi chybu bad file descriptor
    if (fd == -1) {
        perror("open() selhal - save_file()");
        exit(EXIT_FAILURE);
    }

    size_t  bytes_total = 0;
    ssize_t bytes_now;

    for (; ;) { 
        bytes_now = write(fd, data + bytes_total, bytes_len - bytes_total);

        if ( bytes_now == -1) {
            perror("write() selhal - save_file()");
            exit(EXIT_FAILURE);
        }
        else if (bytes_total < bytes_len) {
            bytes_total += bytes_now;
        }
        else if (bytes_total == bytes_len) {
            printf("\nvytvoren novy file");
            break;
        }
    }       
}

int no_states_check(struct Node_Linked_List *node) {
    // kdyz se vraci urcite veci, tak se davaji do registru, protoze, chceme zkontrolovat no_states, tak nam staci jenom pointer na tu memory oblast
    int no_states = node->no_states;

    return no_states;
}

char **delete_dir_names_i(char **dir_names, int no_states, int i_to_delete) {
    char **new_dir_names = malloc(sizeof(char *) * no_states);

    int index_new_dir_names = 0;
    // tato funkce musi byt zavolana PO zavolani (*old_node)->no_states--
    for (int index_loop = 0; index_loop < no_states + 1; index_loop++) {
        if (index_loop != i_to_delete) {
            new_dir_names[index_new_dir_names] = (char *)malloc(strlen(dir_names[index_loop]));
            strcpy(new_dir_names[index_new_dir_names++], dir_names[index_loop]);
        }
        else {
            continue;
        }
    }

    return new_dir_names;
}

void delete_node(struct Node_Linked_List **node_to_delete, int is_root_node, struct Node_Linked_List *node_change_info) {
    // pro pointer node_change_info se udela kopie (udela se nova memory adresa/ulozeni do registru) ta memory adresa, kam ten originalni pointer ukazuje, a pokud zmenime obsah memory pomoci ->, tak se ukaze globalne, ale pokud se to zmeni pomoci =, tak to probehne jenom lokalne
    // pokud bychom chteli zmenit CELY pointer na treba jinou strukturu, tak bychom museli z pointeru udelat pointer na pointer


    // az se narazi na 0 no_states, budeme se chtit vratit nazpatek a k tomu bude dobre dealokovat vsechny nodes, ktere uz maji data (files) odeslane, proto potrebujeme dealokovat vsechny membery te struct ale i pointer na tu struct samotny, proto **node_to_delete (protoze ted uz dodrzuji "konvenci", JINAK BY TO SLO I S POUHYM JEDNO LEVELOVYM POINTEREM)

    // protoze mame jak ten pointer v memory, do ktereho alokujeme velikost te struktury, tak se tak alokuji i ty "staticke promenne", ale protoze, potom mame nejake pointery, tak ty potrebuji svoje vlastni alokovani, proto se musi dealokovat osamostatne, jinak kdyz dealokujeme ten hlavni pointer na tu strukturu, tak ztratime ten pointer na strukturu, takze vznikne memory leak na ten dynamicky pointer, ale potom az dealokujeme tu memory pro ten hlavni pointer, tak se tak dealokuji i ty staticke promenne

    free((*node_to_delete)->path);
    free((*node_to_delete)->dir_names); // diky memory allocator staci jenom pointer na zacatek teto memory oblasti, memory allocator ma metadata o teto memory oblasti a vi presne, kolik Bytes tam je
    free((*node_to_delete)->previous_node);
    free((*node_to_delete)->next_node);
    free((*node_to_delete));

    if (!is_root_node) {
        node_change_info->next_node = NULL; // automaticka dereference
    }
}

struct Node_Linked_List *create_assign_next_node(struct Node_Linked_List **old_node) {
    // tato funkce vrati novy node (dalsi slozka)
    // chci se podivat na informace node, ktery dostaneme, na jeho path, dirnames, states a prvni, kde bude v states 1, tak nastavime node, ktery jsme dostali 1 a path noveho nodu nastavime na prave tuto path a chceme nastavit referenci (pointer) na node, ktery jsme dostali
    // toto by slo i s jenom POINTER *, ** je k tomu, abychom kdyztak mohli zmenit cely node
    // int **ptr = 2 papirove sacky cekajici na naplneni
    
    // POINTERS INFORMACE - PASS BY VALUE

    // C je tzv. pass by value, co toto znamena je to, ze kdyz funkci dame nejakou promennou, tak my dostaneme na svuj stack frame tu promenou (nebo v registrech, spise v registrech, prvnich 9 promennych jde do funkci pomoci registru), ma to svoji memory adresu (i v tom registru), ale dostali jsme kopii samotne promenne, nedostali jsme tu samotnou jednu promennou, udelala se nova se stejnou hodnotou, u pointeru je to stejne, ale U POINTERU POZOR, protoze pointery maji jinou SVOJI memory adresu (kde se v RAM) nachazeji, ale maji STEJNOU MEMORY ADRESU, KAM UKAZUJI, tak kdyz udelame dereferenci, tak se hodnoty zmeni VSUDE V RAM, jak ve funkci, kde jsme ten pointer dostali, tak i v te funkci, ze ktere jsme ten pointer predavali
    // ale protoze jsme dostali kopii toho pointeru, tak kdyz udelame ptr = , tak se zmeni memory adresa kam bude pointer ukazovat JEN LOKALNE, PROTOZE JSME DOSTALI POUZE KOPII!!
    
    
    // ptr = change the memory address of ptr
    // *ptr = get the value that is on memory address pointed to by ptr
    // &ptr = get the memory address of ptr where the ptr is located at

    // pointer na pointer si muzeme predstavit takto:
    // promenna s hodnotou je boxik s kulickou, pointer je papirovy pytlik a * dereference operator je posun z jednoho vnejsiho levelu o jeden level dovnitr
    // takze mame pytliku 1 boxik s kulickou (pointer na promennou - hodnotu), a toto cele je v papirovem pytliku 2 (pointer na pointer), pokud bychom chteli zmenit pytlik 1, tak bychom museli udelat *ptr = , pokud bychom chteli zmenit samotnou hodnotu v boxiku, tak bychom museli udelat **ptr = ,

    // pokud bychom meli jenom nejaky pointer, ktery by ukazoval na cista data tak bychom meli pytlik, vnemz by byla kulicka (samotna data), pointer na pointer => papirovy pytlik s kulickou v dalsim papirovem pytliku s kulickou

    // !POZOR kdybychom delali malloc(), tak se dela type cast na PRVNI POINTER V TOM memory chunk, proto se tam dela char * = (char *)malloc(), specifikuje se jaky typ bude ten PRVNI pointer na tuto memory adresu
    // jedna strana se musi rovnat druhe!
    // *ptr = *ptr, **ptr = **ptr, SAMOZREJME TAKY PODLE KONTEXTU (co se **ptr = **ptr tyce)


    // TAKE JE ROZDIL MEZI KOPIROVANI DAT DO POLE A DO PROMENNE
    // do promenne je to jednodussi, protoze nam to staci dereferencovat, ale do pole nejdrive musime alokovat memory chunk a az potom do nej neco kopirovat, protoze pokud mame pointer, ktery uz je naalokovany a predame ho funkci, tak nam staci jenom memcpy do tohoto pointeru a bude to fungovat, protoze ta kopie pointeru ukazuje na stejne misto jako ten originalni pointer

    // ale pokud budeme mit pointer, ktery je nealokovany a budeme ho chtit alokovat v samotne funkci, tak ta funkce MUSI dostat memory adresu tohoto pointeru => pointer na pointer, proc?
    // kdybychom meli pointer ve funkci => kopiie, vse naalokujeme apod. ALE, takhle naplnime ten "lokalni" pointer (kopii), to bychom ten pointer museli vracet, coz by treba mohl byt problem pokud ta funkce ma vracet neco jineho, kdybychom dostali memory adresu toho pointeru, tak muzeme na tu adresu alokovat a nasledne i memcpy bez potreby navratu nebo alokovani v jine funkci a zbytecne se starat o alokovani/pripravovani pointeru na jinych mistech v kodu

    // pokud bychom naalokovali ten lokalni pointer a potom ho treba nevratili, tak by vznikl memory leak, na danou memory adresu nikdo neukazuje (neni zadna reference)


    // nejdrive maji prednost operatory, ktere jsou urcene pro pristup do urcitych struktur, indexace, volani funkci
    // pote dereference, typecast, sizeof, address of
    // pote jsou matematicke operace, pokud si nejsme jisti temito operace, tak bychom meli pouzit zavorky, abychom to jiste odlisili od sebe

    // v C jmena statickych poli NEJSOU POINTERY:

    // v C si muzeme vytvorit pole bud staticky a nebo dynamicky s tim, ze staticke alokovani pameti je znamo uz pri kompilaci, zatimco dynamicke alokovani je znamo az pri run time
    // jmeno statickeho pole je konstantni symbolicka adresa (tento vyraz se pouziva se treba v Assembly -> konstantni "string pismen", ktery ma zamenitelny nazev za memory adresu) prvniho prvku (ALE POZOR JE TO KONSTANTNI SYMBOLICKA ADRESA => KONSTANTA), to znamena, ze nemuzeme nasmerovat, aby tato promenna smerovala nekam jinam, protoze je to konstanta => nemuzeme udelat pole = memoryaddress
    // u dynamickeho alokovani je prostor znam az pri run time, dostane klasickou promennou, ktera v sobe uchovava memory adresu prvniho prvku alokovaneho memory chunku, protoze to NENI KONSTANTA, tak muzeme zmenit, kam bude ukazovat tato nova memory adresa tohoto pointeru => pole = memoryaddress
    // proto nemuzeme udelat sizeof() pro pointer z dynamickeho pole, ale muzeme to udelat pro konstantu s memory adresou ze statickeho pole
    
    // Dobra vec je, ze lidi, kteri C vytvorili, tak aby neudelali zbytecne velky zmatek, tak nechali zpusob k pristupovani prvku STEJNE u obou prvku
    // u obou pripadech muze dojit k segmentation fault nebo k nedefinovanemu chovani programu a mozny buffer overflow

    // u statickeho pole existuje jeste existuje tzv. array decay, coz znamena ze symblicky link pole premenime na pointer, je to pro to, abychom treba mohli pouzivat staticke pole z main do jine funkce, int *static_array_ptr = static_array, ted je do *static_array_ptr ulozen prvni prvek statickeho pole (z celeho pole - memory oblasti se stane pouze pointer na prvni prvek => &staticke_pole[0] - decay), posouvani se muze bud delat pomoci *(static_array_ptr + 1), nebo pomovi static_array_ptr[i] i++, s tim ze my posuneme tu adresu o jeden prvek (pointer arythmetic) a potom ten samotny pointer dereferencujeme, nemuzeme ale udelat
    // (&static_array_ptr + 1) nebo *(&static_array_ptr + 1), to bychom posunuli cele pole o delku celeho pole + 1, toto plati i pro dynamicke pointery

    // u statickeho pole je pole[i] int (pokud je pole typu int)
    // u dynamickeho pole je pole[i] int (pokud je pole typu int), protoze int * (pointer na int je jen prvni prvek)

    // kdyz dostaneme int *, tak ono je nejake pole memory a my dostaneme pointer na ten prvni prvek, takze my vubec nedostaneme ten prvek ale jenom pointer a tim k tim ostatnim prvkum pristupujeme a potom u statickeho pole je to jmeno symbolicky link, takze to jmeno je zamenitelne s memory adresou, takze taky jakoby nedostaneme prvek jenom celou oblast a C ma nejaky interni mechanismus jak indexovat ty prvky toho pole pomoci pole[i]? ze ano?

    // ten "mechanismus" je implicitni array decay

    char *path;
    num = 1;
    int arr_i = 0;
    struct Node_Linked_List *new_node;
    new_node = (struct Node_Linked_List *)malloc(sizeof(struct Node_Linked_List));

    // printf("\n\ncreate_assign old_node: %p", (void *)old_node);
    // printf("\ncreate_assign *old_node: %p", (void *)*old_node);
    // printf("\ncreate_assign &old_node: %p", (void *)&old_node);
    

    // printf("value on the memory address pointed to by old_node: \n", **old_node); // 2 papirove pytlikove sacky
   
    /*
    // tato podminka je zbytecna, protoze kdybychom meli v root jenom soubory, tak by se uz poslali, pokud ne, tak mame vice nez nebo jednu no_states a pokud bychom sli o jeden level nize, tak pokud by ta slozka mela jenom soubory, tak mame path z tamte pred ni, protoze TA SLOZKA PRED NI MELA no_states vice nebo rovno no_states nez 1! protoze je to zbytecne
    */
    // toto bylo pred tim nez jsem zjistil, ze pokud odesleme vsechny soubory, tak se vratime na 0. index do dir_names v old_node, to ale bude fungovat pokud je tam vice nez dve podslozky, pokud nejsou, tak jsme prave tady
    // ne, toto nahore neni pravda, pokud mame nejakou slozku X levelu dopredu, kde uz nejsou zadne slozky, tak se musime podivat, jestli pred tim byly min 2 slozky, dve protoze jedna slozka se odecte, protoze jsme ji uz precetli, pokud je tam dalsi slozka, tak path bude ona sama, pokud to tak neni, tak new_node, MUSI BYT old_node, kde tedy NENI dalsi slozka, pokud no_states == 0, to znamena, ze files uz byly odeslany A MUSIME POKRACOVAT V BACKTRACKINGU, ale protoze se v tom kodu pri posilani uz nacitani no_states, to znamena, ze 0 no states je DEFAULTNI, tak si musime udelat novou promennou, kterou VZDY BUDEME KONTROLOVAT, anychom vedeli, jestli mame vubec posilat soubory nebo ne

    if ( (*old_node)->no_states >= 1) {
        for (int i = 0; i < (*old_node)->no_states; i++) { // musim o jeden pytlik dovnitr a mam pointer na strukturu, pokud bych chtel strukturu => (**old_node).no_states (protoze chci z pointeru NA STRUKTURU STRUKTURU => **)
            char *partial_path = (char *)malloc(strlen((*old_node)->dir_names[i]) + 1); // uz je s \0, takze uz nemusim s + 1
            // memcpy((void *)partial_path, (void *)(*old_node)->dir_names[i], strlen( (**old_node).dir_names[i]));
            strcpy(partial_path, (*old_node)->dir_names[i]);
            // ted tam mame jmeno te slozky

            size_t len = strlen( (*old_node)->path) + strlen(partial_path) + 1 + 1; // pro / // pro \0 zapise se n-1 char ve snprintf, vraci se pocet Bytes, ktere By se zapsalo, kdyby n bylo dostatecne velike, takze n muze byt malinke a return value muze byt mnohem vetsi
            path = (char *)malloc(strlen((*old_node)->path) + strlen(partial_path) + 1 + 1); // +1 pro / // nemusim resit \0, snprintf odstrani prvni \0, prida hned za nim dalsi string a na konec da \0 (necha ten druhy \0), ALE MUSIM SI PRO NEJ VYPOCITAT DOSTATECNE VELKE MISTO
            snprintf(path, len, "%s/%s", (*old_node)->path, partial_path); // path noveho node // +1 pro \0 (including the terminating null bytes)
            
            // printf("\n\nTO, CO SE VYMAZE: %s, %d, path: %s", (*old_node)->dir_names[i], (*old_node)->no_states, path);
            (*old_node)->no_states--;

            (*old_node)->dir_names = delete_dir_names_i((*old_node)->dir_names, (*old_node)->no_states, i);
            // printf("\n%d, %s, %s, %s\n\n", (*old_node)->no_states, path, (*old_node)->path, partial_path);
            fflush(stdout);
            // memset((*old_node)->dir_names[i], 0, strlen((*old_node)->dir_names[i])); // jakoby "free()"

            break; // tento loop staci pustit jenom jednou a mame vysledky
        }
    }
    else {
        // kdyz bude slozka, kde jsou soubory a jedna dalsi slozka, tak se koukne na tu slozku, ten stary node, s touhle slozkou bude mit v dir_names tuto slozku, udela se novy node, kde bude path prave tato slozka, u stareho node se udela -- u no_states, pokud v teto slozce bude dalsi slozka, tak se bude pokracovat, ale pokud ne, tak se musi jit na backtracking, to se musi vratit new_node jako old_node, potom se udela novy node, zkoukne se tato podminka a pokud bude else (budeme tady), tak vime, ze uz se ty soubory poslali a MUSIME vratit previous_node jako new_node
        // root_node
        if ((*old_node)->previous_node == NULL) {
            // jestli root_node ma 0 no_states, tak uz je konec a dostali jsme se uplne na vrchol
            printf("\nbyly poslany vsechny slozky\n");
            delete_node(old_node, 1, NULL);
            exit(EXIT_SUCCESS);
        }
        else {
            return (*old_node)->previous_node;
        }
    }
    

    // printf("\n\npath: %s\n\n", path);
    // NULL pointer je hodnota 0, na kterou je pointer, je to cislo 0, ale je to interpretovano jako pointer na ADRESU 0
    // zatimco \0 je ASCII hodnota 0x0 => 0, tak je to interpretovano jako normalni datovy typ int 0, NE jako adresa

    // ted si chci vzit vsechny mozne informace o root_node (te slozky, kterou jsme dostali), tyto informace nam budou uzitecne k tomu, abychom vedeli, do jake slozky mame vniknou, co tam poslat a zase nejaky zpusob nazpatek
    printf("\n\npath: %s", path);
    fflush(stdout);
    DIR *node_dir = opendir(path);

    if (node_dir == NULL) {
        perror("\nopendir() selhal");
        fflush(stdout);
    }
    struct dirent *node_entry;

    int number_of_elements = 1;
    new_node->dir_names = (char**)malloc(sizeof(char *) * num);
    for (; (node_entry = readdir(node_dir)) != NULL;) { // muzu nadeklarovat vice promennych stejneho typu ve for loopu, ale nemuzu odlisne datove typy, jedine pomoci lokalni struct

        if (node_entry->d_type == DT_REG) {
            // send_file();
            printf("\nfile %s sent", node_entry->d_name);
        }
        else if (node_entry->d_type == DT_DIR && strcmp(node_entry->d_name, ".") != 0 && strcmp(node_entry->d_name, "..") != 0) {
            size_t len_dirname = strlen(node_entry->d_name);
            new_node->dir_names[arr_i] = (char *)malloc(len_dirname + 1); // bez + 1 heap overflow
            // memcpy((void *)new_node->dir_names[i], (void *)node_entry->d_name, len_dirname);
            strcpy(new_node->dir_names[arr_i++], node_entry->d_name);
            // printf("\nTO, CO ZUSTANE: %s", node_entry->d_name);
            char **new_temp_dir_names = (char **)realloc(new_node->dir_names, sizeof(char *) * ++num); // C standard nic o tomto nerika, ale GNU libc kompilator rika, ze vrati stejnou memory adresu toho pointeru, ktery predame
            new_node->dir_names = new_temp_dir_names;
            new_node->no_states++;
            // protoze realloc potrebuje nejaky ukazatel na memory adresu a pozaduje void *, tak to muze mit formu int *, int **, int ***, jakykoliv datovy typ a proc tam neni *new_node->dir, protoze realloc() chce pointer na memory chunk a tento memory chunk muze byt jakehokoliv typu, realloc potrebuje jenom pointer na uplny zacatek tohoto pole, najde novy memory chunk, stary memory chunk dealokuje a zkopiruje puvodni data do noveho chunku, jak se ale dovime, kolik Bytes v tom chunku bylo na kopirovani, system ma tzv. memory allocator, software ktrery drzi metadata prave o tichto informacich o techto memory chunks
        }
    }

    // kdybychom pouzili memcpy, tak by se stalo nasledovne:
    // memcpy((void*)new_node->path, (void *)path, strlen(path));
    // zkopiruje a pastne se presne tolik Bytes, kolik ma JENOM ten string path BEZ \0, takze se vrati pocet o JEDNA mensi nez ma byt (bez \0), takze potom az bychom neco chteli vyprintovat pomoci printf, tak printf %s cte do te doby NEZ NENARAZI NA \0, a protoze bychom nezkopirovali presny pocet Bytes, tak bychom dostali garbage values
    // strcpy kopiruje I S \0, tam se zastavuje
    new_node->path = (char*)malloc(strlen(path) + 1); // jinak buffer overflow!!
    strcpy((void*)new_node->path, (void *)path);
    // printf("\nnew_node->path %s, strlen new_node->path: %d", new_node->path, strlen(new_node->path)); // 36 -> 42
    fflush(stdout);

    // new_node->no_states = (*new_node).no_states

    // kdyz mame pointer na struct Node_Linked_List *, tak bud muzeme udelat manualni prirazeni jako ptr->ptr = memory_address, nebo pomoci kopirovani memory adresy do toho pointer, kdyz se udela ptr->ptr=memory_address, tak se udela uplne to stejne, TAKE SE ZKOPIRUJE ta memory adresa, pokud se udela free() jednoho z tich dvou pointeru, tak ten druhy ztrati pristup k te memory adrese a pokud se pokusime udelat dalsi free(), tak to vypise error

    // toto by udelalo memory leak, protoze uz je naalokovano 8 Bytes pro pointer a ja bych prepsal tu memory adresu na jinou, protoze se nam vrati x Bytes na jine memory adrese ma heapu, neni jak ziskat puvodnich 8 Bytes => memory leak
    // new_node->previous_node = malloc(sizeof(struct Node_Linked_List )); // alokuje se nove pole, proto nebude mit stejnou memory adresu jako root_node
    // new_node->previous_node (hodnota pointeru), &new_node->previous_node (CILOVA ADRESA POINTERU PREVIOUS_NODE) a chceme tam ulozit memory adresu pointeru na struct, protoze (*old_node)
    // protoze (*old_node) je pointer na zacatek struktury, tak by se zkopirovalo size(struct Node_Linked_List *) dat ze struct, ale my chceme zkopirovat memory adresu toho pointeru, abychom vedeli
    // protoze memcpy ocekeva pointer na OBJEKT, ze ktereho bude brat data, tak kdyby byl tam dan pointer jenom na struct, tak by si memcpy myslelo, ze to je pointer na struct, takze by se vzalo sizeof(struct Node_Linked_List *) ze struct
    memcpy((void *)&new_node->previous_node, (void *)(old_node), sizeof(struct Node_Linked_List *));
    // alternativa: new_node->previous_node = (*old_node);
    // new_node->previous_node = (*old_node);
    // (*old_node)->next_node = malloc(sizeof(struct Node_Linked_List )); // vzdy do zavorek, protoze -> ma vyssi prioritu nez *, takze se nejdrive vezme next_node a az potom ten dereference
    // &(*old_node)->next_node protoze old_node je pointer na pointer na struct, ale my potrebujeme memory adresu samotneho clena
    memcpy((void *)&(*old_node)->next_node, (void *)&new_node, sizeof(struct Node_Linked_List *));
    // alternativa: (*old_node)->next_node = new_node;
    // (*old_node)->next_node = new_node;


    

    if ( no_states_check(new_node) == 0) { // uz tam neni zadna slozka
        // nejdrive se koukneme, jestli je v node nejaka slozka, pokud ne, tak to znamena, ze muze zacit proces backtracking, na tuto podminku se ptame az na konci teto funkce, protoze budeme chtit free() cely node, aby nas to nejak netrapilo/nezmatlo a kdybychom chteli udelat free() toho node, kdyz jsou pointery uninitialized, tak by to bylo undefined behaviour (UB), zatimco JDE BEZ PROBLEMU free() NULL pointer, proto se ta no ptame az na konci
        // (*old_node)->next_node = NULL; // toto tady nemusi byt, protoze to delame v delete_node()
        fprintf(stdin, "\nvse probehlo OK, ftp_client poslal vse soubory v jednom node (jedne slozce/adresari)\n");
        delete_node(&new_node, 0, (*old_node));
        return (*old_node);
        // delete_node(&new_node, (*old_node));

        // protoze jsme si udelali funkci, ktera nam realokuje to pole aby bylo vzdycky plne hodnot, ktere urcite jeste nebyly poslany, tak muzeme udelat "novy node", kde jenom zmenime path na novou slozku/adresar, ktera jeste nebyla poslana a vratime TEN STARY NODE, toto bude fungovat jen pokud mame 2 a vice dalsich podslozek
    }
   
    // (*old_node)->previous_node = NULL; // pointer ukazujici na hodnotu 0, tento pointer ma hodnotu 0 a je to nastaveno tak, ze jakakoliv spatna manipulace tohoto pointeru vytvori segmentation fault => NULL (void *)0, nekdo rika, ze to je jako memory adresa 0, protoze memory adresa 0x0, protoze nejde dereferencovat (nejde se k ni dostat) a nekdo to vysvetluje jako prosta hodnota 0, pravda je, ze to je opravdu jen prosta hodnota 0 a ptr = 0 je stejne jako ptr = NULL, ale ten mechanismus je uplne stejny tomu s tou memory adresou

    // printf("\n\nold_node->next_node: %p", (void *)((*old_node)->next_node));
    // printf("\nnext_node: %p", (void *)new_node);

    // printf("\n\nnew_node->previous_node: %p", (void *)(new_node->previous_node));
    // printf("\nprevious_node: %p", (void *)(*old_node));
    printf("\nnew_node->path %s", new_node->path);
    fflush(stdout);
    closedir(node_dir);
    return new_node; // new_node
}

// u pouhych char *, jednotlivych pismen se nemusi davat \0 (NULL terminator), protoze to neni C-string
// kdyz je neinicializovana promenna v C, tak C pro to nema zadne pravidla, ale kompilatory si udelaji sve vlastni prave pro tyto promenne (nastavi jim nejake hodnoty - zalezi to na kompilatoru)

// .a je staticka knihovna - musi se linknout pri kompilaci
// .so je dynamicka knihovna / linkuje se dynamicky

void fill_root_node(struct Node_Linked_List **root_node, char *path) {
    num = 1;
    int arr_i = 0;

    DIR *root_dir_stream = opendir(path);
    struct dirent *rds_entry;

    // protoze v te struct mam i staticke promenne, tak musim alokovat celou tu strukturu a potom jednotlive ty pointery
    (*root_node) = (struct Node_Linked_List *)malloc(sizeof(struct Node_Linked_List));
    memset((void *)(*root_node), 0, sizeof(struct Node_Linked_List));
    // memset((void *)(*root_node), 0, sizeof(struct Node_Linked_List *)); // vynulovani, protoze next_node asi neudelame automaticky

    (*root_node)->path = (char *)malloc(strlen(path) + 1); // STRLEN VRACI VELIKOST BEZ \0!!!!
    strcpy((void *)(*root_node)->path, (void *)path);
    // memcpy((void *)(*root_node)->path, (void *)path, strlen(path));

    (*root_node)->no_states = 0;

    (*root_node)->dir_names = (char **)calloc(sizeof(char *) * num, sizeof(char *));

    for (int i = 0; (rds_entry = readdir(root_dir_stream)) != NULL ; i++) {
        
        // printf("%s\n", rds_entry->d_name);
        if (rds_entry->d_type == DT_REG) {
            printf("\nfile %s sent", rds_entry->d_name);
        }
        else if (rds_entry->d_type == DT_DIR && strcmp(rds_entry->d_name, ".") != 0 && strcmp(rds_entry->d_name, "..") != 0) {
            // printf("\nentry: %s", rds_entry->d_name);
            size_t len_dirname = strlen(rds_entry->d_name) + 1; // jinak buffer overflow!!!
            // to ze si naalokujeme pointer, ktery ma 8 Bytes, tak to neznamena, ze muzeme udelat p[0], protoze ten pointer jeste NIKAM neukazuje, a proto to vyhodi segmentation fault, je to jenom 8 Bytes pointeru, ktery ZATIM NIKAM NEUKAZUJE! proto se nejdrive musi naalokovat
            (*root_node)->dir_names[arr_i] = (char *)malloc(len_dirname); // vraci pointer na void *, proto to na leve strane muze byt COKOLIV => int **, int ***, char ****, char *
            strcpy((*root_node)->dir_names[arr_i++], rds_entry->d_name); // i s \0
            printf("\n\n root_entry_d_name: %s", rds_entry->d_name);
            // memcpy((void *)(*root_node)->dir_names[num-1], (void *)rds_entry->d_name, len_dirname); // realloc() premeni velikost toho bufferu a necha tam ty stejne data, toto zkopiruje jen pouha data bez \0!
            // printf("\n\n root: %s\n", rds_entry->d_name);
            // fflush(stdout);

            char **temp_dir_names = (char **)realloc((*root_node)->dir_names, sizeof(char *) * ++num); // bez tohoto if statementu by se zbytecne alokovalo o jeden char * navic
            (*root_node)->dir_names = temp_dir_names;

            (*root_node)->no_states++;
        }
    }

    if (no_states_check( (*root_node)) == 0) {
        fprintf(stdin, "\nvse probehlo OK, ftp_client poslal vse soubory\n");
        exit(EXIT_SUCCESS);
    }

    // printf("%d %d", arr_i, num);
    (*root_node)->previous_node = NULL;
    closedir(root_dir_stream);
}

int partial_login_lookup(char *text, int username_password) {
    // 0 - username
    // 1 - password
    // printf("\n0 - username, 1 - password => %d, %s\n", username_password, text);

    FILE *fs = fopen("./TXT/accounts.txt", "r+");

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
        char *line_separator = strstr(line, " ");
        if (line_separator == NULL) {
            perror("strstr() selhal - partial_login_lookup");
            exit(EXIT_FAILURE);
        }
        int len_line = strlen(line) - 1; // strlen(line) je i s \n a bez \0

        int line_separator_i = (int)(line_separator - line);        
        memcpy(account_info[0], line, line_separator_i); // username
        memcpy(account_info[1], line + line_separator_i + 1, len_line - (line_separator_i + 1)); // password

        // printf("username_password: %d, account_info[0] = %s, account_info[1] = %s", username_password, account_info[0], account_info[1]);
        switch(username_password) {
            case 0: 
                if (strcmp(account_info[0], text) == 0) {
                    // printf("\n\nusername\n\n");
                    ftp_user_info.username = strdup(text);
                    free(account_info[0]);
                    free(account_info[1]);
                    free(account_info);
                    free(line);
                    return 0;
                }
                break;
            case 1:
                if (strcmp(account_info[1], text) == 0) {
                    // printf("\n\npassword\n\n");
                    ftp_user_info.password = strdup(text);
                    free(account_info[0]);
                    free(account_info[1]);
                    free(account_info);
                    free(line);
                    return 0;
                }
                break;
            default:
                free(account_info[0]);
                free(account_info[1]);
                free(account_info);
                free(line);
                fprintf(stderr, "username_password faulty - partial_login_lookup");
                return 1;
        }

        memset(account_info[0], 0, 9); // reset bufferu
        memset(account_info[1], 0, 9); // reset bufferu
    }
    return 1;
}

static void recursive_dir_browsing(char *path) {
    // k tomu, abych umel vedet, kam presne jit (do jake slozky a v jakem poradi), tak musim implementovat linked list, proc? kdyz bych vstoupil do nejake slozky a ta mela dalsi a ta mela dalsi..., tak bych velice za chvili ztratil informaci o tom, jakou slozku mam otevrit, proto pro kazdy "level" musim udelat linked list, protoze ty soubory jsou usporadane jako strom => strom, binary tree ma 0 az max 2 potomky, tree ma 0 do nekonecna => takovy backtracking
    
    printf("\nAVE AVE CHRISTUS REX!\n");


    // nastaveni informaci root_node

    // nejdrive je potreba alokovat celou strukturu a potom kdyztak alokovat dalsi pointery a membery v one strukture
    // root_node = (struct Node_Linked_List *)malloc(sizeof(struct Node_Linked_List *));
    // root_node_path = (char *)malloc(strlen(path));
    // memcpy((void *)root_node_path, (void *)path, strlen(path)); // path vyplnena, vse ostatni se vyplni ve funkci create_assign_next_node, kde pozor old_node a new_node JE root_node
    
    // toto je validni jen tehdy, kdyz mame nejakou strukturu pointer typu te struktury a predavame memory adresu te struktury

    struct Node_Linked_List *root_node;
    fill_root_node(&root_node, path);

    struct Node_Linked_List *new_node;
    new_node = create_assign_next_node(&root_node);

    struct Node_Linked_List *pointer_to_pass = new_node;
    while (1) {
        struct Node_Linked_List *continuous_node;
        continuous_node = create_assign_next_node(&pointer_to_pass);
        pointer_to_pass = continuous_node;
    }
   

    // printf("\n\n vypis: %d", root_node->no_states);
    for (int i = 0; i < root_node->no_states; i++) {
        printf("\ndir_names[i]: %s", root_node->dir_names[i]);
    }


    // for (int i = 0; i < new_node->no_states; i++) {
    //     printf("\nnames: %s", new_node->dir_names[i]);
    // }


    // struct Node_Linked_List *new_node = (struct Node_Linked_List *)malloc(sizeof(struct Node_Linked_List));
    // new_node = create_assign_next_node(&root_node); // return kopiruje data do pointeru automaticky pokud ta funkce vraci typ struct, pokud se vraci string literal, tak to nezanikne a je to jenom read-only, pokud lokalni pole, promenna, tak to zanikne
    // // protoze C je by value jazyk, tak cokoliv co ma value tak nezanikne, krome poli na vlastnim stacku a pointeru na vlastnim stacku


}

char *path_safety(char *path) {
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
        free_all();
    }
    memset(path_to_control, 0, strlen(buf) + 1);

    char *start_filename = NULL;
    if (ftp_user_info.filename_to_save != NULL) {
        char *temp = (char *)malloc(strlen(buf) + 10);
        if (temp == NULL) {
            free(path_to_file);
            free(path_to_control);
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

    // else if (working_with_files == 1) {
    //     size_t length = strlen(buf);

    //     char *temp_filename = (char*)malloc(strlen(buf) + 1);
    //     if (temp_filename == NULL) {
    //         perror("malloc() selhal - path_to_open - working with files");
    //         free_all();
    //     }
    //     memset(temp_filename, 0, strlen(buf) + 1); // automaticky NULL terminator

    //     int temp_filename_i = 0;
    //     for (int i = length - 1; i >= 0; i--) {
    //         temp_filename[temp_filename_i++] = buf[i];
    //     }

    //     char *st_slash = strstr(temp_filename, "/");
    //     if (st_slash == NULL) {
    //         fprintf(stderr, "\nstrstr() nenasel zadny slash - path_to_open - working with files\n");
    //         fflush(stderr);
    //         free(path_to_control);
    //         free(path_to_file);

    //         return NULL;
    //     }
    //     int st_slash_i = (int)(st_slash - temp_filename);

    //     char *filename = (char *)malloc(st_slash_i);
    //     if (filename == NULL) {
    //         perror("malloc() selhal - path_to_open - working with files");
    //         fflush(stderr);

    //         free(path_to_control);
    //         free(path_to_file);
    //         free_all();
    //     }
    //     memset(filename, 0, st_slash_i);

    //     int filename_i = 0;
    //     for (int i = st_slash_i - 1; i >= 0; i--) {
    //         filename[filename_i++] = temp_filename[i];
    //     }

    //     ftp_user_info.filename_to_save = strdup(filename);

    //     strcpy(path_to_control, filename);

    //     free(temp_filename);
    //     free(filename);
    // }

    // printf("\n\n\n\033[31mpath_to_file - path_to_open - zacatek: %s", path_to_file);
    printf("\nbuf - path_to_open - zacatek: %s\033[0m\n\n", buf);

    // uz udelano v extract_path_command
    // // " "

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
        strcpy(path_to_file, ftp_user_info.curr_dir);
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
        strcpy(path_to_file, ftp_user_info.curr_dir);
        strcpy(path_to_file + strlen(ftp_user_info.curr_dir), path_to_control + 2); // protoze ftp_user_info.curr_dir ma format /tmp/
    }
    // slozka => ./slozka
    else if (tilde_p == NULL && strstr(path_to_control, ".") == NULL && strstr(path_to_control, "/") == NULL) {
        // printf("\n\n\n\n\nTADY TO JE");
        fflush(stdout);
        strcpy(path_to_file, ftp_user_info.curr_dir);
        strcpy(path_to_file + strlen(ftp_user_info.curr_dir), path_to_control); // toto jde protoze je tam curr_dir ve formatu /slozka/
    }
    else {
        printf("\nNejaka chyba v if statementu v path_to_open()\n");
        return NULL;
    }

    if (start_filename != NULL) { 
        char *output = (char *)malloc(strlen(path_to_file) + strlen(ftp_user_info.filename_to_save) + 2); // / \0
        if (output == NULL) {
            free(path_to_file);
            free(path_to_control);
            free_all();
        }

        snprintf(output, strlen(path_to_file) + strlen(ftp_user_info.filename_to_save) + 2, "%s%s", path_to_file, ftp_user_info.filename_to_save); // !CHRIST IS GOD!
        // char *output = path_safety(temp); // kdyby to bylo s path_safety, tak by open() vyhodil error, ze to neni directory, i kdyz je to file /soubor.txt => soubor, /soubor.txt/ => directory

        free(path_to_file);
        free(path_to_control);
        return output;
    }
    else if (working_with_files == 1) { // pracuje se se soubory
        char *output = (char *)malloc(strlen(path_to_file) + strlen(ftp_user_info.filename_to_save) + 1);
        if (output == NULL) {
            perror("malloc() selhal - path_to_open - working with files");
            fflush(stderr);

            free(path_to_control);
            free(path_to_file);
            free_all();
        } // CHRIST IS GOD!!
        memset(output, 0, strlen(path_to_file) + strlen(ftp_user_info.filename_to_save) + 1);

        snprintf(output, strlen(path_to_file) + strlen(ftp_user_info.filename_to_save) + 1, "%s%s", path_to_file, ftp_user_info.filename_to_save);
    }
    else {
        char *output = path_safety(path_to_file);

        free(path_to_file);
        free(path_to_control);
        return output;
    }    
    // printf("\n\033[31mfinal_path - path_to_open - konec: %s\n\n\n\033[0m", final_path); // Christ is Lord!
    // fflush(stdout);
}

static int ftp_dtp() {
    // ~/Documets/FTP_SERVER
    // => /home/marek

    // char *final_path = path_to_open(path);
    // printf("tady je path: %s\n", final_path);
    // fflush(stdout);

    fd_set readbitmask_stdin;
    
    char *user_data = (char *)malloc(MAX_LEN);
    char *user_choice_dir_file = (char *)malloc(sizeof(char));
    // setvbuf(stdout, NULL, _IONBF, 0); // nebude bufferovane

    int write_choice = 0;

    for (;;) { // setup, advance nic zvlastniho nedelaji
        if (!write_choice) {
            printf("\nchcete poslat soubor (f) nebo adresar (d): \n");
            fflush(stdout);
        }
        
        struct timeval timeout = { .tv_sec = 2, .tv_usec = 0}; // select zase muze zasahnout do teto struktury

        FD_ZERO(&readbitmask_stdin); // select meni obsah toho fd_set, proto v loopu to musi byt inicializovano vzdy nove
        FD_SET(STDIN, &readbitmask_stdin); // stdin pridavam do long => 1024 bits, je to typu long => 8 Bytes => 64 bits => 1024 / 64 => array 16 long
        fflush(stdout);
        int select_rv = select(NFDS, &readbitmask_stdin, NULL, NULL, &timeout); //  4 jakoze, 0 - stdin, 1 - stdout - 2, stderr - 3 => 3 + 1 = 4, 4 aby se nereklo

        if (select_rv == -1) {
            perror("select() selhal - ftp_dtp - stdin");
            exit(EXIT_FAILURE);
        }

        if (select_rv == 1 || FD_ISSET(STDIN, &readbitmask_stdin)) { // pokud je stdin ready
            // scanf ma tzv. scan set a potom si muzeme rict i kolik presne charakteru, potrebujeme
            // tento scam set muze failnout, protoze kdyz zadam pred tim neco a zmacknu enter, tak se vezme jenom to neco a v stdin bufferu zustane \n, proto tenhle call uvidi to prvni \n a failne, proto musim ignorovat vsechny whitespaces pred skutecnym obsahem v stdin, to se dela vyznacenim mista pred %, flushnout by neslo, protoze flushovani je jenom pro output streamy, nebo by to nejspise slo flushnout tim loopem getchar()
            // kdyz udelam &d, %s, %c, tak se vezme jen ta dana vec a ten zbytek zbyde v stdin
            scanf(" %c", user_choice_dir_file); // white sprace ve formatu => ignoruji se whitespaces v tom bufferu
            printf("\nzadejte path: ");
            scanf(" %255[^\n]", user_data); // cti dokud se nenarazi na \n, to ^ znamena, ze chceme cist vsechnz charaktery krome za ^, kdyby to bylo bez toho ^, tak chci cist JENOM TY charaktery
            printf("\n");
            char *path = path_to_open(user_data, 0);
            if (path != NULL) {
                // printf("path_to_open: %s", path);
                recursive_dir_browsing(path);

                // free(path);
                // printf("user_data: %s\n", user_data);
            }
            else {
                fprintf(stderr, "\nUser zadal spatnou path\n");
                fflush(stdout);
                free_all();
            }
            
            
        }
        // else {
        //     printf("\ntady\n");
        //     fflush(stdout);
        // }
        // printf("\na\n");
        
        write_choice = 1;
    }
}

void zero_memory(char *ptr_memory_address) {
    // printf("\ndela se neco?");
    // protoze je C jazyk, kde se davaji veci by value, tak to znamena, pri predani funkci urciteho pointeru, tak se udela kopie a do te see ulozita hodnota a kdyz se udela pointer = nova_vec, tak se to zmeni jenom lokalne, ale pokud se udela dereference (zmena hodnoty na urcite memory adrese), tak se to promeni globalne, jako treba pointer->neco = nova_nec se udela globalne, protoze -> je defaultne dereference
    memset(ptr_memory_address, 0, sizeof(char) * 100);
}

void send_ftp_code(char *message, int ftp_control_com) {
    ssize_t bytes_sent;
    size_t bytes_total;

    if (strlen(message) == 0) {
        fprintf(stderr, "nulova zprava - send_ftp_code");
        exit(EXIT_FAILURE);
    }

    int len_message = strlen(message) + 1; // protoze strlen() vraci delku bez \0

    // https://stackoverflow.com/questions/3081952/with-c-tcp-sockets-can-send-return-zero
    // strlen("") => 0
    // enums zacinaji na 0 a potom + 1 dalsim enumem
    // https://www.quora.com/What-is-the-best-way-to-read-from-a-socket-if-we-dont-know-how-many-bytes-are-to-be-received
    while ( (bytes_sent = send(ftp_control_com, message, len_message, 0)) != len_message) {
        if ( bytes_sent == -1) {
            perror("send() selhal - send_ftp_code");
            exit(EXIT_FAILURE);
        }
        // podle jednoho cloveka na stackoverflow to muze vratit 0, kdyz TCP stack receive buffer je plny, tak se muze cekat/odeslat 0 Bytes
    }

}

// protoze FTP server (originalni implementaci podporuje jenom ascii soubory), takze nemuzeme posilat treba veci v cestine, protoze to je jina encoding sada, tak prakticky jenom zalezi, jak se interne ulozi ty chars, protoze, pokud v programu to ulozime jako unsigned char => 1 Bytes, tak kdybychom chteli ulozit 2 Bytes znak do 1 Bytes znaku, tak by to nefungovalo
// tento server bude podporovat jenom ASCII (potom kdyztak utf-8)

char *read_contents_ftp(char *path) {
    int fd = open(path, O_RDONLY);

    // pokud bychom meli FILE *, tak musime pouzit fileno() pro ziskani file descriptoru
    struct stat info;
    printf("\n\nchar path: %s\n", path);
    fflush(stdout);

    // stat/fstat/lstat
    if (stat(path, &info) == -1) { // path s / na konci se pocita jako path pro slozku a path bez niceho na konci se pocita jako path pro file => path/, path.txt
        perror("stat() selhal - read_contents_ftp");
        printf("\n\nerror: %d\n", errno);
        printf("\n\n%d %d %d %d %d %d %d", EACCES, EIO, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, EOVERFLOW);
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    size_t len_file = info.st_size;
    char *data_from_file = (char *)malloc(len_file + 1); // file s jednim znakem => 2 Bytes => char + \n => proto + 1 pro => 3 Bytes

    ssize_t bytes_read;
    size_t total_bytes = 0;
    while (1) {
        bytes_read = read(fd, data_from_file + total_bytes, len_file - total_bytes);
        if (bytes_read == len_file) {
            total_bytes += bytes_read;
            break;
        }
        else if ( bytes_read == -1) {
            perror("read() selhal - read_contents_ftp");
            exit(EXIT_FAILURE);
        }
        total_bytes += bytes_read;
    }
    data_from_file[total_bytes] = '\0';
    return data_from_file;
}

void data_send_ftp(struct bufferevent *bufevent_data, char *data_to_send) {
    printf("\n\n\n\nDATA_SEND_FTP, data_to_send: %s\n", data_to_send);
    fflush(stdout);
    fflush(stdout);
    if (bufferevent_write(ftp_user_info.bufevent_data, data_to_send, strlen(data_to_send)) == -1) { // strlen bez +1, protoze files NEMAJI NULL TERMINATOR!!
        fprintf(stderr, "\nbufferevent_write selhal - data_send_ftp");
        exit(EXIT_FAILURE);
    }
}

void control_send_account_info(struct bufferevent *bufevent_control, char *text) {
    if ( bufferevent_write(ftp_user_info.bufevent_control, text, strlen(text) + 1) == -1) {
        perror("bufferevent_write() selhal - control_send_account_info");
        exit(EXIT_FAILURE);
    }
    // printf("\n\n\n\n\n\nPOSLALO SE TO?\n\n\n\n\n\n\n\n");
    fflush(stdout);
}

void send_data_file_path(struct bufferevent *bufevent_data) {   char *file_path = (char *)malloc(QUEUE_MESSAGE_LEN); // protoze musi byt vetsi nebo rovno defaultni velikost mq_msgsize
    // memset(file_path, 0, QUEUE_MESSAGE_LEN);

    if ( mq_receive(ftp_user_info.data_queue, file_path, QUEUE_MESSAGE_LEN, NULL) == -1) {
        perror("mq_receive() selhal - send_data_file_path");
        exit(EXIT_FAILURE);
    }
    printf("\n\n\n\n\nfile_path: %s", file_path);
    fflush(stdout);
    if ( bufferevent_write(ftp_user_info.bufevent_data, file_path, strlen(file_path) + 1) == -1) {
        perror("bufferevent_write() selhal - send_data_file_path");
        exit(EXIT_FAILURE);
    }

    printf("\n\n\nted by se to melo poslat\n\n\n\n");
    fflush(stdout);
}

void reset_bufevent_data_len() {
    BUFEVENT_DATA_LEN = 512;
}

int is_command_ok(char *command_user) {
    // USER
    // PASS
    // QUIT - nepotrebuje nic kontrolovat
    // PORT
    // PASV - nepotrebuje nic kontrolovat
    // RETR
    // STOR
    // NOOP - nepotrebuje nic kontrolovat
    // TYPE - nepotrebuje nic kontrolovat
    // CHDD

    // 1 - True - vse OK
    // 0 - False - neco spatne

    char *space = strstr(command_user, " ");
    int space_i = (int)(space - command_user);

    if ( strstr(command_user, "USER") != NULL && space != NULL) {
        if (isalpha(command_user[++space_i]) && isalpha(command_user[++space_i]) ) {
            return 1;
        }
        return 0;
    }
    else if ( strstr(command_user, "PASS") != NULL && space != NULL) {
        for (int i = ++space_i; i < strlen(command_user) + 1; i++) {
            if (!isalpha(command_user[i]) || !isdigit(command_user[i]) || !ispunct(command_user[i]) ) {
                return 0;
            }
        }
    }
    else if (strstr(command_user, "LIST") != NULL) {
        if (strstr(command_user, " ") != NULL || strstr(command_user, ".") != NULL || strstr(command_user, "~") != NULL || strstr(command_user, ".") || strstr(command_user, "/") != NULL || space == NULL) { // u STOR, RETR apod. chci, aby user zadaval definitivni path, ale u list je to jedno
            return 1;
        }
        return 0;
    }
    else if ( strstr(command_user, "RETR") != NULL || strstr(command_user, "STOR") != NULL || strstr(command_user, "CHDD") != NULL) {
        if (strstr(command_user, "/") != NULL || strstr(command_user, ".") != NULL || strstr(command_user, "~") != NULL && space != NULL) {
            return 1;
        }
        return 0;
    }
    return 1;
}

void send_ftp_commands(struct bufferevent *bufevent_control) {
    char *commands_to_send = (char *)malloc(QUEUE_MESSAGE_LEN);
    if ( commands_to_send == NULL) {
        perror("malloc() selhal - send_ftp_commands");
        exit(EXIT_FAILURE);
    }

    /*
    The msg_len argument specifies the size of the buffer pointed to by
    msg_ptr; this must be greater than or equal to the mq_msgsize attribute of the queue (see mq_getattr(3)).
    */
    int num;
    if ( mq_receive(ftp_user_info.control_queue, commands_to_send, QUEUE_MESSAGE_LEN, NULL) == -1) {
        perror("mq_receive() selhal - send_ftp_commands");
        exit(EXIT_FAILURE);
    }

    printf("\n\n\n send_ftp_commands: %s\n\n", commands_to_send);
    fflush(stdout);
    if ( bufferevent_write(ftp_user_info.bufevent_control, commands_to_send, strlen(commands_to_send) + 1) == -1) {
        perror("bufferevent_write() selhal - send_ftp_commands");
        printf("\ntady");
        exit(EXIT_FAILURE);
    }
    // send(ftp_sockets_obj.ftp_control_com, commands_to_send, strlen(commands_to_send) + 1, 0); // tomuto se vytvori novy ephemeral port a rovnou se to bindne!, proto se ukazovaly dve connections na server
    // protoze se acceptlo skutecne pripojeni a potom se slo vykonavat neco jineho, ale mezitim protoze ten socket byl nastaveny na listen socket, tak se server chtel pripojit podruhe A kernel prijima connections automaticky, ale do te doby, co program neudela accept(), tak nepracuje s danym connection!! to se nejspise stalo
    // kdyz kernel acceptoval tento socket a aplikace jeste neudelala accep(), tak se socket nachazi v completed connection queue a ma stav ESTABLISHED, zatimco i  socket, ktery je v modu listen bude se stavem v LISTEN a potom hned jak skonci program, tak ty sockety, ktere byly opravdu pripojene, tak se prepnou do stavu TIME_WAIT a ty vsechny ostatni, ktere treba nebyly acceptnute, tak se ihned zrusi a neprepne se do TIME_WAIT
    printf("=== bufferevent_write done ===, %s", commands_to_send);
    // kazdy command se musi poslat pres control connection, aby i server dostal zpravy o informacich
}

void bufevent_event_cb_data(struct bufferevent *bufevent_data, short events, void *ptr_arg) {
    // printf("\n\n\nftp_user_info.quit_command_now: %d", ftp_user_info.quit_command_now);
    fflush(stdout);
    if (ftp_user_info.user_loggedin == 0) {
        close(ftp_user_info.ftp_sockets_obj.ftp_data_com);
        ftp_user_info.ftp_sockets_obj.ftp_data_com = -1;
        return;
    }
    printf("\n\n\n\n\n\nEVENT DATA\n\n\n");
    fflush(stdout);
    // exit(EXIT_FAILURE);
    evutil_socket_t socket_to_close = bufferevent_getfd(ftp_user_info.bufevent_data);
    if (socket_to_close == -1) {
        fprintf(stderr, "\nbufferevent_getfd() selhal - bufevent_event_cb_data");
        exit(EXIT_FAILURE);
    }

    if ((BEV_EVENT_EOF & events) == BEV_EVENT_EOF) {
        close(ftp_user_info.ftp_sockets_obj.ftp_data_com);
        close(ftp_user_info.ftp_sockets_obj.ftp_data_socket);
        close(ftp_user_info.ftp_sockets_obj.ftp_control_socket);
        close(ftp_user_info.ftp_sockets_obj.ftp_control_com);
        fprintf(stderr, "\nbufferevent_read() selhal - bufevent_event_cb_data");
        fprintf(stderr, "\npeer ukoncil connection - EOF - data connection - bufevent_event_cb_data");
        fflush(stderr);
        exit(EXIT_FAILURE); // bez tohoto se potom spusti event_cb_control, protoze ten socket se taky uzavira
    }
    else if ( (BEV_EVENT_ERROR & events) == BEV_EVENT_ERROR) {
        if (close(socket_to_close) == -1) {
            perror("close() selhal - bufevent_event_cb_data");
            exit(EXIT_FAILURE);
        }
        close(ftp_user_info.ftp_sockets_obj.ftp_data_com);
        close(ftp_user_info.ftp_sockets_obj.ftp_data_socket);
        close(ftp_user_info.ftp_sockets_obj.ftp_control_socket);
        close(ftp_user_info.ftp_sockets_obj.ftp_control_com);
        fprintf(stderr, "\nbufferevent_read() selhal - data connection - bufevent_event_cb_data");
        exit(EXIT_FAILURE);
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
        close(ftp_user_info.ftp_sockets_obj.ftp_data_com);
        close(ftp_user_info.ftp_sockets_obj.ftp_data_socket);
        close(ftp_user_info.ftp_sockets_obj.ftp_control_socket);
        close(ftp_user_info.ftp_sockets_obj.ftp_control_com);
        
        fprintf(stderr, "\nbufferevent_read() selhal - control connection - bufevent_event_cb_control");
        fprintf(stderr, "\npeer ukoncil connection - EOF - control connection - bufevent_event_cb_control");
        _exit(EXIT_FAILURE);
    }
    else if ( (BEV_EVENT_ERROR & events) == BEV_EVENT_ERROR) {
        close(ftp_user_info.ftp_sockets_obj.ftp_data_com);
        close(ftp_user_info.ftp_sockets_obj.ftp_data_socket);
        close(ftp_user_info.ftp_sockets_obj.ftp_control_socket);
        close(ftp_user_info.ftp_sockets_obj.ftp_control_com);
        
        fprintf(stderr, "\nbufferevent_read() selhal - control connection - bufevent_event_cb_control");
        fflush(stderr);
        _exit(EXIT_FAILURE);
    }
}

// void bufevent_event_cb_both(struct bufferevent *both, short events, void *ptr_arg) {
//     if ( (BEV_EVENT_EOF & events) == BEV_EVENT_EOF) {
//         struct evbuffer *input_evbuffer = bufferevent_get_input(ftp_user_info.bufevent_control); // ziskame underlying vrstvu bufferevents => input/output evbuffer

//         // pokud se prerusi data connection a bude prazdny buffer, tak to znamena, ze server doposlal posledni data => zalezi na transmission modes
//         // toto by se melo zavolat az potom se zjisti, ze bufferevent_read dostal flag EOF => po dokonceni posilani jakychkoliv dat
//         if ( evbuffer_get_length(input_evbuffer) != 0) {
//             fprintf(stderr, "nejspise nastal error - EOF - bufevent_event_cb_both - data");
//             exit(EXIT_FAILURE);
//         }
//     }
//     else if (( (BEV_EVENT_ERROR) & events) == BEV_EVENT_ERROR) {
//         EVUTIL_SOCKET_ERROR();
//         exit(EXIT_FAILURE);
//     }
// }

void bufevent_read_cb_control(struct bufferevent *bufevent_control, void *ptr_arg) {
    // close(bufferevent_getfd(ftp_user_info.bufevent_control));

    reset_bufevent_data_len();

    char *command_buf_to_recv = (char *)malloc(BUFEVENT_DATA_LEN);
    memset(command_buf_to_recv, 0, BUFEVENT_DATA_LEN);

    size_t total_bytes = 0, bytes_now;
    for (; ;) {
        bytes_now = bufferevent_read(ftp_user_info.bufevent_control, command_buf_to_recv + total_bytes, BUFEVENT_DATA_LEN - total_bytes);

        if (bytes_now == -1) {
            perror("bufferevent_read() selhal - bufevent_read_cb_control");
            free(command_buf_to_recv);
            exit(EXIT_FAILURE);
        }
        else if (bytes_now == 0) {
            // printf("\n\n%s", command_buf_to_recv);
            if (strstr(command_buf_to_recv, "!END!") != NULL) {
                fprintf(stderr, "\nserver ukoncil proces");
                free(command_buf_to_recv);
                _exit(EXIT_FAILURE);
            }
            else if (strstr(command_buf_to_recv, "\r\n") != NULL) {
                // printf("\nvse precteno");
                printf("\n%s", command_buf_to_recv);
                // free(command_buf_to_recv);
                break;
            }
            else {
                fprintf(stderr, "\nserver nejspise neukoncil odpoved pomoci CRLF = carriage return line feed");
                free(command_buf_to_recv);
                exit(EXIT_FAILURE);
            }
            
        }

        total_bytes += bytes_now;
    }
    // printf("\n\n\n\n\n\n\n\ntady po funkci\n\n\n\n");
    // fflush(stdout);
    free(command_buf_to_recv);

    
}

void bufevent_write_cb_control(struct bufferevent *bufevent_control, void *ptr_arg) {
    // printf("\nall data sent\n");
}

char *precise_path(char *filename) {
    // char *precise_path = (char *)malloc(strlen(ftp_user_info.username) + strlen(ftp_user_info.filename_to_save) + 7); // jedno pro / => dve pro \0, tri pro tmp
    // memset(precise_path, 0, strlen(ftp_user_info.username) + strlen(ftp_user_info.filename_to_save) + 7);

    // snprintf(precise_path, strlen(ftp_user_info.username) + strlen(ftp_user_info.filename_to_save) + 7, "/tmp/%s/%s", ftp_user_info.username, ftp_user_info.filename_to_save);
    // return precise_path;

    char *temp_output = (char *)malloc(strlen(ftp_user_info.dd) + strlen(filename) + 2); // / \0
    if (temp_output == NULL) {
        free_all();
    }
    memset(temp_output, 0, strlen(ftp_user_info.dd) + strlen(filename) + 2);

    snprintf(temp_output, strlen(ftp_user_info.dd) + strlen(filename) + 2, "%s%s", ftp_user_info.dd, filename);

    return temp_output;
}// CHRIST IS KING! AVE AVE CHRISTUS REX!

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
        if (temp_last_slash_buf[i] != '\r' && temp_last_slash_buf[i] != '\n') {
            filename[filename_i++] = temp_last_slash_buf[i];
        }
    }
    ftp_user_info.filename_to_save = filename;
    return filename;
}

// data queue = path for saving/retrieving
// control queue = commands to send
// QUEUE_MESSAGE_LEN = MQ_XX
// BUFEVENT_DATA_LEN = BUFFEREVENT_XX
void bufevent_read_cb_data(struct bufferevent *bufevent_data, void *ptr_arg) {
    printf("\n\n\n\n\n\n\n\n\nPRECETL SE TENHLE CALLBACK?");
    fflush(stdout);
    reset_bufevent_data_len();

    char *temp_path = (char *)malloc(QUEUE_MESSAGE_LEN);
    if (temp_path == NULL) {
        perror("malloc() selhal - bufevent_read_cb_data");
        exit(EXIT_FAILURE);
    }
    memset(temp_path, 0, QUEUE_MESSAGE_LEN);

    if (mq_receive(ftp_user_info.data_queue, temp_path, QUEUE_MESSAGE_LEN, NULL) == -1) {
        perror("mq_receive() selhal - bufevent_read_cb_data");
        exit(EXIT_FAILURE);
    }




    char *data_buf = (char *)malloc(BUFEVENT_DATA_LEN);
    if (data_buf == NULL) {
        perror("malloc() selhal - bufevent_read_cb_data");
        exit(EXIT_FAILURE);
    }

    size_t bytes_now, bytes_total = 0;
    for (; ;) {
        bytes_now = bufferevent_read(ftp_user_info.bufevent_data, data_buf + bytes_total, BUFEVENT_DATA_LEN - bytes_total);

            // zadna data v bufferu nebo read selhal, pokud by to selhalo, tak by se zavolal nejspise nejdrive event_cb, ktery by skoncil proces, takze 0 = zadne data v bufferu
            if (bytes_now == 0) {
                bytes_total += bytes_now;
                // printf("\n\n\n\n\n\nSPECIFY PATH: %s - read_cb_data, %s", temp_path, ftp_user_info.username);
                char *filename = get_file_name(temp_path);
                char *path = precise_path(filename);
                printf("\n\ntemp_path: %s, filename: %s, path: %s", temp_path, filename, path);
                fflush(stdout);
                save_file(path, data_buf, bytes_total); // posilano bez null terminatoru, protoze files nejsou ukonceny null terminatorem, vraci 0 bytes, pokud uz nejsou data nebo pokud je error, ale jelikoz je nastaven event_callback, tak by se error zaregistroval drive nez samotny error u bufferevent_read()
                printf("\nvse OK, precise_path: %s", precise_path);
                break;
        }
        bytes_total += bytes_now;

        if (bytes_total == BUFEVENT_DATA_LEN) {
            BUFEVENT_DATA_LEN += 512;

            char *temp_data_buf = (char *)realloc(data_buf, BUFEVENT_DATA_LEN);
            if (temp_data_buf == NULL) {
                free(data_buf);
                perror("realloc() selhal - bufevent_read_cb_data");
                exit(EXIT_FAILURE);
            }
            data_buf = temp_data_buf;

        }
    }
    
}

void bufevent_write_cb_data(struct bufferevent *bufevent, void *ptr_arg) {
    // printf("\nzapsala se data");
}

char *extract_path_command(char *command) {
    // if ( (strstr(command, "LIST") != NULL && strstr(command, ".") != NULL && strlen(command) == 8) || (strstr(command, "LIST") != NULL && strlen(command) == 6) ) { // protoze tam je jeste \r\n
    //     // char *path_to_return = (char *)malloc(strlen(ftp_user_info.curr_dir) + 1); // malloc() protoze nechci polkud udelam free, tak se zkoruptuje i main pointer ftp_user_info.curr_dir
    //     // memset(path_to_return, 0, strlen(ftp_user_info.curr_dir));
    //     // path_to_return = strdup(ftp_user_info.curr_dir);
        
    //     return ftp_user_info.curr_dir;
    // }

    char *path = (char *)malloc(92); // protoze 100 - 3 (\r\n\0) - 5 (RETR )
    if (path == NULL) {
        perror("malloc() selhal - extract_path_command");
        exit(EXIT_FAILURE);
    }
    memset(path, 0, 92);

    char *separator = strstr(command, " ");

    // path: " "
    printf("\n\n\nextract_path_command: %s, strlen(command): %zu\n", command, strlen(command));
    fflush(stdout);
    if (separator == NULL) {
        if (strstr(command, "CD") != NULL) {
            int uid = getuid(); // user ID
            struct passwd *password = getpwuid(uid);
            char *home_directory = password->pw_dir;
            return home_directory;
        }
        else if (strstr(command, "LIST") != NULL) {
            printf("\n\n\033[31mpath v extract_path_command: ''\033[0m");
            fflush(stdout);
            strcpy(path, ftp_user_info.curr_dir);
            return path;
        }
    }

    int separator_i = (int)(separator - command);

    char *carriage_return = strstr(command, "\r");
    if (separator == NULL) {
        perror("strstr() selhal - extract_path_command");
        exit(EXIT_FAILURE);
    }
    int carriage_return_i = (int)(carriage_return - command);

    for (int i = separator_i + 1, path_i = 0; i < carriage_return_i; i++) {
        path[path_i++] = command[i];
    }
    // nemusime resit \0, protoze automaticky NULL terminated
    printf("\n\n\n\nextract_path: path: %s\n\n\n", path);
    fflush(stdout);
    return path;
}

char *insert_crlf(char *command) {
    // prepisovani \0, takze musi byt ten buffer automaticky ukoncen \0, jinak strlen() selze, protoze nenajde \0 a vyhodi to error buffer overflow
    // zero_memory nefunguje tak, jak ma
    // printf("\n\n %zu", strlen(command));
    fflush(stdout);
    command[strlen(command)] = '\r'; // \r
    // printf("\n\n %zu", strlen(command));
    fflush(stdout);
    command[strlen(command)] = '\n'; // \n, strlen(command) + 1 je spatne, protoze pridanim \r se zvetsi ta velikost toho command
    // printf("\n\n %zu", strlen(command));
    fflush(stdout);
    command[strlen(command)] = '\0'; // aby to vzdy koncilo <crlf>NULL char

    return command;
}



void *thread_callback_func(void *) {
    printf("\n\n\n\n\n\n\n\ntadyy ahooj");
    fflush(stdout);
    event_base_loop(ftp_user_info.evbase_data, EVLOOP_NO_EXIT_ON_EMPTY);

    printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nTO SKONCILO?");
    fflush(stdout);
    exit(EXIT_FAILURE);
}

void signal_handler(int signal_value) {
    // ctrl + \ ukonci taky program
    if (ftp_user_info.bufevent_control == NULL) {
        puts("bufevent je prazdny");
        _exit(EXIT_FAILURE);
    }
    if (bufferevent_write(ftp_user_info.bufevent_control, "!END!", strlen("!END!") + 1) == -1) {
        _exit(EXIT_FAILURE);
    }
   
    free_all();

    // _exit(EXIT_FAILURE); // man signal-safety
    // _Exit(EXIT_FAILURE);
    // reentrant/nonreentrant functions
}

void reset_timeval_struct_data (evutil_socket_t fd, short what, void *arg) {
    // printf("\ndata_struct");
    // fflush(stdout);
    ftp_user_info.timeout_data.tv_sec = 5;
    ftp_user_info.timeout_data.tv_usec = 0;
}

void reset_timeval_struct_control (evutil_socket_t fd, short what, void *arg) {
    ftp_user_info.timeout_control.tv_sec = 5;
    ftp_user_info.timeout_control.tv_usec = 0;
}

int does_path_exist(char *path) {
    // 1 = OK
    // 0 = NE OK
    if (open(path, O_DIRECTORY) == -1) {
        return 0;
    }
    return 1;
}

int check_path(char *path) {
    // 0 = false
    // 1 = true

    if ( strstr(path, "/tmp/ftp_server_files") == NULL) {
        return 0;
    }
    return 1;
}

void quit_user() {
    if (ftp_user_info.username != NULL) {
        free(ftp_user_info.username); // free nezerouje memory, jen ji pripravi na dalsi pouzivani!
    }
    if (ftp_user_info.password != NULL) {
        free(ftp_user_info.password);  // free nezerouje memory, jen ji pripravi na dalsi pouzivani!
    }
    if (ftp_user_info.filename_to_save != NULL) {
        free(ftp_user_info.filename_to_save);
    }
    if (ftp_user_info.last_path != NULL) {
        free(ftp_user_info.last_path);
    }
    if (ftp_user_info.dd != NULL) {
        free(ftp_user_info.dd);
    }
    if (ftp_user_info.user_request != NULL) {
        free(ftp_user_info.user_request);
    }

    if ( ftp_user_info.data_queue != -1) {
        mq_close(ftp_user_info.data_queue);
    }
    if (ftp_user_info.evbase_data != NULL) {
        free(ftp_user_info.evbase_data);
    }
    if (ftp_user_info.bufevent_data != NULL) {
        free(ftp_user_info.bufevent_data);
    }

    ftp_user_info.username = NULL;
    ftp_user_info.password = NULL;
    ftp_user_info.filename_to_save = NULL;
    ftp_user_info.last_path = NULL;
    ftp_user_info.dd = NULL;
    ftp_user_info.user_request = NULL;

    ftp_user_info.user_loggedin = 0;

    sleep(1); // prevence toho, ze se zprava <&&> neposle vcas
    close(ftp_user_info.ftp_sockets_obj.ftp_data_com);
    ftp_user_info.ftp_sockets_obj.ftp_data_com = -1;
}

void handle_command_function(char *command) {
    /*
    USER
    PASS
    QUIT
    PORT
    PASV
    RETR
    STOR
    NOOP
    TYPE
    CHDD
    */
    // printf("\n\ncommand: %s", command);
    // fflush(stdout);

    if (strstr(command, "QUIT") != NULL) {
        control_send_account_info(ftp_user_info.bufevent_control, "<&&>");

        puts("200 - command okay");

        // printf("\n\n\nftp_user_info.username: %s, ftp_user_info.password: %s", ftp_user_info.username, ftp_user_info.password);
        fflush(stdout);
        if (ftp_user_info.username != NULL && ftp_user_info.password != NULL) {
            quit_user();
        }
        else {
            puts("530 - Not logged in");
        }
    }
    else if (strstr(command, "CHDD") != NULL) {
        // musi byt ve formatu /slozka*/*
        // change default/downloads directory
        if (is_command_ok(command) != 1) {
            fprintf(stderr, "\nnejspise spatne zadany command");
            exit(EXIT_FAILURE);
        }

        char *temp_path = extract_path_command(command);
        char *path = path_to_open(temp_path, 0);
        if (path != NULL) {
            if (does_path_exist(path) != 1) {
                fprintf(stderr, "\npath neni adresar - neplatny argument pro CHDD");
                exit(EXIT_FAILURE);
            }
            printf("\n\ncurrent dd: %s", ftp_user_info.dd);
            printf("\n\nnew dd: %s", path);

            if (ftp_user_info.dd != NULL) {
                free(ftp_user_info.dd);
            }
            ftp_user_info.dd = strdup(path);
        }
        else {
            fprintf(stderr, "\nUser zadal spatnou path\n");
            fflush(stderr);
        }
        // free_all();
    }
    else if (strstr(command, "PORT") != NULL || strstr(command, "PASV") != NULL) { // connection part
        if (strstr(command, "PORT") != NULL) {
            // IPv4/IPv6, zpusob prenosu dat, protokol
            if ((ftp_user_info.ftp_sockets_obj.ftp_data_socket = socket(ftp_user_info.server_data_info.sin_family, SOCK_STREAM, 0)) == -1) {
                perror("socket() selhal - handle_command_function - PORT");
                exit(EXIT_FAILURE);
            }

            // pro klienta
            unsigned char *byte_field_address = (unsigned char *)&ftp_user_info.server_control_info.sin_addr.s_addr; // nova promenna Bytes na memory adresu, kde je ulozeno 4 Bytes

            int st_byte_addr = byte_field_address[0];
            int nd_byte_addr = byte_field_address[1];
            int rd_byte_addr = byte_field_address[2];
            int fth_byte_addr = byte_field_address[3];

            // PORT = server se pripojuje na clienta (data)
            // PASV = client se pripojuje na server (data)

            unsigned char *byte_field_port = (unsigned char *)&ftp_user_info.server_data_info.sin_port;

            int st_byte_port = byte_field_port[0];
            int nd_byte_port = byte_field_port[1];

            printf("\nPORT %d,%d,%d,%d,%d,%d", st_byte_addr, nd_byte_addr, rd_byte_addr, fth_byte_addr, st_byte_port, nd_byte_port);
            fflush(stdout);

            char *temp_command = (char *)malloc(sizeof(int)*6 + 1);
            memset(temp_command, 0, sizeof(int)*6 + 1);
            snprintf(temp_command, sizeof(int)*6 + 1, "PORT %d,%d,%d,%d,%d,%d", st_byte_addr, nd_byte_addr, rd_byte_addr, fth_byte_addr, st_byte_port, nd_byte_port);

            char *port_command = insert_crlf(temp_command);
            send_message_queue(ftp_user_info.control_queue, port_command, strlen(port_command) + 1, "mq_send() selhal - handle_command_function - PORT");

            int yes = 1;
            if (setsockopt(ftp_user_info.ftp_sockets_obj.ftp_data_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &yes, sizeof(int)) == -1 ) {
                perror("setsockopt() selhal - handle_command_function - PORT");
                exit(EXIT_FAILURE);
            }

            send_ftp_commands(ftp_user_info.bufevent_control); // send to the server
            // exit(EXIT_FAILURE);
           
            // if (setsockopt(ftp_user_info.ftp_sockets_obj.ftp_data_socket_or_com, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) {
            //     perror("setsockopt() selhal - handle_command_function - PORT");
            //     exit(EXIT_FAILURE);
            // }

            if ( bind(ftp_user_info.ftp_sockets_obj.ftp_data_socket, (struct sockaddr*)&ftp_user_info.server_data_info, sizeof(ftp_user_info.server_data_info)) == -1) {
                perror("bind() selhal - handle_command_functions");
                exit(EXIT_FAILURE);
            }

            if (listen(ftp_user_info.ftp_sockets_obj.ftp_data_socket, BACKLOG) == -1) {
                perror("listen() selhal - handle_command_function");
                exit(EXIT_FAILURE);
            }

            if ((ftp_user_info.ftp_sockets_obj.ftp_data_com = accept(ftp_user_info.ftp_sockets_obj.ftp_data_socket, NULL, NULL)) == -1) {
                perror("accept() selhal - handle_command_function");
                exit(EXIT_FAILURE);
            }

            printf("\n%s, connection established", port_command);
        }
        else if (strstr(command, "PASV") != NULL) {
            // SELECT() NENI K TOMU ABY SE ZJISTILO JESTLI SE MUZE VYKONAT CONNECT< ALE JENM JESTLI JE MOZNO PRECIST/POSLAT DATA!!!!          
            if (ftp_user_info.user_loggedin) {
                send_message_queue(ftp_user_info.control_queue, "PASV\r\n", strlen("PASV\r\n") + 1, "mq_send() selhal - handle_command_function - PASV");

                if ((ftp_user_info.ftp_sockets_obj.ftp_data_socket = socket(ftp_user_info.server_data_info.sin_family, SOCK_STREAM, 0)) == -1) {
                    perror("socket() selhal - handle_command_function - PASV");
                    exit(EXIT_FAILURE);
                }

                send_ftp_commands(ftp_user_info.bufevent_control); // send to the server

                
                /*if () {

                    // stal se takovy error, ze transport endpoint is already connected, ale ten endpoint byl ephemeral port (ten random port, ktery priradi kernel) - to se zjistilo, ze jsem udelal nekolik connections a koukal se na to, jake porty se opakovaly v tich connections
                    // proto kdyz klient se pripojuje a dostane socket descriptoru od socket(), tak by se melo udelat setsockopt(), protoze kdyz server se pripojoval na klienta (PORT), tak server vyhodil error transport endpot is alreadu connected => client at fault 
                    // By default, the kernel will not reuse any in-use port for an ephemeral port, which may result in failures if you have 64K+ simultaneous ports in use.
                    int yes = 1;
                    printf("\nftp_sockets_obj.ftp_data_socket: %d", ftp_user_info.ftp_sockets_obj.ftp_data_socket);
                    fflush(stdout);
                    if ( setsockopt(ftp_user_info.ftp_sockets_obj.ftp_data_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &yes, sizeof(yes)) == -1) {
                        perror("setsockopt() selhal - handle_command_function - PASV");
                        exit(EXIT_FAILURE);
                    }

                    toto vsechno bylo kvuli tomu, ze to bylo poor maintenace a prehled o socketech
                    jinak OS kernel prideluje ephemeral porty (docasne porty), ktere nejsou v TIME_WAIT, pokud by vsechny byly vTIME_WAIT, tak by nejspis TCP (bind() nebo connect() vyhodilo error) a nepustilo by me to dal
                    proto pokud bych chtel reusovat ty porty, tak bych musel nejak pouzit SO_REUSEADDR (to pusobi na IP odkud:ephemeral port), takze bych musel explicitne bind() nejakou local adresu a udelat jeste pred tim setsockopt() SOL_SOCKET, SO_REUSEADDR

                }*/
                
                if (fcntl(ftp_user_info.ftp_sockets_obj.ftp_data_socket, F_SETFL, O_NONBLOCK) == -1) {
                    perror("fcntl() selhal - neslo nastavit O_NONBLOCK - handle_command_function");
                    exit(EXIT_FAILURE);
                }

                clock_t timeout = clock();
                double difference = 0;
                int return_value;
                while(1) {
                    // ftp_user_info.server_data_info.sin_port = htons(DATA_PORT);
                    return_value = connect(ftp_user_info.ftp_sockets_obj.ftp_data_socket, (struct sockaddr *)&ftp_user_info.server_data_info, sizeof(ftp_user_info.server_data_info)); // 127.0.0.1:21 => port 21 = data connection)
                    printf("\n\nted se to stalo");
                    fflush(stdout);
                    if (return_value == 0) {
                        printf("\n\n\n\n\nJOOOOOOO AVE CHRISTUS REX\n\n\n\n");
                        ftp_user_info.ftp_sockets_obj.ftp_data_com = ftp_user_info.ftp_sockets_obj.ftp_data_socket;
                        fflush(stdout);
                        break;
                    }
                    else if (return_value == EINPROGRESS || difference >= 5) {
                        perror("connect() selhal 0 EINPROGRESS - nejde to udelat hned - handle_command_function");
                        exit(EXIT_FAILURE);
                    }
                    else if (return_value == EAGAIN || return_value == EALREADY) {
                        clock_t time_right_now = clock();
                        difference = (double)(time_right_now - timeout) / CLOCKS_PER_SEC;
                        continue;
                    }
                }
            }
            else {
                if (errno == 0) {
                    fprintf(stderr, "530 - Not logged in");
                }
                else {
                    perror("nekde se naskytl error - handle_command_function - PASV");
                    exit(EXIT_FAILURE);
                }
            }  
        }

        // printf("\nftp_data_com: %d", ftp_user_info.ftp_sockets_obj.ftp_data_com);
        if (ftp_user_info.user_loggedin == 1) {
            // if (fcntl(ftp_user_info.ftp_sockets_obj.ftp_data_com, F_SETFL, O_NONBLOCK) == -1) {
            //     perror("fcntl() selhal - neslo nastavit O_NONBLOCK - handle_command_function");
            //     exit(EXIT_FAILURE);
            // }

            evutil_make_socket_nonblocking(ftp_user_info.ftp_sockets_obj.ftp_data_com);

            ftp_user_info.event_timeout_data = event_new(ftp_user_info.evbase_data, ftp_user_info.ftp_sockets_obj.ftp_data_com, EV_PERSIST | EV_TIMEOUT, reset_timeval_struct_data, NULL);
            event_add(ftp_user_info.event_timeout_data, &ftp_user_info.timeout_data);

            ftp_user_info.bufevent_data = bufferevent_socket_new(ftp_user_info.evbase_data, ftp_user_info.ftp_sockets_obj.ftp_data_com, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE); // BEV_OPT_UNLOCK_CALLBACKS - toto chce defaultne dereffered callbacks
            if (ftp_user_info.bufevent_data == NULL) {
                perror("bufevent_data selhal - handle_command_function - PORT/PASV");
                exit(EXIT_FAILURE);
            }
            printf("\n\n\nnovy bufferevent_socket_new()");
            fflush(stdout);

            void (*bufevent_event_data)(struct bufferevent *bufevent_both, short events, void *ptr_arg) = &bufevent_event_cb_data;
            void (*bufevent_write_data)(struct bufferevent *bufevent_data, void *ptr_arg) = &bufevent_write_cb_data;
            void (*bufevent_read_data)(struct bufferevent *bufevent_data, void *ptr_arg) = &bufevent_read_cb_data;

            bufferevent_setcb(ftp_user_info.bufevent_data, bufevent_read_data, bufevent_write_data, bufevent_event_data, NULL);
            bufferevent_enable(ftp_user_info.bufevent_data, EV_READ | EV_WRITE); // event base pro bufferevent


            void *(*f_thread_callback_func)(void *) = thread_callback_func;
            pthread_t callback_thread;

            printf("\n\n\npred pthread_create()");
            fflush(stdout);

            if ( pthread_create(&callback_thread, NULL, f_thread_callback_func, NULL) != 0) {
                perror("pthread_create() selhal - handle_command_function - PORT/PASV");
                exit(EXIT_FAILURE);
            }
            pthread_detach(callback_thread);
        }
        // printf("\ndata_queue file descriptor: %d", ftp_user_info.data_queue);
    }
    else if (strstr(command, "TYPE") != NULL) {
        // printf("\nftp_user_info.ftp_data_representation: %d", ftp_user_info.ftp_data_representation);
        fflush(stdout);

        if (strstr(command, "IMAGE") != NULL) {
            puts("200 - command okay");
            ftp_user_info.ftp_data_representation = IMAGE;
        }
        else {
            puts("504 - Command not implemented for that parameter - no change");
            // ftp_user_info.ftp_data_representation = ASCII;
        }
        // printf("ftp_user_info.ftp_data_representation: %d", ftp_user_info.ftp_data_representation);
        fflush(stdout);
    }
    else if (strstr(command, "PWD") != NULL){
        printf("\n257 '%s'\n", ftp_user_info.curr_dir);
        fflush(stdout);
    }
    else if (strstr(command, "MKD") != NULL) {
        char *temp_path = extract_path_command(command);

        if (strcmp(temp_path, ftp_user_info.curr_dir) == 0) {
            free(temp_path);
            fprintf(stderr, "\nbud user zadal working directory nebo nebyla zadana zadna path\n");
            fflush(stdout);
        }
        else {
            char *path = path_to_open(temp_path, 0);
            if (path != NULL) {
                struct stat check_if_exists;
                if (stat(path, &check_if_exists) == -1) {
                    if (errno == ENOENT) { // no such file or directory
                        // mode_t mode JE POTREBA ZAPSAT V OCTAL TAKZE POKUD NORMALNI PERMISE => 4 CISLA => 0777, POKUD PLUS SPECIAL BITS => 5 CISEL => 01777
                        // sticky bit nejde nejak odstranit s permisemi tohoto programu, proto vytvarim jenom s normalnimi permisemi, ale bez special bits
                        // proto si musim davat pozor na to abych tam dal 0 jako OCTAL a ne rovnou ty permise jinak se to udela takhle: 
                        if (mkdir(path, 0777) == -1) { // 4777 se vezme jako dec na binary AND oct 777 na binary => AND NOT octal na binary umask (002) => + pry pridani specialnich bits (jako sticky bit apod. nazpatek) => permise
                            // pokud ma slozka ticky bit (a asi dalsi special bits, tak to bude barevne v terminalu)
                            perror("mkdir() selhal - handle_command_function");
                            
                            free(temp_path);
                            free(path);
                            free_all();
                        }
                        printf("\n257 - %s\n", path); // ftp code prave pro mkd nebo pro pwd
                    }
                    else {
                        perror("stat() selhal - handle_command_function");
                        free(temp_path);
                        free(path);
                        free_all();
                    }    
                }
                else { // S_ISDIR(check_if_exists.st_mode) != 0
                    fprintf(stderr, "\nDirectory %s already exists\n", path);
                    fflush(stderr);
                }        
                // 257
            }
            else {
                fprintf(stderr, "\nUser zadal spatnou, jiz existujici path\n");
                fflush(stderr);
            }
        }
    }
    else if (strstr(command, "RMD") != NULL) {
        char *temp_path = extract_path_command(command);

        if (strcmp(temp_path, ftp_user_info.curr_dir) == 0) {
            free(temp_path);
            fprintf(stderr, "\nbud user zadal working directory nebo nebyla zadana zadna path\n");
            fflush(stdout);
        }
        else {
            char *path = path_to_open(temp_path, 0);
            if (path != NULL) {
                if (strcmp(path, ftp_user_info.curr_dir) == 0) { // tady to musi byt 
                    free(temp_path);
                    fprintf(stderr, "\nbud user zadal working directory nebo nebyla zadana zadna path\n");
                    fflush(stdout);
                }
                else {
                    if ( rmdir(path) == -1) {
                        if (errno == ENOENT) {
                            fprintf(stderr, "\nRMD - spatna path - slozka %s neexistuje\n", path);
                            fflush(stderr);
                        }
                        else {
                            perror("rmdir() selhal - handle_command_function");
                        
                            free(temp_path);
                            free(path);
                            free_all();
                        }
                    }
                    free(temp_path);
                    free(path);
                }
            }
            else {
                fprintf(stderr, "\nUser zadal spatnou path\n");
                fflush(stderr);
            }
        }   
    }
    else if (strstr(command, "NOOP") != NULL) {
        puts("200 - command okay");
        send_message_queue(ftp_user_info.control_queue, command, strlen(command) + 1, "mq_send() selhal - handle_command_function - NOOP");
        send_ftp_commands(ftp_user_info.bufevent_control); // send to the server
        // puts("NOOP tady je\n");
    }
    else if(strstr(command, "CDUP") != NULL) {
        printf("\n\nftp_user_info.curr_dir: %s\n\n\n", ftp_user_info.curr_dir);
        fflush(stdout);
        if (ftp_user_info.curr_dir != NULL) {
            free(ftp_user_info.curr_dir);
        }
        ftp_user_info.curr_dir = strdup("/tmp/ftp_server/"); // musi tam byt to posledni /, protoze od toho se potom odvijeji paths
        
       
    }
    // !Christ Is God!
    else if (strstr(command, "LIST") != NULL) {
        // ls -g, protoze nechci, aby tam bylo videt, ze to vytvoril root
        // kdyz se da LIST ~, tak se vyobrazi slozka '~', coz by nemelo ale asi je to stejne jako to . a ..
        if (is_command_ok(command) == 1) {
            // ftp_user_info.curr_dir = strdup("/tmp/ftp_server");

            char *temp_path = extract_path_command(command); // toto neplati uz (V TOMTO PRIPADE SE NESMI UDELAT FREE(TEMP_PATH), PROTOZE SE VRATI FTP_USER_INFO.CURR_DIR A POKUD BY SE TO DEALOKOVALO, TAK BY TO VYHODILO ERROR, COZ ASAN A VALGRIND A NORMALNI CMD VYHODILO SIGSEV, PROTOZE UZ DANY STRING LITERAL NENI PODLE MALLOC, TAKZE NEMUZE BYT ANI MALLOCEM DEALOKOVANY!)
            char *path = path_to_open(temp_path, 0); // 0 protoze se pracuje s directories
            if (path != NULL) {
                // printf("\n\npath: %s, path_len: %zu\n", path, (strlen(path) + strlen("ls -gA ") + 1) );
                printf("temp_path: %s, path: %s", temp_path, path);
                fflush(stdout);

                // protoze popen() vola shell a az ten shell vola ten program a proto vytvari shell proces, je nachylny na utoky, pokud je to input od usera, pomaly, nedokaze chytat errory, jenom je vypise, ma pouze jednosmernou komunikaci, tak misto toho se pouziva fork() + exec() rodina = exec() rodina vezme celou memory oblast a uvolni/prepise ji na to, co je potreba pro running toho noveho programu, takze je to uspornejsi, rychlejsi, nevytvari to shellovy proces, errory se daji zachytit a proste lepsi

                int pipefds_st[2];
                if (pipe(pipefds_st) == -1) {
                    perror("pipe() selhal - handle_command_function - LIST");
                    free_all();
                }
                // close(pipefds_st[1]); // tady nesmi to zatim byt, protoze pokud by se udelal novy proces, tak i ten by mel closenutou write cast, takze by to nemohl posilat
                // stdin se zablokuje tim ze se otevre /dev/null
                // nejsem si jisty, proc jsem pred tim dostaval SIGTTIN, ale stdin se nejspise nemusi resit dokud v commandu bude to -c

                pid_t child_process_len;
                int status_len;
                if ( (child_process_len = fork()) == 0) {
                    // -c = command string => jeden velky string
                    char *part_of_command = (char *)malloc(strlen("ls -gA | wc -m") + strlen(path) + 2); // wc -m pocita charaktery a pomoci pipe se to da presmerovat prave do wc -m jako input
                    if (part_of_command == NULL) {
                        perror("malloc() selhal - handle_command_function");
                        free_all();
                    }
                    memset(part_of_command, 0, strlen("ls -gA | wc -m") + strlen(path) + 2); // automaticke NULL ukonceni potrebne i pro execv

                    snprintf(part_of_command, strlen("ls -gA | wc -m") + strlen(path) + 2, "ls -gA %s | wc -m", path);
                    char *argv[] = {"sh", "-c", part_of_command, NULL}; // nedela se free(), protoze to neni alokovane pomoci malloc(), bez NULL to taky funguje, ale melo by tam byt NULL

                    int fd = open("/dev/null", O_WRONLY);
                    if (fd == -1) {
                        perror("open() selhal - handle_command_function");
                        free_all();
                    }

                    // Pipe bude hangovat pokud se neuzavrou potrebne konce pipes:
                    // write() do pipe se neudela dokud se neuzavrou vsechny read konce pipes
                    // read() se neudela dokud se neuzavrou vsechny konce write() pipes

                    // v exec() se vsechny sockety vezmou od parenta a zkopiruji se child, takze se muze udelat FD_CLOEXEC, to zavre ty dane descriptory, na kterych je ten flag dany, ale kazdopadne, po skonceni procesu, OS uzavre vsechny socket decriptory, takze nebude zadny leak

                    close(pipefds_st[0]);
                    if (dup2(fd, STDIN_FILENO) == -1) {
                        perror("dup2() selhal - handle_command_function");
                        free_all();
                    }

                    if ( dup2(pipefds_st[1], 1) == -1) { // stdout_fileno
                        perror("dup2() selhal - handle_command_function");
                        free_all();
                    }

                    // jakykoliv printf() od ted nepujde na stdout ale do pipe[1] a pokud to nebude nejake cislo, tak atoi() to nevezme a vrati 0 => muze se zdat jako error (undefined behaviour => platform defined)

                    if (dup2(pipefds_st[1], 2) == -1) { // stderr_fileno
                        perror("dup2() selhal - handle_command_function");
                        free(part_of_command);
                        free_all();
                    }

                    if ( close(pipefds_st[1]) == -1) { // je to prakticky jedno, reference count je vice nez 1, takze nebude problem, pokud bych udelal close pipefds[1] i prislusne sockets, tak by to bylo undefined behaviour
                        perror("close() selhal - handle_command_function");
                        free(part_of_command);
                        free_all();
                    }

                    // jaky program, jmeno programu => sh je defaultni shell => dash => symbolicky link na bash
                    // pokud bych napsal jenom dash, tak by se to cetlo z stdin, -c udela aby se to precetlo z toho stringu
                    // execl("/bin/sh", "sh", "-c", "ls", "-l", (char *)NULL

                    if (execv("/bin/sh", argv) == -1) {
                        perror("execv() selhal - handle_command_function - LIST"); // execv() vrati jenom pokud je error
                        free_all();
                    }
                }
                waitpid(child_process_len, &status_len, 0); // 0 nikde v tutorialech napsana neni, jenom ze se to chova jako wait... 0 blokuje dokud child neskonci

                if (WIFEXITED(status_len)) {
                    printf("\n\nok\n\n");
                }
                close(pipefds_st[1]);

                char buf_for_len[10] = {0};
                ssize_t bytes_read_now;
                // bytes_read_now = read(pipefds_st[0], buf_for_len, 9999);
                while ( (bytes_read_now = read(pipefds_st[0], buf_for_len, 9)) > 0) { // 0 = end of file, -1 = error
                    if (bytes_read_now == 0) {
                        fprintf(stderr, "read() - EOF - handle_command_function - LIST");
                        fflush(stderr);
                    }
                    else if (bytes_read_now == -1) {
                        perror("read() selhal - handle_command_function - LIST");
                        free_all();
                    }
                }
                close(pipefds_st[1]);

                int command_read_len = atoi(buf_for_len);
                // printf("\ncommand_read_len: %d", command_read_len);
                fflush(stdout);


                char *list_command_answer = (char *)malloc(command_read_len + 1);
                memset(list_command_answer, 0, command_read_len + 1);
                if (list_command_answer == NULL) {
                    perror("malloc() selhal - handle_command_function - LIST");
                    free_all();
                }

                int pipefds_nd[2];
                if (pipe(pipefds_nd) == -1) {
                    perror("pipe() selhal - handle_command_function - LIST");
                    free_all();
                }

                pid_t child_process;
                if ( (child_process = fork()) == 0) {
                    char *part_of_command = (char *)malloc(strlen("ls -gA") + strlen(path) + 2);
                    if (part_of_command == NULL) {
                        perror("malloc() selhal - handle_command_function");
                        free_all();
                    }
                    memset(part_of_command, 0, strlen("ls -gA") + strlen(path) + 2);

                    snprintf(part_of_command, strlen("ls -gA") + strlen(path) + 2, "ls -gA %s", path);
                    char *argv[] = { "sh", "-c", part_of_command, NULL}; // pole ukazatelu, muze tam byt i promenna jako sama o sobe
                    // ale nebude fungovat s pole[5][10], protoze to je continuous pole dat, tak tam nejsou pointery, exec() to nevezme

                    // pipefds_nd[1] = write() do "virtualniho souboru"
                    // pipefds_nd[0] = read() z "virtualniho souboru"
                    if ( dup2(pipefds_nd[1], STDOUT_FILENO) == -1) { // udela kopii file descriptoru ze kdyz a = b, tak b = a, proto kdyz se udela treba print() do b, tak je to stejne jako print() do a
                        perror("dup2() selhal - handle_command_funtion");
                        free(part_of_command);
                        free_all();
                    }

                    if (dup2(pipefds_nd[1], STDERR_FILENO) == -1) {
                        perror("dup2() selhal - handle_command_function");
                        free(part_of_command);
                        free_all();
                    }

                    // execv() vrati jenom pokud je error 
                    if (execv("/bin/sh", argv) == -1) { // v jako vector => array
                        perror("execv() selhal - handle_command_function - LIST");
                        free(part_of_command);
                        free_all();
                    }
                }
                waitpid(child_process_len, &status_len, 0);
                close(pipefds_nd[1]);

                bytes_read_now = 0;
                while ( (bytes_read_now = read(pipefds_nd[0], list_command_answer, command_read_len)) > 0) { // 0 = end of file, -1 = error
                    if (bytes_read_now == 0) {
                        fprintf(stderr, "read() - EOF - handle_command_function - LIST");
                        fflush(stderr);
                    }
                    else if (bytes_read_now == -1) {
                        perror("read() selhal - handle_command_function - LIST");
                        free_all();
                    }
                }
                

                printf("\nLIST output: %s\n", list_command_answer);
                fflush(stdout);

                // pokud je slozka prazdna
                if (!strcmp(list_command_answer, "total 0") && strlen(list_command_answer) != 8) { // protoze terminal vyplyvne 'total 0\n' => 8
                    printf("\nLIST output: %s\n", list_command_answer);
                    fflush(stdout);
                }

                free(list_command_answer);
                free(temp_path);
                free(path);
                // ftp_user_info.curr_dir = strdup("/tmp/"); // neudela memory leak protoze se to odkazuje na string literal,ztrati se ukazatel na ten string literal, ale neni to memory leak, protoze to je string literal
                // free_all();
            }
            else {
                fprintf(stderr, "\nUser zadal spatnou path\n");
                fflush(stderr);
            }
        }
        else {
            fprintf(stderr, "LIST command ma spatny format\n");
            fflush(stderr);
        }       
    }
    else if (strstr(command, "CD") != NULL) {
        
        char *temp_path = extract_path_command(command);
        char *path = path_to_open(temp_path, 0);

        if (path != NULL) {
            struct stat exists;
            if (stat(path, &exists) == -1) {
                if (errno == ENOENT) {
                    printf("\nCD - slozka %s neexistuje\n");
                    fflush(stdout);
                }
                else {
                    perror("stat() selhal - handle_command_function - CD");

                    free(temp_path);
                    free(path);
                    free_all();
                }
            }
            else {
                if (ftp_user_info.curr_dir != NULL) {
                    free(ftp_user_info.curr_dir);
                }
                ftp_user_info.curr_dir = strdup(path);        
            }
        }
        else {
            fprintf(stderr, "\nUzivatel zadal spatnou path\n");
            fflush(stderr);
        }
    }
    else if (strstr(command, "RETR") != NULL || strstr(command, "STOR") != NULL) { // tady se otevre datova message queue //  && ftp_user_info.loggedin_info == 1
        if (ftp_user_info.bufevent_data != NULL) {
            if (strstr(command, "RETR") != NULL) {
                if (is_command_ok(command) != 1) {
                    fprintf(stderr, "RETR command ma spatny format", command);
                    exit(EXIT_FAILURE);
                }
                char *temp_path = extract_path_command(command);
                char *filename = get_file_name(temp_path);
                char *path = path_to_open(temp_path, 1);

                if (path != NULL) {
                    printf("\n\n\n \x1b[32mTady je temp_path: %s, tady je path: %s \xb1[0m", temp_path, path);
                    fflush(stdout);


                    // if (check_path(path) == 0) {
                    //     fprintf(stderr, "\nUzivatel chce na jinou slozku - directory traversal attack - denied\n");
                    //     exit(EXIT_FAILURE);
                    // }

                    // char *path_for_saving = (char *)malloc()


                    // informovani datove casti programu => DTP
                    send_message_queue(ftp_user_info.data_queue, path, strlen(path) + 1, "mq_send() selhal - handle_command_function - RETR");

                    // i kdyz je to nejaky command, ktery prakticky nic nedela, tak se musi posilat serveru, aby i server vedel o co go, pokud je to command s path nebo tak neco tak vetsinou se to posle na control connection cele
                    // char *new_command = insert_crlf(command);

                    char *command_path_info = (char *)malloc(strlen("RETR \r\n") + strlen(path) + 1); // +1 pro \0
                    memset(command_path_info, 0, strlen("RETR \r\n") + strlen(path) + 1);
                    snprintf(command_path_info, strlen("RETR \r\n") + strlen(path) + 1, "RETR %s\r\n", path); // uz rovnou s crlf, ale mohlo by se pouzit funkce insert_crlf

                    printf("\n\n\ncommand_path_info: %s", command_path_info);

                    send_message_queue(ftp_user_info.control_queue, command_path_info, strlen(command_path_info) + 1, "mq_send() selhal - handle_command_function");

                    free(temp_path);
                    free(path);
                }
                else {
                    fprintf(stderr, "\nUzivatel zadal spatnou path\n");
                    fflush(stderr); 
                }
            }
            if (strstr(command, "STOR") != NULL) {
                // STOR filename = klient posle soubor, pod nejakym nazvem, pod timto nazvem se ten soubor ulozi i na serveru, to ale nemuzu udelat, protoze ftp server hostuju na svem pocitaci, takze to ulozim do /tmp pod stejny nazvem, dobre by bylo udelat kazdemu userovi nejakou vlastni slozku
                if (is_command_ok(command) != 1) {
                    fprintf(stderr, "STOR command ma spatny format", command);
                    exit(EXIT_FAILURE);
                }
                char *temp_path = extract_path_command(command);
                char *filename = get_file_name(command);
                char *path = path_to_open(temp_path, 1);

                if (path != NULL) {
                    // printf("\ndata_queue file descriptor: %d, path:%s", ftp_user_info.data_queue, path);
                    // fflush(stdout);
                    
                    char *contents = read_contents_ftp(path);
                    printf("\n\n\n\nCONTENTS: %s", contents);
                    fflush(stdout);
                    data_send_ftp(ftp_user_info.bufevent_data, contents);

                    char *data_to_send = (char *)malloc(strlen(path) + strlen("STOR\r\n") + 2); // 1 pro mezeru a jedna pro \0
                    memset(data_to_send, 0, strlen(path) + strlen("STOR\r\n") + 2);
                    snprintf(data_to_send, strlen(path) + strlen("STOR\r\n") + 2, "STOR %s\r\n", path);

                    printf("\n\n\n\n\ndata_to_send: %s", data_to_send);
                    fflush(stdout);

                    send_message_queue(ftp_user_info.control_queue, data_to_send, strlen(data_to_send) + 1, "mq_send() selhal - handle_command_function");

                    free(temp_path);
                    free(path);
                }
                else {
                    fprintf(stderr, "\nUzivatel zadal spatnou path\n");
                    fflush(stderr);
                }
            }

            // posilani message
            send_ftp_commands(ftp_user_info.bufevent_control); // send to the server
        }
        else {
            puts("530 - Not logged in");
        }
    }
    else {
        // errno ma hodnotu 0, pokud je vse ok, pokud je to rozdilne, tak nekde nastala chyba
        if (errno != 0) {
            perror("nekde se vyskytla chyba - nejspise spatne zadany command - handle_command_function");
        }
        else {
            fprintf(stderr, "zadany command nepotrebuje explicitni funkci nebo nejste prihlaseni a chcete pouzit command s data pripojenim\n");
            fflush(stdout);
        }        
    }
}

void *entering_commands(void *arg) {
    ftp_user_info.user_request = (char *)malloc(100);
    zero_memory(ftp_user_info.user_request); // automaticky NULL terminated

    // struct mq_attr ma;
    // ma.mq_flags = 0;
    // ma.mq_maxmsg = 16;
    // ma.mq_msgsize = 50;
    // ma.mq_curmsgs = 0;


    struct mq_attr attr;
    mq_getattr(ftp_user_info.control_queue, &attr);
    printf("\n\n tady jsou ty udaje: %ld %ld %ld %ld", attr.mq_curmsgs, attr.mq_msgsize, attr.mq_curmsgs, attr.mq_flags); // mozna nejake threads chteji otevrit stejnou frontu => blokuji ji?
    fflush(stdout);

    puts("+-----------------------------------------+");
    puts("| AVE CHRISTUS REX FTP server implements: |");
    puts("|                                         |");
    puts("| DATA REPRESENTATION: ASCII NONPRINT (N) |");
    puts("| TRANSMISSION MODE  : STREAM             |");
    puts("| DATA STRUCTURE     : FILE-STRUCTURE     |");
    puts("| COMMANDS: USER, PASS, QUIT, PORT, PASV  |");
    puts("|           RETR, STOR, NOOP, TYPE        |");
    puts("+-----------------------------------------+");

    puts("+------------------------------------------------+");
    puts("| USER string = log in - necessary 1st command!  |"); // 2
    puts("| PASS string = log in - necessary 2nd command!  |"); // 2
    puts("| QUIT        = log out (teminate control con.)  |"); // 1
    puts("| PORT        = server -> client data con.       |"); // 7
    puts("| PASV        = client -> server data con.       |"); // 0
    puts("| RETR        = retrieve last specified file by  |"); // 1
    puts("| STOR        = send a file to server            |"); // 2
    puts("| NOOP        = server will send OK code & msg   |"); // 1
    puts("| TYPE        = ASCII N(on-print)/Image (bits)   |"); // 3
    puts("+------------------------------------------------+");

    // transmission mode - stream indikuje EOF jako ukonceni konekce, dalsi soubor musi na dalsi konekci, ale pozor toto muzeme delat, jenom kdyz mame tu socket adresu muzeme reusovat a ze se nema cekat na ten TCP delay
    // kdyz se ukonci TCP socket, tak se jeste TIME_WAIT chvilku bude cekat nez prijde ACK od druheho hosta, aby oba vedeli, ze ta konekce bude ukoncena
    puts("\nDATA STRUCTURE      = file-structure (contiguous bits)");
    // transmission mode definovano takhle, protoze kdyby to bylo block, tak to by odpovidalo TCP s Nagle algorithm a stream by bylo TCP bez Nagle algorithm => jakoby nonblocking
    puts("TRANSMISSION MODE   = stream (with Nagle algortithm - TCP segments will wait for data to be as full)");
    puts("DATA REPRESENTATION = ASCII Non-print (only ASCII chars)/Image (bit data)");

    while(1) {
        printf("\nName: ");
        scanf(" %97[^\n]", ftp_user_info.user_request); // %99[^\n] chceme cist maximalne 99 charakteru, protoze +1 pro \0 a chceme cist vsechny charaktery nez nenarazime na \n, potom uz to nechceme cist a nebudeme to cist \n, mezera mezi " a % znamena, ze chceme ignorovat kazdy whitespace v stdout bufferu (vsechny znaky, ktere kdyz vyprintujeme, tak proste nemaji ten normalni charakter)
        // control_send_ftp(ftp_user_info.bufevent_control);
        int resolution1 = partial_login_lookup(ftp_user_info.user_request, 0); // 0 - username, 1 = password
        ftp_user_info.user_request = insert_crlf(ftp_user_info.user_request);

        // if ( mq_send(ftp_user_info.control_queue, user_request, strlen(user_request) + 1, 31) == -1) {
        //     perror("mq_send() selhal - control_send_ftp");
        //     exit(EXIT_FAILURE);
        // }
        zero_memory(ftp_user_info.user_request);

        printf("Password: ");
        scanf(" %97[^\n]", ftp_user_info.user_request);
        int resolution2 = partial_login_lookup(ftp_user_info.user_request, 1);
        ftp_user_info.user_request = insert_crlf(ftp_user_info.user_request);
        // control_send_ftp(ftp_user_info.bufevent_control);

        // if ( mq_send(ftp_user_info.control_queue, user_request, 100, 31) == -1) { // strlen(user_request) + 1
        //     perror("mq_send() selhal - control_send_ftp");
        //     exit(EXIT_FAILURE);
        // }
        zero_memory(ftp_user_info.user_request);
        // tento socket bude blocking, protoze budeme vzdy cekat na odpoved od serveru
        // nedela nic specialniho; pokud bude false, tak se to ukonci; nedela nic specialniho

        if (resolution1 == 0 && resolution2 == 0) { 
            puts("230 - User logged in, proceed");
            puts("220 -    Service ready for new user");

            // posilani serveru informace o clientu
            // printf("\n\nlength strlen(ftp_user_info.username) + strlen(ftp_user_info.password) + strlen(&<>&): %zu", strlen(ftp_user_info.username) + strlen(ftp_user_info.password) + strlen("&<>&"));
            char *temp_conformation = (char *)malloc(strlen(ftp_user_info.username) + strlen(ftp_user_info.password) + strlen("&<>&") + 3);
            memset(temp_conformation, 0, strlen(ftp_user_info.username) + strlen(ftp_user_info.password) + strlen("&<>&") + 3);
            snprintf(temp_conformation, strlen(ftp_user_info.username) + strlen(ftp_user_info.password) + strlen("&<>&"), "%s&<>&%s", ftp_user_info.username, ftp_user_info.password); // zapise vsechny bytes toho stringu bez \0 a na konci se to zakonci \0
            temp_conformation = insert_crlf(temp_conformation);

            control_send_account_info(ftp_user_info.bufevent_control, temp_conformation);

            ftp_user_info.user_loggedin = 1;

            if (ftp_user_info.dd != NULL) {
                free(ftp_user_info.dd);
            }
            char *temp_dd = (char *)malloc(strlen("/tmp/ftp_server/") + strlen(ftp_user_info.username) + 2); // /tmp/ftp_server/username/\0 => +2
            if (temp_dd == NULL) {
                free_all();
            }

            memset(temp_dd, 0, strlen("/tmp/ftp_server/") + strlen(ftp_user_info.username) + 2);
            snprintf(temp_dd, strlen("/tmp/ftp_server/") + strlen(ftp_user_info.username) + 2, "/tmp/ftp_server/%s/", ftp_user_info.username);
            
            if (ftp_user_info.dd == NULL) {
                ftp_user_info.dd = strdup(temp_dd);
            }
            else {
                free(ftp_user_info.dd);
                ftp_user_info.dd = strdup(temp_dd);
            }
            free(temp_dd);
            break;
        }
        else if (resolution1 == 0 || resolution2 == 0) {
            puts("430 - Invalid username or password");
        }
        else {
            puts("535 - Failed security check");
        }
    }

    // one (or more) whitespace characters validates (UZNA/AKCEPTUJE) jeden/zadny/vice nez jeden WHITESPACES IN THE INPUT STRING, toto chovani maji jako %d, %f, %s => a toto znamena, ze muze ignorovat whitespaces v input stringu jako 10       10 => a=10, b=20, toto chovani nemaji implicitne %c a %[], k dosazeni toho stejneho chovani musime dat whitespace do format stringu, tim se explicitne "zapne" toto chovani
    // %c => a\n, vezme se jenom a, \n zustane v stdin bufferu, proto pro dalsi pouzivani funkce je nutno scanf(" %c"), pro zapnuti validace whitespaces
    // kazdy system maji jiny zpusob, jak oznacit novy radek, nekdo to ma \r\n, nekdo \n, nekdo \r, proto se udelalo to, ze kdyz nejaky source code ma v sobe \n, tak by to melo znamenat novy radek pro vsechny systemy, takova interpretace noveho radku, ale pokud je to zapsane ve file, tak to uz je jine, protoze si pise pouze to, co je v tom bufferu, proto nejake files budou zobrany jinak na jinych systemech

    while (1) {
        // telnet commands jsou ukonceny <CRLF> 13, 10 a ftp code jsou terminated <space> 32
        if (ftp_user_info.user_request != NULL) { // neni NULL, ale plne 0x00
            // cisteni vstupu, protoze v nem zustavalo \n
            free(ftp_user_info.user_request);
            ftp_user_info.user_request = (char *)malloc(100); // nemuzu pouzit ani strdup() ani NULL, protoze strdup("") by alokoval jenom 1 Byte, kdyby bylo scanf => buffer overflow, pokud NULL => scanf => cteni do 0x00000..., nejde SIGSEV
            memset(ftp_user_info.user_request, 0, 100);

            // ftp_user_info.user_request = strdup("");
            // free(ftp_user_info.user_request);
            // ftp_user_info.user_request = NULL;
        }

        printf("[%s] $ ", ftp_user_info.curr_dir);
        fflush(stdout);
        scanf(" %99[^\n]", ftp_user_info.user_request);
        printf("\nuser_request: %s", ftp_user_info.user_request);

        ftp_user_info.user_request = insert_crlf(ftp_user_info.user_request);
        // printf("\n\nuser_request: %s, non_terminated_request: %s", user_request, non_terminated_request);
        // fflush(stdout);
        printf("\nuser_request: %s", ftp_user_info.user_request);
        handle_command_function(ftp_user_info.user_request);

    }

    // free_all();
    /*
    case USER_LOGGEDIN:
        continue; // nemusi byt break, protoze se rovnou skoci na dalsi iteraci toho for loopu (udelala by se i kdyztak inkrementace u toho for loopu)
    */
}

void *setup_con_buf() {
    printf("\n\nsetup_con_buf");
    fflush(stdout);

    // pokazde kdyz se client pripoji, tak dostane novy nahodny port od OS, proto musi server udelat setsockopt SO_REUSABLE, protoze server nemenni port a binduje
    // ten stejny
    // client zahajuje control connection u FTP, potom se muze rozhoudnout, jestli zahaji server nebo client data connection
    // int ftp_control_com; // vytvori se jakoby zakladni socket descriptor popisujici, ze bude komunikace pres sit a potom pomoci connect
    // se klientovi priradi ten nahodny ephemeral port a ten socket descriptor se jakoby zmeni na communication socket descriptor
    // socket take zalozi interni strukturu o tomto pripojeni

    // 0 => OS vybere nejlepsi protokol pro ty specifikace, jinak ty protokoly jsou definovane v glibc netine/in.h
    int optval = 1;
    if (setsockopt(ftp_user_info.ftp_sockets_obj.ftp_control_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT , (char *)&optval, sizeof(optval)) == -1) { // IPPROTO_TCP, TCP_NODELAY
        perror("setsockopt() selhal - setup_con_buf");
        exit(EXIT_FAILURE);
    }
    // client nemusi mit setsockopt SO_REUSEADDR, protoze se binduje k nejakemu stanovemu portu, client ma svuj lokalni port, takze se vzdycky zmeni
   
   /*
    grep -i "in_addr_t" /usr/include/netinet/in.h
    typedef uint32_t in_addr_t;
   */

    // u connect to musi byt oboustranne dane zavorkami, protoze == ma vetsi prioritu nez =
    // (**) se z toho stane struktura, (**) je dereference jako (*(*ptr))
    // blocking, protoze client zacina control connection
    if ( connect(ftp_user_info.ftp_sockets_obj.ftp_control_socket, (struct sockaddr *)&ftp_user_info.server_control_info, sizeof(ftp_user_info.server_control_info)) == -1 ) { // () meni poradi operandu
        perror("connect() selhal - setup_con_buf");
        exit(EXIT_FAILURE);
    }
    ftp_user_info.ftp_sockets_obj.ftp_control_com = ftp_user_info.ftp_sockets_obj.ftp_control_socket;

    // printf("=== Connection ftp_control_com: %d ===", ftp_user_info.ftp_sockets_obj.ftp_control_com);
    // send(ftp_user_info.ftp_sockets_obj.ftp_control_com, "ahoj", 10, 0);

    char errstr[50] = {0};
    if (ftp_user_info.control_queue == -1 || ftp_user_info.data_queue == -1) {
        ftp_user_info.control_queue = mq_open(CONTROL_QUEUE_NAME, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID, &global_mq_setting); // pokud jeste ta queue neni vytvorena, tak to bude blokovat

        if (ftp_user_info.control_queue == -1) {
            strerror_r(errno, errstr, 50);
            printf("\n%s\n");
            fflush(stdout);
            perror("mq_open() selhal - setup_con_buf");
            exit(EXIT_FAILURE);
        }

        ftp_user_info.data_queue = mq_open(DATA_QUEUE_NAME, O_CREAT | O_RDWR, S_IRWXU | S_IRWXO | S_IRWXG | S_ISUID, &global_mq_setting); // 4777
        if (ftp_user_info.data_queue == -1) {
            perror("mq_open() selhal - handle_command_function");
            exit(EXIT_FAILURE);
        }

        // printf("\n\n\n\n\n\n\n\n\n\n\n\nDATA_QUEUE - handle_command_function: %d", ftp_user_info.data_queue);
        fflush(stdout);
    }

    ftp_user_info.evbase_control = event_base_new();
    ftp_user_info.evbase_data = event_base_new();

    if (ftp_user_info.evbase_control == NULL) {
        perror("event_base_new() selhal - setup_con_buf - evbase_control");
        exit(EXIT_FAILURE);
    }
    if (ftp_user_info.evbase_data == NULL) {
        perror("event_base_new() selhal - setup_con_buf - ftp_user_info.evbase_data");
        exit(EXIT_FAILURE);
    }

    ftp_user_info.event_timeout_control = event_new(ftp_user_info.evbase_control, ftp_user_info.ftp_sockets_obj.ftp_data_com, EV_PERSIST | EV_TIMEOUT, reset_timeval_struct_control, NULL);
    event_add(ftp_user_info.event_timeout_control, &ftp_user_info.timeout_control);
    
    if (fcntl(ftp_user_info.ftp_sockets_obj.ftp_control_com, F_SETFL, O_NONBLOCK) == -1) { // socket musi byt v nonblocking mode, aby to slo do bufferevent_socket_new()
        perror("fcntl() selhal - neslo nastavit O_NONBLOCK - handle_command_function");
        exit(EXIT_FAILURE);
    }

    ftp_user_info.bufevent_control = bufferevent_socket_new(ftp_user_info.evbase_control, ftp_user_info.ftp_sockets_obj.ftp_control_com, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE); // BEV_OPT_UNLOCK_CALLBACKS
    // printf("\n\n%p %d", (void *)ftp_user_info.bufevent_control, ftp_user_info.ftp_sockets_obj.ftp_control_com);
    fflush(stdout);
    if (ftp_user_info.bufevent_control == NULL) {
        fprintf(stderr, "buffervent_socket_new() selhal - setup_con_buf");
        exit(EXIT_FAILURE);
    }

    void (*bufevent_event_control)(struct bufferevent *bufevent_both, short events, void *ptr_arg) = &bufevent_event_cb_control;
    void (*bufevent_write_control)(struct bufferevent *bufevent_control, void *ptr_arg) = &bufevent_write_cb_control;
    void (*bufevent_read_control)(struct bufferevent *bufevent_control, void *ptr_arg) = &bufevent_read_cb_control;
    bufferevent_setcb(ftp_user_info.bufevent_control, bufevent_read_control, bufevent_write_control, bufevent_event_control, NULL); // 1. NULL => eventcb, 2. NULL => pointer, ktery se preda vsem callbackum
    bufferevent_enable(ftp_user_info.bufevent_control, EV_READ | EV_WRITE); // event base pro bufferevent

    event_base_loop(ftp_user_info.evbase_control, EVLOOP_NO_EXIT_ON_EMPTY);
}

int main() {
    signal(SIGINT, signal_handler);
    // /media/sf_projects_on_vm/FTP_SERVER/file.txt
    set_queue_message_len();
    // event_enable_debug_logging(EVENT_DBG_ALL);
    // event_enable_debug_mode();
    evthread_use_pthreads(); // abychom mohli pouzivat libevent s threads
    ftp_user_info.curr_dir = strdup("/tmp/ftp_server/"); // aby se to dalo dealokovat pomoci free()

    // clock_t => __kernel_long_t => long
    clock_t start;
    start = clock(); // counting tics from the start of this process
    memset(&ftp_user_info.server_control_info, 0, sizeof(struct sockaddr_in)); // ujisteni, ze struiktura je opravdu prazdna, bez garbage values, v struct adrrinfo bych diky 
    //tomu nastavit protokol TCP!
    ftp_user_info.server_control_info.sin_family = AF_INET;
    ftp_user_info.server_control_info.sin_port = htons(CONTROL_PORT); // htons => host to network short
    // pokud je datovy typ nejaky typ pole nebo struktura, union apod., TAK TO MUSIM ZKOPIROVAT DO TOHO a nejde to jenom priradit!!
    // naplneni hints.sin_addr
    if (inet_pton(ftp_user_info.server_control_info.sin_family, "127.0.0.1", &ftp_user_info.server_control_info.sin_addr) <= 0) { // pred a po hints.sin_addr nemusi byt ty zavorky a povazuji se za nadbytecne
        perror("inet_pton() selhal - ftp_control");
        exit(EXIT_FAILURE);
    }

    memset(&ftp_user_info.server_data_info, 0, sizeof(struct sockaddr_in));
    ftp_user_info.server_data_info.sin_family = AF_INET;
    ftp_user_info.server_data_info.sin_port = htons(DATA_PORT);
    // "muze se do davat rovnou do te struktury, protoze ma jen jednoho clena a tam se kopiruji ty data a zrovna to vyjde na tu delku, ale kdyby tam byly dva cleny, tak je lepsi tam uvest samotneho clena te struktury", takhle je to napsane v serveru, ale tady to je to explicitne napsane, coz je best practice
    if (inet_pton(ftp_user_info.server_data_info.sin_family, "127.0.0.1", &ftp_user_info.server_data_info.sin_addr) == 0) {
        perror("inet_pton selhal() - ftp_data");
        exit(EXIT_FAILURE);
    }

    // ftp_user_info.server_data_info.sin_addr.s_addr = INADDR_ANY;

    if ( (ftp_user_info.ftp_sockets_obj.ftp_control_socket = socket(ftp_user_info.server_control_info.sin_family, SOCK_STREAM, 0)) == -1) {
        perror("socket() selhal - ftp_data");
        exit(EXIT_FAILURE);
    }
    // printf("\n\ntemp_data_socket: %d\n\n", ftp_user_info.ftp_sockets_obj.ftp_control_socket);

    // AVE MARIA
    // AVE CHRISTUS REX THE KING OF KINGS THE LORD OF LORDS
    
    

    
    pthread_t thread_control, command_control; // ID of thread
    const pthread_attr_t thread_attributes;

    void *(*setup_p)(void *) = &setup_con_buf; // int, struct sockaddr **
    if ( pthread_create(&thread_control, NULL, setup_p, NULL)) { // NULL je atribut pro atribut strukturu, ktera specifikuje urcite atributy nove vytvoreneho thread, jako scheduling policy, inherit scheduler
        perror("pthread_create() selhal - main() - thread_control");
        exit(EXIT_FAILURE);
    }

    void *(*command_control_p)(void *) = &entering_commands;
    if ( pthread_create(&command_control, NULL, command_control_p, NULL)) {
        perror("pthread_create() selhal - main() - command_control");
        exit(EXIT_FAILURE);
    }

    // pthread_exit(NULL);
    // pthread_kill(pthread_self(), SIGSTOP);
    // pokud skonci hlavni vlakno -> tak skonci cely program
    while (1) {
        // sleep(500);
    }

    // data_connection(&data_args);

    // ftp_dtp();

    // > ma vetsi prioritu nez =
    return EXIT_SUCCESS;
}
/*



struct Data_Args data_args = { .ftp_d_socket = ftp_data_socket, .server_d_info = &ftp_user_info.server_data_info};
// void *(* f_data_connection)(void *) = &data_connection; // int, struct sockaddr **

 struct Control_Args *control_arg_struct = (struct Control_Args *)temp_p;

int ftp_control_socket = control_arg_struct->ftp_c_socket; // nejde rovnou typecastovat, protoze -> ma vetsi prednost nez (type cast) 
struct sockaddr_in *ftp_user_info.server_control_info = control_arg_struct->server_c_info; // VZDY se musi castovat void * pointer, protoze C nevi, na jaky datovy typ se ukazuje, nevi klik memory se ma priradit one promenne, kam chceme ty data ulozit, proto se to musi vzdy castovat
*/

// AVE CHRISTUS REX!