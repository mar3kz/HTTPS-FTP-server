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
    QUEUE_MESSAGE_LEN = bytes;
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
    // int ftp_control_socket;
    int ftp_control_com; // client ma jenom jeden socket na komunikacis
    int ftp_data_socket;
    int ftp_data_com;

    int ftp_data_socket_or_com; // zalezi jestli ftp_data_socket se bude povazovat za ftp_data_com podle aktivni/pasivni mode
};
struct Ftp_Sockets ftp_sockets_obj = { .ftp_control_com = -1, .ftp_data_com = -1, .ftp_data_socket_or_com = -1};

struct Account_Information {
    char *username;
    char *password;
};
struct Account_Information account_information;

enum Ftp_Code_Login {
    FAILED_SECURITY = 535,
    INVALID_USERNAME_PASSWORD = 430,
    USER_LOGGEDIN = 230,
};
enum Ftp_Code_Login ftp_code_login;

enum Ftp_Commands {
    USER, // 0
    PASS,
    QUIT,
    PORT,
    PASV,
    RETR,
    STOR,
    NOOP,
    TYPE, // 8
};
enum Ftp_Commands ftp_commands;

enum Ftp_Data_Representation {
    ASCII = 0,
    IMAGE = 1,
};
enum Ftp_Data_Representation ftp_data_representation = ASCII;

struct Ftp_User_Info {
    char *name_info;
    int loggedin_info; // 1 = TRUE, 0 = FALSE
    int ftp_data_com;
    int ftp_control_com;

    enum Ftp_Data_Representation ftp_data_representation;
    int length_new_file;
};
struct Ftp_User_Info ftp_user_info = { .ftp_data_representation = ASCII};

struct sockaddr_in server_control_info;
struct sockaddr_in server_data_info;
struct bufferevent *bufevent_control;
struct event_base *evbase_control;
struct bufferevent *bufevent_data;
struct event_base *evbase_data;

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

void save_file(char *path, char *data) {
    // O => open() flags
    // S => file mode bits
    // F => fcntl() prikazy

    // pokud to nebude k otevreni, tak by to melo file permissions 4777 // umask nemuze NIJAK ovlivnit setuid bit
    // open(path, O_CREAT | O_APPEND | O_RDONLY, S_IRWXU | S_IRWXG, S_IRWXO, S_ISUID); // 4777 => spusteni s pravy vlastnika, vsichny read, write, execute
    int fd = open(path, O_CREAT | O_APPEND, S_IRWXU | S_IRWXO | S_IRWXG | S_ISUID);
    if (fd == -1) {
        perror("open() selhal - send_file()");
        exit(EXIT_FAILURE);
    }

    size_t length_data, bytes_total = 0;
    ssize_t bytes_now;
    length_data = strlen(data) + 1;

    for (; ;) { 
        bytes_now = write(fd, data + bytes_total, length_data - bytes_total);

        if ( bytes_now == -1) {
            perror("write() selhal - send_file()");
            exit(EXIT_FAILURE);
        }
        else if (bytes_total < length_data) {
            bytes_total += bytes_now;
        }
        else if (bytes_total == length_data) {
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
            
            printf("\n\nTO, CO SE VYMAZE: %s, %d, path: %s", (*old_node)->dir_names[i], (*old_node)->no_states, path);
            (*old_node)->no_states--;

            (*old_node)->dir_names = delete_dir_names_i((*old_node)->dir_names, (*old_node)->no_states, i);
            printf("\n%d, %s, %s, %s\n\n", (*old_node)->no_states, path, (*old_node)->path, partial_path);
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
    printf("\nnew_node->path %s, strlen new_node->path: %d", new_node->path, strlen(new_node->path)); // 36 -> 42
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
    printf("\n0 - username, 1 - password => %d, %s\n", username_password, text);

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

        printf("username_password: %d, account_info[0] = %s, account_info[1] = %s", username_password, account_info[0], account_info[1]);
        switch(username_password) {
            case 0: 
                if (strcmp(account_info[0], text) == 0) {
                    printf("\n\nusername\n\n");
                    account_information.username = strdup(text);
                    return 0;
                }
            case 1:
                if (strcmp(account_info[1], text) == 0) {
                    printf("\n\npassword\n\n");
                    account_information.password = strdup(text);
                    return 0;
                }
            default:
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
   

    printf("\n\n vypis: %d", root_node->no_states);
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

static char *path_to_open(char *path) {
    int uid = getuid(); // user ID
    struct passwd *password = getpwuid(uid);
    char *home_directory = password->pw_dir;

    size_t path_len = strlen(path);
    size_t home_directory_len = strlen(home_directory);


    char *path_to_file = (char *)malloc(path_len + home_directory_len);
    memset(path_to_file, 0, path_len + home_directory_len);

    char *tilde_p = strstr(path, "~");
    if ( tilde_p == NULL && strstr(path, "/") != NULL) { // kde se hleda, co se hleda
        int tilde_index = (int)(tilde_p - path);
        strcpy(path_to_file, path);
    }
    else if (tilde_p != NULL && strlen(path) == 1) {
        strcpy(path_to_file, home_directory);
    }
    else if (tilde_p != NULL && strlen(path) > 1) {
        strcpy(path_to_file, home_directory);
        strcpy(path_to_file + home_directory_len, path + 1);
    }
    else {
        printf("\nnejaka chyba");
    }

    return path_to_file;
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
            char *path = path_to_open(user_data);
            // printf("path_to_open: %s", path);
            recursive_dir_browsing(path);
            // printf("user_data: %s\n", user_data);
            
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

    // stat/fstat/lstat
    if (stat(path, &info) == -1) {
        perror("stat() selhal - read_contents_ftp");
        exit(EXIT_FAILURE);
    }

    size_t len_file = info.st_size;
    char *data_from_file = (char *)malloc(len_file + 1); // file s jednim znakem => 2 Bytes => char + \n => proto + 1 pro => 3 Bytes

    ssize_t bytes_read;
    size_t total_bytes = 0;
    while ( bytes_read = read(fd, data_from_file + total_bytes, len_file - total_bytes) != len_file) {
        if ( bytes_read == -1) {
            perror("read() selhal - read_contents_ftp");
            exit(EXIT_FAILURE);
        }
        total_bytes += bytes_read;
    }
    data_from_file[total_bytes] = '\0';
    return data_from_file;
}

// void data_send_ftp(struct bufferevent *bufevent_data) {
//     mqd_t data_queue;
//     if ( data_queue = mq_open(DATA_QUEUE_NAME, O_RDWR) == -1) {
//         perror("mq_open() selhal - data_send_ftp");
//         exit(EXIT_FAILURE);
//     }

//     char *queue_path = (char *)malloc(QUEUE_MESSAGE_LEN);
//     memset(queue_path, 0, QUEUE_MESSAGE_LEN);
//     if ( mq_receive(data_queue, queue_path, QUEUE_MESSAGE_LEN, NULL) == -1) {
//         perror("mq_receive() selhal - data_send_ftp");
//         exit(EXIT_FAILURE);
//     }

//     char *data_to_send = read_contents_ftp(queue_path);
//     if ( bufferevent_write(bufevent_data, data_to_send, strlen(data_to_send) + 1) == -1) {
//         perror("bufferevent_write() selhal - data_send_ftp");
//         exit(EXIT_FAILURE);
//     }
// }

void control_send_account_info(struct bufferevent *bufevent_control, char *text) {
    if ( bufferevent_write(bufevent_control, text, strlen(text) + 1) == -1) {
        perror("bufferevent_write() selhal - control_send_account_info");
        exit(EXIT_FAILURE);
    }
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

    // 1 - True - vse OK
    // 0 - False - neco spatne

    char *space = strstr(command_user, " ");
    if (space == NULL) {
        fprintf(stderr, "strstr() selhal - nenasel space - command pravdepodobne spatne formatovan - is_command_ok - USER\n");
        exit(EXIT_FAILURE);
    }
    int space_i = (int)(space - command_user);

    if ( strstr(command_user, "USER") != NULL) {
        if (isalpha(command_user[++space_i]) && isalpha(command_user[++space_i]) ) {
            return 1;
        }
        return 0;
    }
    else if ( strstr(command_user, "PASS") != NULL) {
        for (int i = ++space_i; i < strlen(command_user) + 1; i++) {
            if (!isalpha(command_user[i]) || !isdigit(command_user[i]) || !ispunct(command_user[i]) ) {
                return 0;
            }
        }
    }
    else if ( strstr(command_user, "PORT") != NULL) {
        printf("\ntadyy");
        fflush(stdout);
        int space_index = space_i + 1;

        for (int i = 0; i < 5; i++) {
            printf("\n1\n");
            char *temp_finding;
            if ((temp_finding = strstr(command_user + space_index, ",")) == NULL ) {
                return 0;
            }
            space_index = (int)(temp_finding - command_user) + 1;
        }
    }
    else if ( strstr(command_user, "RETR") != NULL) {
        if (strstr(command_user, "/") != NULL || strstr(command_user, ".") != NULL) {
            return 1;
        }
        return 0;
    }
    else if ( strstr(command_user, "STOR") != NULL) {
        if (strstr(command_user, "/") != NULL || strstr(command_user, ".") != NULL) {
            return 1;
        }
        return 0;
    }
    return 1;
}

void send_ftp_commands(struct bufferevent *bufevent_control) {
    mqd_t control_queue = mq_open(CONTROL_QUEUE_NAME, O_RDWR);
    if (control_queue == -1) {
        perror("mq_open() selhal - send_ftp_commands");
        exit(EXIT_FAILURE);
    }

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
    if ( mq_receive(control_queue, commands_to_send, QUEUE_MESSAGE_LEN, NULL) == -1) {
        perror("mq_receive() selhal - send_ftp_commands");
        exit(EXIT_FAILURE);
    }

    if ( bufferevent_write(bufevent_control, commands_to_send, strlen(commands_to_send) + 1) == -1) {
        perror("bufferevent_write() selhal - send_ftp_commands");
        printf("\ntady");
        exit(EXIT_FAILURE);
    }
    send(ftp_sockets_obj.ftp_control_com, commands_to_send, strlen(commands_to_send) + 1, 0);
    printf("=== bufferevent_write done ===, %s", commands_to_send);
    // kazdy command se musi poslat pres control connection, aby i server dostal zpravy o informacich
}

void bufevent_event_cb_both(struct bufferevent *both, short events, void *ptr_arg) {
    if ( (BEV_EVENT_EOF & events) == BEV_EVENT_EOF) {
        struct evbuffer *input_evbuffer = bufferevent_get_input(bufevent_control); // ziskame underlying vrstvu bufferevents => input/output evbuffer

        // pokud se prerusi data connection a bude prazdny buffer, tak to znamena, ze server doposlal posledni data => zalezi na transmission modes
        // toto by se melo zavolat az potom se zjisti, ze bufferevent_read dostal flag EOF => po dokonceni posilani jakychkoliv dat
        if ( evbuffer_get_length(input_evbuffer) != 0) {
            fprintf(stderr, "nejspise nastal error - EOF - bufevent_event_cb_both - data");
            exit(EXIT_FAILURE);
        }
    }
    else if (( (BEV_EVENT_ERROR) & events) == BEV_EVENT_ERROR) {
        EVUTIL_SOCKET_ERROR();
        exit(EXIT_FAILURE);
    }
}

void bufevent_read_cb_control(struct bufferevent *bufevent_control, void *ptr_arg) {
    reset_bufevent_data_len();

    char *command_buf_to_recv = (char *)malloc(BUFEVENT_DATA_LEN);
    memset(command_buf_to_recv, 0, BUFEVENT_DATA_LEN);

    size_t total_bytes = 0, bytes_now;
    for (; ;) {
        bytes_now = bufferevent_read(bufevent_control, command_buf_to_recv + total_bytes, BUFEVENT_DATA_LEN - total_bytes);

        if (bytes_now == -1) {
            perror("bufferevent_read() selhal - bufevent_read_cb_control");
            exit(EXIT_FAILURE);
        }
        else if (bytes_now == 0) {
            printf("\n\n%s", command_buf_to_recv);
            if (strstr(command_buf_to_recv, "\r\n") != NULL) {
                printf("\nvse precteno");
                printf("\n%s", command_buf_to_recv);
                break;
            }
            else {
                fprintf(stderr, "\nserver nejspise neukoncil odpoved pomoci CRLF = carriage return line feed");
                exit(EXIT_FAILURE);
            }
            
        }

        total_bytes += bytes_now;
    }
}

void bufevent_write_cb_control(struct bufferevent *bufevent_control, void *ptr_arg) {
    printf("\nall data sent\n");
}

void bufevent_read_cb_data(struct bufferevent *bufevent_data, void *ptr_arg) {
    reset_bufevent_data_len();

    mqd_t control_queue = mq_open(CONTROL_QUEUE_NAME, O_RDWR);
    if (control_queue == -1) {
        perror("mq_open() selhal - bufevent_read_cb_data");
        exit(EXIT_FAILURE);
    }

    char *path_for_new_file = (char *)malloc(QUEUE_MESSAGE_LEN);
    if (path_for_new_file == NULL) {
        perror("bufferevent_read() selhal - bufevent_read_cb_data");
        exit(EXIT_FAILURE);
    }
    memset(path_for_new_file, 0, QUEUE_MESSAGE_LEN);

    if (mq_receive(control_queue, path_for_new_file, QUEUE_MESSAGE_LEN, NULL) == -1) {
        perror("bufferevent_read() selhal - bufevent_read_cb_data");
        exit(EXIT_FAILURE);
    }
    

    mqd_t data_queue = mq_open(DATA_QUEUE_NAME, O_RDWR);
    if (data_queue == -1) {
        perror("mq_open() selhal - bufevent_read_cb_data");
        exit(EXIT_FAILURE);
    }

    char *path_to_save = (char *)malloc(QUEUE_MESSAGE_LEN);
    if ( path_to_save == NULL) {
        perror("malloc() selhal - bufevent_read_cb_data");
        exit(EXIT_FAILURE);
    }

    if ( mq_receive(data_queue, path_to_save, QUEUE_MESSAGE_LEN, NULL) == -1) {
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
        bytes_now = bufferevent_read(bufevent_data, data_buf + bytes_total, BUFEVENT_DATA_LEN - bytes_total);

        if (bytes_now == -1) {
            perror("bufferevent_read() selhal - bufevent_read_cb_data");
            exit(EXIT_FAILURE);
        }
        else if (bytes_now == 0) {
            bytes_total += bytes_now;
            ftp_user_info.length_new_file = bytes_total;
            save_file(path_for_new_file, data_buf);
            printf("\nvse OK");
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
    printf("\nzapsala se data");
}

char *extract_path_command(char *command) {
    char *separator = strstr(" ", command);
    int separator_i = (int)(separator - command);

    char *carriage_return = strstr("\r", command);
    int carriage_return_i = (int)(carriage_return - command);

    char *path = (char *)malloc(92); // protoze 100 - 3 (\r\n\0) - 5 (RETR )
    memset(path, 0, 92);

    for (int i = separator_i + 1, path_i = 0; i < carriage_return_i; i++) {
        path[path_i++] = command[i];
    }
    // nemusime resit \0, protoze automaticky NULL terminated

    return path;
}

char *insert_crlf(char *command) {
    // zero_memory nefunguje tak, jak ma
    command[strlen(command)] = '\r'; // \r
    command[strlen(command)] = '\n'; // \n, strlen(command) + 1 je spatne, protoze pridanim \r se zvetsi ta velikost toho command
    command[strlen(command)] = '\0'; // aby to vzdy koncilo <crlf>NULL char

    return command;
}

void *thread_callback_func(void *) {
    event_base_loop(evbase_data, EVLOOP_NO_EXIT_ON_EMPTY);
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
    */

    // printf("\n\ncommand: %s", command);
    fflush(stdout);
    int control_queue_count = 0, data_queue_count = 0;
    mqd_t control_queue;
    if (control_queue_count == 0) {
        control_queue = mq_open(CONTROL_QUEUE_NAME, O_RDWR);
        if (control_queue == -1) {
            perror("mq_open() selhal - handle_command_function");
            exit(EXIT_FAILURE);
        }
        control_queue_count++;
    }

    if (strstr(command, "QUIT") != NULL) {
        puts("200 - command okay");
        ftp_user_info.loggedin_info = 0;
        // nutnost usera zadat nove jmeno
        ftp_user_info.name_info = NULL;
        close(ftp_sockets_obj.ftp_data_com);
    }
    else if (strstr(command, "PORT") != NULL || strstr(command, "PASV") != NULL) { // connection part
        if (strstr(command, "PORT") != NULL) {
            ftp_sockets_obj.ftp_data_socket = ftp_sockets_obj.ftp_data_socket_or_com;

            if (is_command_ok(command) != 1) {
                fprintf(stderr, "PORT command ma spatny format", command);
                exit(EXIT_FAILURE);
            }

            // pro klienta
            unsigned char *byte_field_address = (unsigned char *)&server_control_info.sin_addr.s_addr; // nova promenna Bytes na memory adresu, kde je ulozeno 4 Bytes

            int st_byte_addr = byte_field_address[0];
            int nd_byte_addr = byte_field_address[1];
            int rd_byte_addr = byte_field_address[2];
            int fth_byte_addr = byte_field_address[3];

            // PORT = server se pripojuje na clienta (data)
            // PASV = client se pripojuje na server (data)

            unsigned char *byte_field_port = (unsigned char *)&server_control_info.sin_port;

            int st_byte_port = byte_field_port[0];
            int nd_byte_port = byte_field_port[1];

            printf("\nPORT %d,%d,%d,%d,%d,%d", st_byte_addr, nd_byte_addr, rd_byte_addr, fth_byte_addr, st_byte_port, nd_byte_port);

            char *port_command = (char *)malloc(20);
            memset(port_command, 0, 20);
            snprintf(port_command, 20, "PORT %d,%d,%d,%d,%d,%d", st_byte_addr, nd_byte_addr, rd_byte_addr, fth_byte_addr, st_byte_port, nd_byte_port);

            if ( mq_send(control_queue, port_command, strlen(port_command) + 1, 31) == -1) {
                perror("mq_send() selhal - handle_command_function - PORT");
                exit(EXIT_FAILURE);
            }

            if (listen(ftp_sockets_obj.ftp_data_socket, BACKLOG) == -1) {
                perror("listen() selhal - handle_command_function");
                exit(EXIT_FAILURE);
            }

            int ftp_data_com;
            if ((ftp_data_com = accept(ftp_sockets_obj.ftp_data_socket, NULL, NULL)) == -1) {
                perror("accept() selhal - handle_command_function");
                exit(EXIT_FAILURE);
            }
            ftp_sockets_obj.ftp_data_com = ftp_data_com;

            printf("\n%s, connection established", port_command);
        }
        else if (strstr(command, "PASV") != NULL) {            
            if (!ftp_user_info.loggedin_info) {
                ftp_sockets_obj.ftp_data_com = ftp_sockets_obj.ftp_data_socket_or_com;
                int connect_rv = connect(ftp_sockets_obj.ftp_data_com, (struct sockaddr *)&server_data_info, sizeof(server_data_info)); // 127.0.0.1:21 => port 21 = data connection
                if (connect_rv == -1) {
                    perror("connect() selhal - handle_command_function");
                    exit(EXIT_FAILURE);
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
    }
    else if (strstr(command, "TYPE") != NULL) {
        if (strstr(command, "IMAGE") != NULL) {
            puts("200 - command okay");
            ftp_user_info.ftp_data_representation = IMAGE;
        }
        else {
            puts("504 - Command not implemented for that parameter - no change");
            ftp_user_info.ftp_data_representation = ASCII;
        }
    }
    else if (strstr(command, "NOOP") != NULL) {
        puts("200 - command okay");
        if (mq_send(control_queue, command, strlen(command) + 1, 31) == -1) {
            perror("mq_send() selhal - handle_command_function - NOOP");
            exit(EXIT_FAILURE);
        }
        send_ftp_commands(bufevent_control); // send to the server
        // puts("NOOP tady je\n");
    }
    else if (strstr(command, "RETR") != NULL || strstr(command, "STOR") != NULL) { // tady se otevre datova message queue //  && ftp_user_info.loggedin_info == 1
        mqd_t data_queue = -1;
        printf("\ndata_queue_count: %d, ftp_data_com: %d", data_queue_count, ftp_sockets_obj.ftp_data_com);
        if (data_queue_count == 0 && ftp_sockets_obj.ftp_data_com != -1) {
            data_queue = mq_open(DATA_QUEUE_NAME, O_CREAT | O_RDWR, S_IRWXU | S_IRWXO | S_IRWXG | S_ISUID, NULL); // 4777
            if (data_queue == -1) {
                perror("mq_open() selhal - handle_command_function");
                exit(EXIT_FAILURE);
            }
            data_queue_count++;

            bufevent_data = bufferevent_socket_new(evbase_data, ftp_sockets_obj.ftp_data_com, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE); // BEV_OPT_UNLOCK_CALLBACKS - toto chce defaultne dereffered callbacks
            if (bufevent_data == NULL) {
                perror("bufevent_data selhal - handle_command_function");
                exit(EXIT_FAILURE);
            }
            void (*bufevent_event_both)(struct bufferevent *bufevent_both, short events, void *ptr_arg) = &bufevent_event_cb_both;
            void (*bufevent_write_data)(struct bufferevent *bufevent_data, void *ptr_arg) = &bufevent_write_cb_data;
            void (*bufevent_read_data)(struct bufferevent *bufevent_data, void *ptr_arg) = &bufevent_read_cb_data;

            bufferevent_setcb(bufevent_data, bufevent_read_data, bufevent_write_data, bufevent_event_both, NULL);

            void *(*f_thread_callback_func)(void *) = thread_callback_func;
            pthread_t callback_thread;

            if ( pthread_create(&callback_thread, NULL, f_thread_callback_func, NULL) != 0) {
                perror("pthread_create() selhal - handle_command_function - RETR");
                exit(EXIT_FAILURE);
            }
        }
        printf("\ndata_queue file descriptor: %d", data_queue);

        if (strstr(command, "RETR") != NULL) {
            if (is_command_ok(command) != 1) {
                fprintf(stderr, "RETR command ma spatny format", command);
                exit(EXIT_FAILURE);
            }
            
            // retr
            char *path = extract_path_command(command);
            if ( mq_send(data_queue, path, strlen(path) + 1, 31) == -1) {
                perror("mq_send() selhal - handle_command_function - RETR");
                exit(EXIT_FAILURE);
            }
        }
        if (strstr(command, "STOR") != NULL) {
            if (is_command_ok(command) != 1) {
                fprintf(stderr, "RETR command ma spatny format", command);
                exit(EXIT_FAILURE);
            }

            char *path = extract_path_command(command);
            printf("\ndata_queue file descriptor: %d", data_queue);
            if ( mq_send(data_queue, path, strlen(path) + 1, 31) == -1) {
                perror("mq_send() selhal - handle_command_function - STOR");
                exit(EXIT_FAILURE);
            }
        }
    }
    else {
        // errno ma hodnotu 0, pokud je vse ok, pokud je to rozdilne, tak nekde nastala chyba
        if (errno != 0) {
            perror("nekde se vyskytla chyba - handle_command_function");
            exit(EXIT_FAILURE);
        }
        else {
            fprintf(stderr, "zadany command nepotrebuje explicitni funkci nebo nejste prihlaseni a chcete pouzit command s data pripojenim\n");
            fflush(stdout);
        }        
    }
}

void *entering_commands(void *arg) {
    char *non_terminated_request = (char *)malloc(sizeof(char) * 100);
    char *user_request = (char *)malloc(100);
    zero_memory(non_terminated_request); // automaticky NULL terminated
    zero_memory(non_terminated_request);

    // struct mq_attr ma;
    // ma.mq_flags = 0;
    // ma.mq_maxmsg = 16;
    // ma.mq_msgsize = 50;
    // ma.mq_curmsgs = 0;


    mqd_t control_queue = mq_open(CONTROL_QUEUE_NAME, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID, NULL); // pokud jeste ta queue neni vytvorena, tak to bude blokovat 
    if (control_queue == -1) {
        perror("mq_open() selhal - control_send_ftp");
        exit(EXIT_FAILURE);
    }
    struct mq_attr attr;
    mq_getattr(control_queue, &attr);
    printf("\n\n tady jsou ty udaje: %ld %ld %ld %ld", attr.mq_curmsgs, attr.mq_msgsize, attr.mq_curmsgs, attr.mq_flags); // mozna nejake threads chteji otevrit stejnou frontu => blokuji ji?
    fflush(stdout);

    int introduction = 0;
    while(1) {
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

        printf("Name: ");
        scanf(" %97[^\n]", non_terminated_request); // %99[^\n] chceme cist maximalne 99 charakteru, protoze +1 pro \0 a chceme cist vsechny charaktery nez nenarazime na \n, potom uz to nechceme cist a nebudeme to cist \n, mezera mezi " a % znamena, ze chceme ignorovat kazdy whitespace v stdout bufferu (vsechny znaky, ktere kdyz vyprintujeme, tak proste nemaji ten normalni charakter)
        // control_send_ftp(bufevent_control);
        int resolution1 = partial_login_lookup(non_terminated_request, 0); // 0 - username, 1 = password
        user_request = insert_crlf(non_terminated_request);

        // if ( mq_send(control_queue, user_request, strlen(user_request) + 1, 31) == -1) {
        //     perror("mq_send() selhal - control_send_ftp");
        //     exit(EXIT_FAILURE);
        // }
        zero_memory(user_request);
        zero_memory(non_terminated_request);


        printf("Password: ");
        scanf(" %97[^\n]", non_terminated_request);
        int resolution2 = partial_login_lookup(non_terminated_request, 1);
        user_request = insert_crlf(non_terminated_request);
        // control_send_ftp(bufevent_control);

        // if ( mq_send(control_queue, user_request, 100, 31) == -1) { // strlen(user_request) + 1
        //     perror("mq_send() selhal - control_send_ftp");
        //     exit(EXIT_FAILURE);
        // }
        zero_memory(user_request);
        zero_memory(non_terminated_request);
        // tento socket bude blocking, protoze budeme vzdy cekat na odpoved od serveru
        // nedela nic specialniho; pokud bude false, tak se to ukonci; nedela nic specialniho

        if (resolution1 == 0 && resolution2 == 0) {
            puts("230 - User logged in, proceed");
            puts("220 -    Service ready for new user");
            char *temp_conformation = (char *)malloc(strlen(account_information.username) + strlen(account_information.password) + 2);
            snprintf(temp_conformation, strlen(account_information.username) + strlen(account_information.password) + 5, "%s&<>&%s", account_information.username, account_information.password); // zapise vsechny bytes toho stringu bez \0 a na konci se to zakonci \0
            char *account_conformation = insert_crlf(temp_conformation);
            control_send_account_info(bufevent_control, account_conformation);

            break;
        }
        else if (resolution1 == 0 || resolution2 == 0) {
            puts("430 - Invalid username or password");
        }
        else {
            puts("535 - Failed security check");
        }
        free(account_information.username);
        free(account_information.password);
    }

    // one (or more) whitespace characters validates (UZNA/AKCEPTUJE) jeden/zadny/vice nez jeden WHITESPACES IN THE INPUT STRING, toto chovani maji jako %d, %f, %s => a toto znamena, ze muze ignorovat whitespaces v input stringu jako 10       10 => a=10, b=20, toto chovani nemaji implicitne %c a %[], k dosazeni toho stejneho chovani musime dat whitespace do format stringu, tim se explicitne "zapne" toto chovani
    // %c => a\n, vezme se jenom a, \n zustane v stdin bufferu, proto pro dalsi pouzivani funkce je nutno scanf(" %c"), pro zapnuti validace whitespaces
    // kazdy system maji jiny zpusob, jak oznacit novy radek, nekdo to ma \r\n, nekdo \n, nekdo \r, proto se udelalo to, ze kdyz nejaky source code ma v sobe \n, tak by to melo znamenat novy radek pro vsechny systemy, takova interpretace noveho radku, ale pokud je to zapsane ve file, tak to uz je jine, protoze si pise pouze to, co je v tom bufferu, proto nejake files budou zobrany jinak na jinych systemech

    while (1) {
        // telnet commands jsou ukonceny <CRLF> 13, 10 a ftp code jsou terminated <space> 32
        printf("$ ");
        fflush(stdout);
        scanf(" %99[^\n]", non_terminated_request);
        user_request = insert_crlf(non_terminated_request);
        // printf("\n\nuser_request: %s, non_terminated_request: %s", user_request, non_terminated_request);
        // fflush(stdout);
        printf("\nuser_request: %s", user_request);
        handle_command_function(user_request);

        // // if ( mq_send(control_queue, user_request, strlen(user_request) + 1, 31) == -1) {
        // //     perror("mq_send() selhal - entering commands");
        // //     exit(EXIT_FAILURE);
        // // }
        // //sleep(3);
        // zero_memory(non_terminated_request);
        // zero_memory(user_request);
    }

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
    int ftp_control_com; // vytvori se jakoby zakladni socket descriptor popisujici, ze bude komunikace pres sit a potom pomoci connect
    // se klientovi priradi ten nahodny ephemeral port a ten socket descriptor se jakoby zmeni na communication socket descriptor
    // socket take zalozi interni strukturu o tomto pripojeni
    if ( (ftp_control_com = socket(server_control_info.sin_family, SOCK_STREAM, 0)) == -1 ) { // type => SOCK_STREAM znazi jaky typ socketu to bude => pouzivajici TCP (bytes streams) nebo UDP (datagrams)
        perror("socket selhal() - ftp_control");
        exit(EXIT_FAILURE);
    }
    ftp_sockets_obj.ftp_control_com = ftp_control_com;
    // 0 => OS vybere nejlepsi protokol pro ty specifikace, jinak ty protokoly jsou definovane v glibc netine/in.h
    int optval = 1;
    if (setsockopt(ftp_control_com, IPPROTO_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval)) == -1) {
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
    if ( connect(ftp_sockets_obj.ftp_control_com, (struct sockaddr *)&server_control_info, sizeof(server_control_info) ) == -1 ) { // () meni poradi operandu
        perror("connect() selhal - setup_con_buf");
        exit(EXIT_FAILURE);
    }
    printf("=== Connection ftp_control_com: %d ===", ftp_sockets_obj.ftp_control_com);
    // send(ftp_sockets_obj.ftp_control_com, "ahoj", 10, 0);

    // struct mq_attr ma;
    // ma.mq_flags = 0;
    // ma.mq_maxmsg = 16;
    // ma.mq_msgsize = sizeof(int)
    // ma.mq_curmsgs = 0;

    mqd_t control_queue;
    char errstr[50] = {0};
    if ( (control_queue = mq_open(CONTROL_QUEUE_NAME, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID, NULL)) == -1) { // 4777
        strerror_r(errno, errstr, 50);
        printf("\n%s\n");
        fflush(stdout);
        perror("mq_open() selhal - setup_con_buf");
        exit(EXIT_FAILURE);
    }

    evbase_control = event_base_new();
    evbase_data = event_base_new();

    if (evbase_control == NULL) {
        perror("event_base_new() selhal - setup_con_buf - evbase_control");
        exit(EXIT_FAILURE);
    }
    if (evbase_data == NULL) {
        perror("event_base_new() selhal - setup_con_buf - evbase_data");
        exit(EXIT_FAILURE);
    }

    bufevent_control = bufferevent_socket_new(evbase_control, ftp_sockets_obj.ftp_control_com, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE); // BEV_OPT_UNLOCK_CALLBACKS
    printf("\n\n%p %d", (void *)bufevent_control, ftp_control_com);
    fflush(stdout);
    if (bufevent_control == NULL) {
        fprintf(stderr, "buffervent_socket_new() selhal - setup_con_buf");
        exit(EXIT_FAILURE);
    }

    void (*bufevent_event_both)(struct bufferevent *bufevent_both, short events, void *ptr_arg) = &bufevent_event_cb_both;
    void (*bufevent_write_control)(struct bufferevent *bufevent_control, void *ptr_arg) = &bufevent_write_cb_control;
    void (*bufevent_read_control)(struct bufferevent *bufevent_control, void *ptr_arg) = &bufevent_read_cb_control;
    bufferevent_setcb(bufevent_control, bufevent_read_control, bufevent_write_control, bufevent_event_both, NULL); // 1. NULL => eventcb, 2. NULL => pointer, ktery se preda vsem callbackum
    bufferevent_enable(bufevent_control, EV_READ | EV_WRITE); // event base pro bufferevent

    event_base_loop(evbase_control, EVLOOP_NO_EXIT_ON_EMPTY);
}

int main() {
    set_queue_message_len();
    evthread_use_pthreads(); // abychom mohli pouzivat libevent s threads

    // clock_t => __kernel_long_t => long
    clock_t start;
    start = clock(); // counting tics from the start of this process

    memset(&server_data_info, 0, sizeof(server_data_info));
    memset(&server_control_info, 0, sizeof(struct sockaddr_in)); // ujisteni, ze struiktura je opravdu prazdna, bez garbage values, v struct adrrinfo bych diky 
    //tomu nastavit protokol TCP!
    server_control_info.sin_family = AF_INET;
    server_control_info.sin_port = htons(CONTROL_PORT); // htons => host to network short
    server_data_info.sin_family = AF_INET;
    server_data_info.sin_port = htons(DATA_PORT);
    // pokud je datovy typ nejaky typ pole nebo struktura, union apod., TAK TO MUSIM ZKOPIROVAT DO TOHO a nejde to jenom priradit!!
    // naplneni hints.sin_addr
    if (inet_pton(server_control_info.sin_family, "127.0.0.1", &server_control_info.sin_addr.s_addr) <= 0) { // pred a po hints.sin_addr nemusi byt ty zavorky a povazuji se za nadbytecne
        perror("inet_pton() selhal - ftp_control");
        exit(EXIT_FAILURE);
    }

    // "muze se do davat rovnou do te struktury, protoze ma jen jednoho clena a tam se kopiruji ty data a zrovna to vyjde na tu delku, ale kdyby tam byly dva cleny, tak je lepsi tam uvest samotneho clena te struktury", takhle je to napsane v serveru, ale tady to je to explicitne napsane, coz je best practice
    if (inet_pton(server_data_info.sin_family, "127.0.0.1", &server_data_info.sin_addr.s_addr) == 0) {
        perror("inet_pton selhal() - ftp_data");
        exit(EXIT_FAILURE);
    }

    

    int temp_data_socket;
    if ( (temp_data_socket = socket(server_data_info.sin_family, SOCK_STREAM, 0)) == -1) {
        perror("socket() selhal - ftp_data");
        exit(EXIT_FAILURE);
    }
    printf("\n\ntemp_data_socket: %d\n\n", temp_data_socket);
    ftp_sockets_obj.ftp_data_socket_or_com = temp_data_socket;

    // control_connection((void *)&control_args);
    
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



struct Data_Args data_args = { .ftp_d_socket = ftp_data_socket, .server_d_info = &server_data_info};
// void *(* f_data_connection)(void *) = &data_connection; // int, struct sockaddr **

 struct Control_Args *control_arg_struct = (struct Control_Args *)temp_p;

int ftp_control_socket = control_arg_struct->ftp_c_socket; // nejde rovnou typecastovat, protoze -> ma vetsi prednost nez (type cast) 
struct sockaddr_in *server_control_info = control_arg_struct->server_c_info; // VZDY se musi castovat void * pointer, protoze C nevi, na jaky datovy typ se ukazuje, nevi klik memory se ma priradit one promenne, kam chceme ty data ulozit, proto se to musi vzdy castovat
*/

// AVE CHRISTUS REX!