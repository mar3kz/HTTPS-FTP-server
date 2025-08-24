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

#define CONTROL_PORT 2100
#define DATA_PORT 2000
#define MAX_LEN 256
#define STDIN 0
#define NFDS 4 // number of file descriptors
int num = 1;

typedef struct Ftp_Dtp_Data {
    char *path;
    char *owner;
    char *type;
    size_t file_length;
} ftp_dtp_data;
ftp_dtp_data obj;


struct Control_Args {
    int ftp_c_socket;
    struct sockaddr_in *server_c_info;
};

struct Data_Args {
    int ftp_d_socket;
    struct sockaddr_in *server_d_info;
};

enum Ftp_Code_Login {
    FSC = 535, // failed security check
    INU_O_PS = 430, // invalid username or password
    ULOG_IN = 230, // user logged in
};
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

static void send_file(char *path) {
    // O => open() flags
    // S => file mode bits
    // F => fcntl() prikazy
    DIR *dirstream_check = opendir(path);
    printf("\npath: %s\n", path);
    struct dirent *entry = readdir(dirstream_check);

        // pokud to nebude k otevreni, tak by to melo file permissions 4777 // umask nemuze NIJAK ovlivnit setuid bit
        // open(path, O_CREAT | O_APPEND | O_RDONLY, S_IRWXU | S_IRWXG, S_IRWXO, S_ISUID); // 4777 => spusteni s pravy vlastnika, vsichny read, write, execute
        int fd = open(path, O_RDONLY | O_NOFOLLOW); // jen cteni, pokud je pathname symbolicky link, open() selze
        if (fd == -1) {
            perror("open() selhal - send_file()");
            exit(EXIT_FAILURE);
        }

        struct stat status_file;
        int fstat_rv = fstat(fd, &status_file);
        if (fstat_rv == -1) {
            perror("fstat() selhal - send_file()");
            exit(EXIT_FAILURE);
        }

        off_t offset_length_file = status_file.st_size;

        char *file_data = (char *)malloc(offset_length_file + 1);

        ssize_t read_rv; // read muze vratit mene Bytes nez chceme
        for (; (read_rv = (read(fd, file_data, offset_length_file))) != offset_length_file;) {
            if (read_rv == -1) {
                perror("read() selhal - send_file()");
                exit(EXIT_FAILURE);
            }
            else if (read_rv == 0) {
                fprintf(stderr, "EOF read - send_file()");
                exit(EXIT_FAILURE);
            }
        }
        file_data[read_rv] = '\0';

        char *username = (char *)malloc(MAX_LEN);
        getlogin_r(username, MAX_LEN);
        if (username == NULL) {
            perror("getlogin_r() selhal - ftp_dtp_data_struct");
            exit(EXIT_FAILURE);
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


void receive_codes_data(int com_socket, enum ) {

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
    memset(ptr_memory_address, sizeof(char) * 100, 0);
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
void *control_connection(void *temp_p) {
    // client nemusi mit setsockopt SO_REUSEADDR, protoze se binduje k nejakemu stanovemu portu, client ma svuj lokalni port, takze se vzdycky zmeni
    struct Control_Args *control_arg_struct = (struct Control_Args *)temp_p;

    int ftp_control_socket = control_arg_struct->ftp_c_socket; // nejde rovnou typecastovat, protoze -> ma vetsi prednost nez (type cast) 
    struct sockaddr_in *server_control_info = control_arg_struct->server_c_info; // VZDY se musi castovat void * pointer, protoze C nevi, na jaky datovy typ se ukazuje, nevi klik memory se ma priradit one promenne, kam chceme ty data ulozit, proto se to musi vzdy castovat

    printf("+-----------------------------------------+");
    printf("| this version of FTP implements:         |");
    printf("| DATA REPRESENTATION: ASCII NONPRINT (N) |");
    printf("| TRANSMISSION MODE  : STREAM             |");
    printf("| DATA STRUCTURE     : FILE-STRUCTURE     |");
    printf("| COMMANDS: USER, PASS, QUIT, PORT, RETR  |");
    printf("|           STOR, NOOP, TYPE              |");
    printf("+-----------------------------------------+");
    // tento socket bude blocking, protoze budeme vzdy cekat na odpoved od serveru
    // nedela nic specialniho; pokud bude false, tak se to ukonci; nedela nic specialniho



    printf("+------------------------------------------------+");
    printf("| USER string = log in - necessary 1st command!  |"); // 2
    printf("| PASS string = log in - necessary 2nd command!  |"); // 2
    printf("| QUIT        = log out (files will be sent)     |"); // 1
    printf("| PORT        = change default port for data tr. |"); // 7
    printf("| RETR        = retrieve last specified file by  |"); // 1
    printf("| STOR        = send a file to server            |"); // 2
    printf("| NOOP        = server will send OK code & msg   |"); // 1
    printf("| TYPE        = ASCII N(on-print)/Image (bits)   |"); // 3
    printf("+------------------------------------------------+");

    // transmission mode - stream indikuje EOF jako ukonceni konekce, dalsi soubor musi na dalsi konekci, ale pozor toto muzeme delat, jenom kdyz mame tu socket adresu muzeme reusovat a ze se nema cekat na ten TCP delay
    // kdyz se ukonci TCP socket, tak se jeste TIME_WAIT chvilku bude cekat nez prijde ACK od druheho hosta, aby oba vedeli, ze ta konekce bude ukoncena
    printf("\nDATA STRUCTURE      = file-structure (contiguous bits)");
    // transmission mode definovano takhle, protoze kdyby to bylo block, tak to by odpovidalo TCP s Nagle algorithm a stream by bylo TCP bez Nagle algorithm => jakoby nonblocking
    printf("\nTRANSMISSION MODE   = stream (with Nagle algortithm - TCP segments will wait for data to be as full)");
    printf("\nDATA REPRESENTATION = ASCII Non-print (only ASCII chars)/Image (bit data)");

    // nebo 100
    char *user_request = (char *)malloc(sizeof(char) * 100);
    

    int new_user_connection = 0;
    for (;;) {
        if (!new_user_connection) {
            int recv_code;

            /*
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



            */


            // u connect to musi byt oboustranne dane zavorkami, protoze == ma vetsi prioritu nez =
            int ftp_control_com;
            // (**) se z toho stane struktura, (**) je dereference jako (*(*ptr))
            // blocking, protoze client zacina control connection
            if ( (ftp_control_com = connect(ftp_control_socket, (struct sockaddr *)server_control_info, sizeof((*server_control_info)) )) == -1 ) { // () meni poradi operandu
                perror("connect() selhal - ftp_control");
                exit(EXIT_FAILURE);
            }


            scanf("Name: %99[^\n]", user_request); // chceme cist maximalne 99 charakteru, protoze +1 pro \0 a chceme cist vsechny charaktery nez nenarazime na \n, potom uz to nechceme cist a nebudeme to cist \n, mezera mezi " a % znamena, ze chceme ignorovat kazdy whitespace v stdout bufferu (vsechny znaky, ktere kdyz vyprintujeme, tak proste nemaji ten normalni charakter)
            send_ftp_info(user_request, strlen(user_request) + 1);
            zero_memory(user_request);


            scanf("Password: %99[^\n]", user_request);
            send_ftp_info(user_request, strlen(user_request) + 1);
            zero_memory(user_request);

            enum FTP_Code_Login recv_code = recv_ftp_info(ftp_control_com);
            switch (recv_code) {
                case FSC:
                    send_ftp_code("535 - Failed security check", ftp_control_com);
                    break;
                case INU_O_PS:
                    send_ftp_code("430 - Invalid username or password", ftp_control_com);
                    break;
                case ULOG_IN:
                    send_ftp_code("230 - User logged in, proceed", ftp_control_com);
                    send_ftp_code("220 -    Service ready for new user", ftp_control_com);
                    new_user_connection = 1;
                    continue; // nemusi byt break, protoze se rovnou skoci na dalsi iteraci toho for loopu (udelala by se i kdyztak inkrementace u toho for loopu)
                default:
                    send_ftp_code("501 - Syntax error in parameter or arguments", ftp_control_com);
            }
            printf("425 - Can't open data connection", ftp_control_com);
        }
        
        scanf(" %99[^\n]", user_request);
        enum Ftp_Commands ftp_commands = get_ftp_command(user_request);

       
    }
}

void *data_connection(void *temp_p) {
    // proc se to typecastuje na struct sockaddr *, protoze sockaddr_in a sockaddr_in6 a sockaddr maji stejne rozlozeni pole family, takze se podle toho, jaka struktura se ma interne pouzivat, vsechno jsou to jenom data
    struct Data_Args *data_arg_struct = (struct Data_Args *)temp_p; // nejde to rovnou typecastovat, protoze -> ma vetsi prednost nez (type cast)

    int ftp_data_socket = (int)data_arg_struct->ftp_d_socket;
    struct sockaddr_in *server_data_info = (struct sockaddr_in *)data_arg_struct->server_d_info; // 1. ->, 2. *
    
    int ftp_data_com;
    if ( (ftp_data_com = connect(ftp_data_socket, (struct sockaddr *)server_data_info, sizeof(server_data_info))) == -1) {
        perror("connect() selhal - ftp_data");
        exit(EXIT_FAILURE);
    }


    printf("ftp_data_com %d", ftp_data_com);
    printf("\n\n\n\nvse probehlo ok, jsem pripojeny \n\n\n\n");
}

int main() {
    // clock_t => __kernel_long_t => long
    clock_t start;
    start = clock(); // counting tics from the start of this process


    struct sockaddr_in server_control_info;
    memset(&server_control_info, 0, sizeof(struct sockaddr_in)); // ujisteni, ze struiktura je opravdu prazdna, bez garbage values, v struct adrrinfo bych diky 
    //tomu nastavit protokol TCP!

    server_control_info.sin_family = AF_INET;
    server_control_info.sin_port = htons(CONTROL_PORT); // htons => host to network short

    // pokud je datovy typ nejaky typ pole nebo struktura, union apod., TAK TO MUSIM ZKOPIROVAT DO TOHO a nejde to jenom priradit!!
    // naplneni hints.sin_addr
    if (inet_pton(server_control_info.sin_family, "127.0.0.1", &server_control_info.sin_addr.s_addr) <= 0) { // pred a po hints.sin_addr nemusi byt ty zavorky a povazuji se za nadbytecne
        perror("inet_pton() selhal - ftp_control");
        exit(EXIT_FAILURE);
    }


    struct sockaddr_in server_data_info;
    memset(&server_data_info, 0, sizeof(struct sockaddr_in));

    server_data_info.sin_family = AF_INET;
    server_data_info.sin_port = htons(DATA_PORT);

    // "muze se do davat rovnou do te struktury, protoze ma jen jednoho clena a tam se kopiruji ty data a zrovna to vyjde na tu delku, ale kdyby tam byly dva cleny, tak je lepsi tam uvest samotneho clena te struktury", takhle je to napsane v serveru, ale tady to je to explicitne napsane, coz je best practice
    if (inet_pton(server_data_info.sin_family, "127.0.0.1", &server_data_info.sin_addr.s_addr) == 0) {
        perror("inet_pton selhal() - ftp_data");
        exit(EXIT_FAILURE);
    }


    // pokazde kdyz se client pripoji, tak dostane novy nahodny port od OS, proto musi server udelat setsockopt SO_REUSABLE, protoze server nemenni port a binduje
    // ten stejny

    // client zahajuje control connection u FTP, potom se muze rozhoudnout, jestli zahaji server nebo client data connection
    int ftp_control_socket; // vytvori se jakoby zakladni socket descriptor popisujici, ze bude komunikace pres sit a potom pomoci connect
    // se klientovi priradi ten nahodny ephemeral port a ten socket descriptor se jakoby zmeni na communication socket descriptor
    // socket take zalozi interni strukturu o tomto pripojeni
    if ( (ftp_control_socket = socket(server_control_info.sin_family, SOCK_STREAM, 0)) == -1 ) { // type => SOCK_STREAM znazi jaky typ socketu to bude => pouzivajici TCP (bytes streams) nebo UDP (datagrams)
        perror("socket selhal() - ftp_control");
        exit(EXIT_FAILURE);
    }
    // 0 => OS vybere nejlepsi protokol pro ty specifikace, jinak ty protokoly jsou definovane v glibc netine/in.h

    int ftp_data_socket;
    if ( (ftp_data_socket = socket(server_data_info.sin_family, SOCK_STREAM, 0)) == -1) {
        perror("socket() selhal - ftp_data");
        exit(EXIT_FAILURE);
    }

    // control_connection((void *)&control_args);
    
    pthread_t thread_control, thread_data; // ID of thread

    struct Control_Args control_args = { .ftp_c_socket = ftp_control_socket, .server_c_info = &server_control_info };

   

    struct Data_Args data_args = { .ftp_d_socket = ftp_data_socket, .server_d_info = &server_data_info};

    void *(* f_control_connection)(void *) = &control_connection; // int, struct sockaddr **
    void *(* f_data_connection)(void *) = &data_connection; // int, struct sockaddr **

    if ( pthread_create(&thread_control, NULL, f_control_connection, (void *)&control_args)); { // NULL je atribut pro atribut strukturu, ktera specifikuje urcite atributy nove vytvoreneho thread, jako scheduling policy, inherit scheduler
        perror("pthread_create() selhal - thread_control");
        exit(EXIT_FAILURE);
    }

    // pthread vraci 0 pri success
    if ( pthread_create(&thread_data, NULL, f_data_connection, (void *)&data_args)) {

    }


    // data_connection(&data_args);

    ftp_dtp();

    // > ma vetsi prioritu nez =
    return EXIT_SUCCESS;
}