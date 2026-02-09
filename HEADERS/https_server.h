// toto by stali vetsi kompilatoru toto podporuje => includeni tento header file jenom jednou, at nejsou duplicit errors # pragma once 
#ifndef HTTPS_SERVER
#define HTTPS_SERVER
// podiva se, jestli je definovane makro HTTPS_SERVER, pokud ne, tak se tam copy paste vsechno, co tedka napisu

typedef enum Media_Enum {
    NONE = -1,
    HTML = 0,
    CSS = 1,
    FAVICON = 2,
    TXT = 3,
    PATH = 4,
} Media_Spec;
enum Media_Enum Media_spec;

struct HTTPS_response {
    char *content;
    size_t content_length;
    int communication_socket;
};

typedef enum HTML_Enum {
    // NONE = -1,
    HTML_FORMULAR_PRIHLASENI = 0,
    HTML_FORMULAR_TVORBA_UCTU = 1,
    HTML_FILES_HTML = 2,
    HTML_INVALID_LOGINS = 3,
    HTML_ACCOUNT_TAKEN = 4,
    HTML_UNKNOWN_TYPE = 5,
} HTML_Spec;
enum HTML_Enum HTML_spec = HTML_FORMULAR_PRIHLASENI;

typedef union Html_Path_Union {
    char *html_file_path;
} Html_path_union;
Html_path_union html_path_union;

typedef struct HTTPS_Global_Info {
    struct HTTPS_Thread_Specific *THREADSPECIFIC_ARRAY;
    int *COMSOCKARRAY; // potom soucasti struct
    SSL **SSL_CONNECTIONS_ARRAY; // potom soucasti struct
    struct event_base **EVENT_CONTEXT;
} HTTPS_Global_info;
struct HTTPS_Global_Info HTTPS_global_info;

typedef struct HTTPS_Thread_Specific {
    int connection;
    int comsocket;
    pthread_t thread_id;
    SSL *specific_ssl_connection;
} HTTPS_Thread_specific;
struct HTTPS_Thread_Specific *HTTPS_thread_specific;

#endif

// compiler manager je software, ktery za me udela vsechny kroky k tomu, aby se z .c stalo .out (gcc, g++...)
// compilation unit = source file
/*
4 procesy:
1. preprocesor = prepsani vseho co zacina na # na opravdovy text, krome takove te ifdef ifndef endif pragma once logiky, copy paste textu, nic specialniho krome teto logiky
2. kompilator = vezme3 .c a prevede ho na .o file, coz jsou assembly instrukce se symboly reprezentujici volani funkci
3. assembler = prevede .o assembly instrukce na machine code (0 a 1)
4. linker = vezme vsechny tzto .o file, koukne na ty symboly a nahradi je opravdovymy funkcemi, u statickych libraries a .c files se to zkopiruje jako preprocesor, u dynamickych RIP pointer skoci pryc do .so file
*/

// proc se v header files pouzivaji jenom deklarace a ne definice?
/*
1. Pokazdy, co by se zmenil kod, by se musel kompilovat cela library => narocne casove, ale i prostredkove
2. Kdyby byl jeden source file s entry pointem (main() funkce) a dalsich par .c files, kde by byly jenom definice funkci a do techto dvou files by se includoval prave nejaky header file s definicemi funkci, tak by linker potom videl v prvnim file s entry pointer (main() funkci), ze vola nejakou funkci, ale ta funkce by byla jak u sebe sama, tak i u toho druhe source file bez entry pointu, tak by linker vyhodil error jako duplicitni error
*/