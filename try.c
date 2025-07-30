#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct xd {
    int type;
};

enum Jmeno {
    ACCOUNT = 1,
    NOT_ACCOUNT = 2,
};
enum Jmeno variable = ACCOUNT;

struct xd data = { .type = 0};

typedef enum Zkouska {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
} Zkouska_zkr;
enum Zkouska Zkouska_promenna;

void funkce() {
    printf("3. data.type: %d\n", data.type);
    data.type = 5;
    printf("4. data.type: %d\n", data.type);
}
int main() {
    printf("1. %d\n", data.type);

    struct xd necodalsi;
    printf("2. %d\n", necodalsi.type);

    funkce();

    char *path = "/marek";
    size_t lenpath = strlen(path);
    printf("\nLenpath: %zu", lenpath);

    printf("\nCharakter: %c\n", path[lenpath]);

    printf("\nVariable: %d", variable);

    while (1) {
        printf("\nVariable: %d", variable);
        variable = NOT_ACCOUNT;
        printf("\nVariable: %d", variable);
        break;
    }
    // printf("\nVariable: %d", variable);

    // FILE *filepointer = fopen("/home/marek/Documents/FTP_SERVER/logs.txt", "w");

    // fwrite("ahoj", sizeof(char), 4, filepointer);

    FILE *filepointer = fopen("/home/marek/Documents/FTP_SERVER/TXT/accounts.txt", "r");
    char line[20];

    int index = 0;
    while (fgets(line, 20, filepointer) != NULL) {
        printf("\n\nindex: %d, string: %s\n", index, line);
        index++;
    }

    printf("\n\nZkouska Promenna: %d", Zkouska_promenna);


    // union {
    //     int number;
    //     char character;
    //     unsigned char pole[sizeof(int)];
    // } data;

    // data.number = 65;

    // // POLE MUSI BYT INICIALIZOVANE POMOCI KONSTATNICH HODNOT NEBO POMOCI MEMCPY
    // // pole[i] = NENI POINTER, pole = JE POINTER, &pole[i] = JE POINTER

    // // unsigned char pole[4];
    // // memcpy(pole, &data.number, sizeof(int));

    // for (int i = 0; i < sizeof(int); i++) {
    //     printf("%x %p\n", data.pole[i], (void *)&(data.pole[i]));
    // }

    // char x = data.character;

    // printf("\n%c %p", data.character, (void *)&(data.character));
    // return 0;
}