#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> // htons()

int MAX = 5;

void *function1(void *) {
    for(;;) {
        printf("\nthread1");
        sleep(5);
    }
}

void *function2(void *) {
    for(;;) {
        printf("\nthread2");
        sleep(5);
    }
}

void *function3(void *) {
    for(;;) {
        // printf("\nthread3");
        sleep(5);
    }
}

void *function4(void *) {
    for(;;) {
        printf("\nthread4");
        sleep(5);
    }
}
void *function5(void *) {
    for(;;) {
        printf("\nthread5");
        sleep(5);
    }
}

void *function6(void *) {
    for(;;) {
        sleep(5);
    }
}


struct Try2 {
    int a;
};

void change_value(struct Try2 *p) {
    // p->a = 10; // zmeni se GLOBALNE!! automaticke dereferencovani
    struct Try2 x = { .a = 20 }; // zmeni se LOKALNE!!
    p = &x;
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

short int return_port(char **metadata_command) {
    short int port;
    unsigned char *port_array = malloc(sizeof(unsigned char ) * 2);
    for (int i = 4, i_port_arr = 0; i < 6; i++) {
        port_array[i_port_arr++] = atoi(metadata_command[i]); // ASCII to Int
    }
    memcpy(&port, port_array, sizeof(unsigned char ) * 2); // takhle se kopiruji data celeho array do jedne promenne

    return htons(port); // aby uz to bylo na network 
}

int main()
{
    // size_t sizearray = 3;
    // pthread_t *arraythread = (pthread_t *) calloc(sizearray, sizeof(pthread_t));

    // void *array[] = {function1, function2, function3, function4, function5, function6};

    // for (int i = 0; i < sizearray; i++) {
    //     pthread_create(&arraythread[i], NULL, array[i], NULL);
    // }

    // //pthread_detach(threadID);
    // for (;;) {
    //     printf("\nmain thread");
    //     sleep(5);
    //     break;
    // }

    // printf("\n\n\n");

    // for (int i = 0; i < sizearray; i++) {
    //     if (pthread_cancel(arraythread[i]) != 0) {
    //         exit(EXIT_FAILURE);
    //     }
    // }

    // pthread_t *new_p = (pthread_t *) realloc(arraythread, sizeof(pthread_t) * 6);
    // sizearray = 6;
    
    // for (int i = 0; i < sizearray; i++) {
    //     pthread_create(&new_p[i], NULL, array[i], NULL);
    // }

    // for (;;) {
    //     printf("\nmain thread\n");
    //     sleep(5);
    // }
    // exit(EXIT_SUCCESS);



    // pthread_t *threadarray;
    // threadarray = (pthread_t *)calloc(MAX, sizeof(pthread_t));
    // int i = 0;
    // for (;;) {
    //     if (pthread_create(&threadarray[i], NULL, function6, NULL) != 0) {
    //         exit(EXIT_FAILURE);
    //     }

    //     if (&threadarray[i] == NULL) {
    //         printf("tady je neco spatne");
    //         exit(EXIT_FAILURE);
    //     }
    //     printf("%d\n", MAX);
        
    //     if (MAX - 1 == i) {
    //         MAX += 5;
    //         pthread_t *new_p = realloc(threadarray, MAX * sizeof(pthread_t));
    //         threadarray = new_p;           
    //     }
    //     i++;
    //     sleep(2);
    // }

    // struct Try {
    //     int a;
    // };
    // struct Try *obj = malloc(sizeof(struct Try));
    // obj->a = 10;

    // // struct Try *p = &obj;
    // struct Try **pp = &obj;

    struct Try2 *p = (struct Try2 *)malloc(sizeof(struct Try2)); // na heapu
    p->a = 5;
    printf("\n\na pred: %d", p->a);

    change_value(p);
    printf("\n\na po: %d", p->a);

    // struct Try2 **pp; // na stacku
    // pp = &p;
    struct Try2 **pp = malloc(sizeof(struct Try2 *)); // na heapu
    pp = &p;
    
    // printf("\n%c", 'ž');
    // printf("\n%d", 'ž'); // protoze to jsou 2 Bytes, tak to udela velke cislo, protoze ty bits, ktere jsou responsible pro to cislo, tak se vypisou decimalne hned za sebou -> velke cislo

    if (13 == 0xD) {
        printf("yes");
    }
    else {
        printf("no");
    }

    char **array = metadata_command("PORT 0,0,0,0,0,0\r\n");
    printf("zacatek");
    fflush(stdout);
    printf("\n\nzacatek%s\n", array[0]);
    printf("%s\n", array[1]);
    printf("%s\n", array[2]);
    printf("%s\n", array[3]);
    printf("%s\n", array[4]);
    printf("%s\n", array[5]);
    fflush(stdout);

    printf("AVE CHRISTUS REX!");
    for (int i = 0; i < 6; i++) {
        printf("AVE CHRISTUS REX!");
        printf("tady: %s", array[i]);
    }
    fflush(stdout);



    printf("\n\n\n%d", return_port(array));

    // if ( strstr("tigujtg\r", "\r") == NULL) {
    //     printf("\nneni");
    // }
    // else {
    //     printf("\nje");
    // }


    // int a = 10;
    // int *p = &a;
    // int **pp = &p;

    // printf("\na: %d\n", a);
    // printf("\nkam ukazuje p: %p\n", (void *)p);
    // printf("\nhodnota, na memory adrese, kam ukazuje p: %d\n", *p);
    // printf("\nmemory adresa p: %p\n", (void *)&p);
    // printf("\nkam ukazuje pp: %p\n", (void *)pp);
    // printf("\nhodnota, kam ukazuje pp: %d\n", **pp);
    // printf("\nmemory adresa, kde je p: %p\n", (void *)&pp);

    // printf("%d", (**pp).a);

}