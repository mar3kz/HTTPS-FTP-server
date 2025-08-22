#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
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
    
    printf("\n%c", 'ž');
    printf("\n%d", 'ž'); // protoze to jsou 2 Bytes, tak to udela velke cislo, protoze ty bits, ktere jsou responsible pro to cislo, tak se vypisou decimalne hned za sebou -> velke cislo


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