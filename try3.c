// AVE CHRISTUS REX!!
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct Try_struct {
    int var1, var2;
};
struct Try_struct obj;

void func() {
    obj.var1 = 10;
    obj.var2 = 20;
}

void zero_memory(char *ptr) {
    memset(ptr, 0, 10);
    strcpy(ptr, "a");
}

int main() {
    obj.var1 = 5;
    obj.var2 = 15;
    func();

    char *text = malloc(10);
    strcpy(text, "ahoj");
    printf("%s\n", text);
    zero_memory(text);
    printf("%s\n", text);
    return 0;
}
// AVE CHRISTUS REX!!