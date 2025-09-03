// AVE CHRISTUS REX!!
#include <stdio.h>
#include <string.h>

struct Try_struct {
    int var1, var2;
};
struct Try_struct obj;

void func() {
    obj.var1 = 10;
    obj.var2 = 20;
}

int main() {
    obj.var1 = 5;
    obj.var2 = 15;
    func();

    return 0;
}
// AVE CHRISTUS REX!!