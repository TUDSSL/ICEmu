#include <stdlib.h>
#include <stdint.h>
#include "printf.h"

volatile int var = 42;

const char *some_str = "Some string";

int main(void)
{
    printf("Test Hello World :)\n");
    printf("Test int arg - %d\n", 42);
    printf("Test 2 int arg - %d, %d\n", 42, 7);
    printf("Test string arg - %s\n", some_str);

    return var;
}
