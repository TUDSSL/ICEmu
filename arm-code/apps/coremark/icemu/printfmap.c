#include <stddef.h>

#pragma GCC push_options
#pragma GCC optimize "-O0"
__attribute__((noinline, used))
int putc(int character, void *stream)
{
    (void)stream;
    return character;
}

void _putchar(char character) {
    putc(character, &character);
}
#pragma GCC push_options
