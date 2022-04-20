#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
    xor rdi, rdi
    mov eax, 0x3c
    syscall

    4831FF
    B83C000000
    0F05
*/

const char *instructions = "\x48\x31\xFF\xB8\x3C\x00\x00\x00\x0F\x05";

int main()
{
    printf("        main @ %p\n", &main);
    printf("instructions @ %p\n", instructions);
    void (*f)(void) = (void *)instructions;
    printf("jumping...\n");
    f();
    printf("after jump\b");
}