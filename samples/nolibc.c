// gcc -nostartfiles -nodefaultlibs nolibc.c -o nolibc

// $ nm -D /usr/lib/libc-2.17.so | grep 'T exit'
// 00031780 T exit

int _start()
{
    __asm__("movq $42,%rdi\n\t"
            "mov $60,%rax\n\t"
            "syscall");
}