// $ gcc -nostartfiles -nodefaultlibs hello-nolibc.c -o hello-nolibc

void ftl_exit(int code)
{
    __asm__(
        " \
            mov     %[code], %%edi \n\t\
            mov     $60, %%rax \n\t\
            syscall"
        :
        : [code] "r"(code));
}

void ftl_print(char *msg)
{
    int len = 0;
    while (msg[len])
    {
        len++;
    }

    __asm__(
        " \
            mov      $1, %%rdi \n\t\
            mov      %[msg], %%rsi \n\t\
            mov      %[len], %%edx \n\t\
            mov      $1, %%rax \n\t\
            syscall"
        :
        : [msg] "r"(msg), [len] "r"(len));
}

int main()
{
    ftl_print("Hello from C!\n");
    return 0;
}

void _start()
{
    ftl_exit(main());
}