// ./chimera; echo $?

extern int number;

extern void change_number(void);

void ftl_exit(int code)
{
    __asm__(
        " \
            mov %[code], %%edi \n\
            mov $60, %%rax \n\
            syscall"
        :
        : [code] "r"(code));
}

void _start(void)
{
    change_number();
    change_number();
    change_number();
    ftl_exit(number);
}