// $ gcc -nostartfiles -nodefaultlibs ifunc-nolibc.c -o ifunc-nolibc
// $ readelf -a ./ifunc-nolibc

int ftl_strlen(char *s)
{
    int len = 0;
    while (s[len])
    {
        len++;
    }
    return len;
}

void ftl_print(char *msg)
{
    int len = ftl_strlen(msg);

    __asm__(
        " \
            mov      $1, %%rdi \n\t\
            mov      %[msg], %%rsi \n\t\
            mov      %[len], %%edx \n\t\
            mov      $1, %%rax \n\t\
            syscall"
        :
        : [msg] "r"(msg), [len] "r"(ftl_strlen(msg)));
}

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

char *get_msg_root()
{
    return "Hello, root!\n";
}

char *get_msg_user()
{
    return "Hello, regular user!\n";
}

typedef char *(*get_msg_t)();

static get_msg_t resolve_get_msg()
{
    int uid;

    __asm__(
        " \
            mov     $102, %%rax \n\t\
            syscall \n\t\
            mov     %%eax, %[uid]"
        : [uid] "=r"(uid)
        : // no inputs
    );

    if (uid == 0)
    {
        // UID 0 is root
        return get_msg_root;
    }
    else
    {
        // otherwise, it's a regular user
        return get_msg_user;
    }
}

// refer: https://blog.csdn.net/qq_36779888/article/details/105283764
char *get_msg() __attribute__((ifunc("resolve_get_msg")));

int main()
{
    ftl_print(get_msg());
    return 0;
}

void _start()
{
    ftl_exit(main());
}