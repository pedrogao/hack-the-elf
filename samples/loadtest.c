#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>

int main()
{
    void *lib = dlopen("target/debug/libstage1.so", RTLD_NOW);
    if (!lib)
    {
        fprintf(stderr, "Could not load library\n");
        return 1;
    }

    void *sym = dlsym(lib, "premain");
    if (!sym)
    {
        fprintf(stderr, "Could not find symbol\n");
        return 1;
    }

    typedef void (*premain_t)(uint64_t);
    premain_t premain = (premain_t)(sym);
    fprintf(stderr, "Calling premain...\n");
    premain(0x1234);
}