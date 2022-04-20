#include <stdio.h>

// $ gcc entry_point.c
int main()
{
    printf("main is at %p\n", &main);

    return 0;
}