; nasm -f elf64 bss2.asm
; ld -pie --dynamic-linker /lib/ld-linux.so.2 bss2.o -o bss2
        global _start

        section .text

_start: lea rax, [rel zero]
        mov rax, [rax]

        xor rdi, rdi    ; return code 0
        mov rax, 60     ; exit syscall
        syscall

        section .bss

pad:    resq 65536
zero:   resq 16