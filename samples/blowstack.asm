; in `samples/blowstack.asm`
; $ nasm -f elf64 blowstack.asm
; $ ld blowstack.o -o blowstack

        global _start

        section .text
    
_start:
        push 0
        jmp _start