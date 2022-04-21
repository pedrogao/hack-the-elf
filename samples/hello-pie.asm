; $ nasm -f elf64 hello-pie.asm
; $ ld -pie hello-pie.o -o hello-pie
; $ ld --dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie hello-pie.o -o hello-pie
; $ objdump -d ./hello-pie

        default rel ; 消除 rip

        global _start

        section .text

_start: mov rdi, 1      ; stdout fd
        lea rsi, [rel msg]
        mov rdx, 9      ; 8 chars + newline
        mov rax, 1      ; write syscall
        syscall

        xor rdi, rdi    ; return code 0
        mov rax, 60     ; exit syscall
        syscall
        
        section .data

msg:    db "hi there", 10