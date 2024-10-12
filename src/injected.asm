BITS 64

SECTION .data
    msg db 'Je suis trop un hacker', 0
    newline db 0x0a, 0 ; carriage return and line feed characters
SECTION .text
global main

main:
    ;save context
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r11 

    ;write syscall
    mov rax, 1 ; syscall number (sys_write)
    mov rdi, 1 ; file descriptor (stdout)
    lea rsi, [rel msg] ; pointer to message to write
    mov rdx, 22 ; message length
    syscall

    ;write newline
    mov rax, 1 ; syscall number (sys_write)
    mov rdi, 1 ; file descriptor (stdout)
    lea rsi, [rel newline] ; pointer to newline character
    mov rdx, 2 ; length of newline character
    syscall

    ;load context
    pop r11
    pop rdi 
    pop rsi
    pop rdx
    pop rcx
    pop rax

    ;mov rax, 0x4022e0; original entry point
    ;jump to original entry point
    ;jmp rax

    ;return
    ret