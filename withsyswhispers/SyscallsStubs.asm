.code

EXTERN SW2_GetSyscallNumber: PROC


NtCreateFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F0A1B781h        ; Load function hash into ECX.
        call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp +8]          ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        nop                  ; Invoke system call.
        ret
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
NtCreateFile ENDP

end