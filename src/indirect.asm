.code

; indirect syscalls

EXTERN ntread_idx:DWORD
EXTERN ntwrite_idx:DWORD
EXTERN ntalloc_idx:DWORD
EXTERN ntprot_idx:DWORD

EXTERN ntread_syscall_inst_addr:QWORD
EXTERN ntwrite_syscall_inst_addr:QWORD
EXTERN ntalloc_syscall_inst_addr:QWORD
EXTERN ntprot_syscall_inst_addr:QWORD

PUBLIC ntread_i
ntread_i PROC
	mov r10, rcx
	mov eax, ntread_idx
	jmp qword ptr [ntread_syscall_inst_addr]
ntread_i ENDP

PUBLIC ntwrite_i
ntwrite_i PROC
	mov r10, rcx
	mov eax, ntwrite_idx
	jmp qword ptr [ntwrite_syscall_inst_addr]
ntwrite_i ENDP

PUBLIC ntalloc_i
ntalloc_i PROC
	mov r10, rcx
	mov eax, ntalloc_idx
	jmp qword ptr [ntalloc_syscall_inst_addr]
ntalloc_i ENDP

PUBLIC ntprot_i
ntprot_i PROC
	mov r10, rcx
	mov eax, ntprot_idx
	jmp qword ptr [ntprot_syscall_inst_addr]
ntprot_i ENDP

END