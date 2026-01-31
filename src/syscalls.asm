.code

EXTERN ntreadidx:DWORD
EXTERN ntwriteidx:DWORD
EXTERN ntallocateidx:DWORD
EXTERN ntprotectidx:DWORD

EXTERN ntreadsyscall:QWORD
EXTERN ntwritesyscall:QWORD
EXTERN ntallocatesyscall:QWORD
EXTERN ntprotectsyscall:QWORD

PUBLIC ntreadvirtualmemory
ntreadvirtualmemory PROC
	mov r10, rcx
	mov eax, ntreadidx
	jmp qword ptr [ntreadsyscall]
ntreadvirtualmemory ENDP

PUBLIC ntwritevirtualmemory
ntwritevirtualmemory PROC
	mov r10, rcx
	mov eax, ntwriteidx
	jmp qword ptr [ntwritesyscall]
ntwritevirtualmemory ENDP

PUBLIC ntallocatevirtualmemory
ntallocatevirtualmemory PROC
	mov r10, rcx
	mov eax, ntallocateidx
	jmp qword ptr [ntallocatesyscall]
ntallocatevirtualmemory ENDP

PUBLIC ntprotectvirtualmemory
ntprotectvirtualmemory PROC
	mov r10, rcx
	mov eax, ntprotectidx
	jmp qword ptr [ntprotectsyscall]
ntprotectvirtualmemory ENDP

END