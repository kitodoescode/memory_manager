.code

; direct syscalls

PUBLIC ntread
ntread PROC
	mov r10, rcx
	mov eax, 63
	syscall
	ret
ntread ENDP

PUBLIC ntwrite
ntwrite PROC
	mov r10, rcx
	mov eax, 58
	syscall
	ret
ntwrite ENDP

PUBLIC ntalloc
ntalloc PROC
	mov r10, rcx
	mov eax, 24
	syscall
	ret
ntalloc ENDP

PUBLIC ntprot
ntprot PROC
	mov r10, rcx
	mov eax, 80
	syscall
	ret
ntprot ENDP

END