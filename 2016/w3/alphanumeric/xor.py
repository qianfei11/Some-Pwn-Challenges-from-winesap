#!/usr/bin/env python
from pwn import *
xx = {}
for i in range(256):
	for x in string.letters + string.digits:
		for y in string.letters + string.digits:
			if i == ord(x) ^ ord(y):
				xx[i] = ((x, y), (ord(x), ord(y)))
for x in xx:
	print hex(x), xx[x]
