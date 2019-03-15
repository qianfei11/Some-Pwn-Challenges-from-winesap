#!/usr/bin/env python
from pwn import *
import string
for x in string.letters + string.digits:
	print x, disasm(x + 'ABCDEFG').split('\n')[0][6:]
