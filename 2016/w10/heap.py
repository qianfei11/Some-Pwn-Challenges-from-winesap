import subprocess
import re
from gdb import *

chunkptr = lookup_type('struct malloc_chunk').pointer()

class PrintHeap (Command):

    def __init__ (self):
        super (self.__class__, self).__init__ ('ph', COMMAND_USER)

    def printchunk(self, addr):
        chunk = addr.cast(chunkptr).dereference()
        prevsize = chunk['prev_size']
        size = chunk['size']
        fd = chunk['fd']
        bk = chunk['bk']
        print (red('Chunk', 'bold'), blue('@', 'bold'), yellow('{}','bold').format(addr))
        if size&1:
            print (red('    prevsize:', 'bold'), purple('(inuse)', 'bold'))
        else:
            print (red('    prevsize:', 'bold'), green('{}', 'bold').format(int(prevsize)), yellow('({})', 'bold').format(prevsize))
        print (red('    size:', 'bold'), green('{}', 'bold').format(int(size&~7)), yellow('({})', 'bold').format(size))
        print (red('    fd:', 'bold'), yellow('{}', 'bold').format(fd))
        print (red('    bk:', 'bold'), yellow('{}', 'bold').format(bk))
        return chunk

    def printheap(self, addr):
        while True:
            chunk = self.printchunk(addr)
            print ('')
            size = chunk['size']&~7
            if size>10000:
                break
            addr += size

    def printbin(self, addr):
        b = addr.cast(chunkptr).dereference()
        chunk = b['fd']
        while chunk != addr:
            chunk = self.printchunk(chunk)['fd']
        print ('')
    
    def invoke(self, arg, from_tty):
        args = arg.split()
        cmd = args[0]
        if len(args)>1:
            addr = parse_and_eval(args[1])
        if cmd=='chunk':
            self.printchunk(addr)
        elif cmd=='mem':
            self.printchunk(addr-16)
        elif cmd=='heap':
            self.printheap(addr)
        elif cmd=='bin':
            self.printbin(addr)
        else:
            pass

PrintHeap()
