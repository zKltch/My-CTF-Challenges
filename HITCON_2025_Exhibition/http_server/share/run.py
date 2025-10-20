from pwn import *

r = process(["./ld-linux-x86-64.so.2", "./server"], env={"LD_PRELOAD":"./libc.so.6"})

r.interactive()
