# Medea
### Writeup by arcayn, 700 points
`We found a strange binary, claiming to use a custom "Medea" instruction set. We found a spec for it at https://github.com/Kantaja/MedeaCTF, can you help us solve this?`

For this challenge, we are given a binary and a link to [documentation](https://github.com/Kantaja/MedeaCTF) for the instruction set it uses. Let's figure out how to get the flag.

The first step here was to take a look at the binary. We can see it has the `6D 43 54 5A` magic bytes which indicate ZStandard compression. We'll get rid of them an decompress it. Now we can take a look at the section headers. The first byte is `02`, and then we have `00 A8` (little endian) indicating that the first 168 16-bit words is the program itself. At the end of these 168 words we have `01 0C 00`, indicating 12 words of `SIN` data at the end of the file, which actually has nothing to do with `stdin`, but is more like the binary's general data section.

Now we know what we're looking at, it's time to write a disassembler. I wrote one in python, and much of the process was just reading the docs correctly, but here is the code, which I will comment on throughout.

```python
# disassembles medeactf files excluding their image magic bytes
# and decompressed if they are compressed

path = input("Enter file to disassemble: ")
f = open(path, 'rb')

# the current word offset
counter = 0

# reads an little-endian int of n bytes, not really used
def read_int(n):
    return int.from_bytes(f.read(n), byteorder="little")

# reads a word (16-bits) from the binary
def read_word():
    global counter
    counter += 1
    return read_int(2)

# reads l bits from a word, at a specified offset from the MSB
def read_bits(word, l, offset=0):
    return ((word << offset) % 2**16) >> (16 - l)

INSTS = [
    ["HALT", 0],
    ["NOOP", 0],
    ["INC", 1],
    ... # this is the master list of opcodes, indexed by binary
]       # values and padded in the list with NOOPS where needed.
        # The second element is the number of operands accepted

# register codes
REGS = [
    "NULL",
    "RX",
    "RY",
    "RZ",
    "RTRGT",
    "RSTAT",
    "RCALL"
]

# read first section magic bytes
SEC = read_int(1)
LEN = read_int(2)

# this will store the list of lines of the program
prog = []

# break condition when section end reached
while counter < LEN:
    # instruction offset
    begin_ctr = counter + 1
    
    # read the instruction word from the binary, including the argument
    # flags, the signed flag and the opcode
    instruction = read_word()
    aflg = [read_bits(instruction, 2), read_bits(instruction, 2, 2), read_bits(instruction, 2, 2)]
    sign = read_bits(instruction, 1, 6)
    op = read_bits(instruction, 9, 7)

    # get data from the instructions array
    opcode, arglen = INSTS[op]

    # determine whether any flags are set which indicates whether
    # a word containing the register operands follows the instruction word
    reg_flags = [1 if a < 2 else 0 for a in aflg[:arglen]]
    reg_num = sum(reg_flags)
    uses_registers = reg_num > 0

    # calculate the bit offset in the register word that points to
    # the register which is used for argument i
    reg_pos = [(3 - reg_num + sum(reg_flags[:i])) * 4 for i in range(arglen)]
    
    if uses_registers:
        register_word = read_word()
    
    # metadata about the instructions will get written as a comment
    comment = ""
    comment += " SIGNSET" if sign == 1 else ""
    args = []

    for idx in range(arglen):
        if aflg[idx] < 2:
            reg = read_bits(register_word, 4, reg_pos[idx])
            args.append(REGS[reg])
        else:
            addr = read_word()
            hex_repr = "0x" + '{0:04x}'.format(addr)
            args.append(hex_repr)
            comment += " " + hex_repr + ":" + ("SIN" if aflg[idx] == 2 else "SMAIN")
    # write the instruction as well as offset and comment to the program
    line = '{0:06x}'.format(begin_ctr) + "  " + opcode + " " + ", ".join(args) + (" ;" + comment if len(comment) > 0 else "")
    prog.append(line)
    
print ("\n".join(prog))
print ()
print (list(used_opcodes))

# read in data about the SIN data section
SEC = read_int(1)
LEN = read_word()

print ()
counter = 0
while counter < LEN:
    begin_ctr = counter + 1
    
    # and print it out
    print ('{0:04x}'.format(begin_ctr), '{0:04x}'.format(read_word()))
```
Now we've got a disassembler, let's look through the disassembly. Let's have a look at this first chunk of code
```assembly
000001  ICPY 0x003e, RTRGT
000004  CALL NULL, NULL, NULL
000006  POP RY
000008  ICPY 0x000c, RZ
00000b  CMP RY, RZ
00000d  ICPY 0x0017, RTRGT
000010  JEQU 
000011  ICPY 0x005a, RTRGT
000014  CALL NULL, NULL, NULL
000016  HALT 
```
We're calling `0x3e`, then jumping to `0x17` if the top value of the stack after that call is equal to `0C` (12), otherwise we call `0x5a` and `HALT`. Let's take a look at `0x3e` first:

```assembly
00003e  ICPY 0x000a, RY
000041  ICPY 0x0000, RZ
000044  INC RZ
000046  READ RX
000048  CMP RX, RY
00004a  ICPY 0x0057, RTRGT
00004d  JEQU 
00004e  CPY RZ, RTRGT
000050  RCPT RX, 0x0001          ; SIGNSET 0x0001:SMAIN
000053  ICPY 0x0044, RTRGT
000056  JUMP 
000057  CPY RZ, RTRGT
000059  RTRN 
```
First we load `0A` to `RY` and `0` to `RZ`. Then we increment `RZ` and read a byte of input into `RX`, compare it with `RY` and jump to `0x57` and return if they are equal, otherwise we save `RX` into general purpose `SMAIN` memory, and jump back to the start (except for the initialization instructions). 

`0A` is the ASCII code for `\n`, so this suggests that this is a `getline` function. It copies bytes from `stdin` to a point in memory until it reaches a newline, at which point it returns. First, however, it copies `RZ` into `RTRGT`. Let's see how `RTRN` is implemented and what happens to that value of `RZ`.

1.  Move `RSR` into `RSK`.
2.  Pop `RX` off the stack.
3.  Set the instruction pointer to the value of `RCALL` plus the value of `RX`.
4.  Pop `RCALL`, `RSTAT`, `RX`, `RY` and `RZ` off the stack, in reverse order.
5.  Push `RTRGT` onto the stack.
6.  Clear `RTRGT`.

So there you go, `RZ` will get pushed onto the stack when `RTRN` is called, and popped off as `RY` when we go back to the main execution flow. As `RZ` was incremented every time a byte of input was accepted, `RY` will end up being a defacto input length parameter, and the line at `0x0b` checks that the length of the input is 12, and if it isn't, jumps down to this function at `0x5a` before `HALT`ing. 
```assembly
00005a  ICPY 0x6e49, RX
00005d  ICPY 0x00a2, RTRGT
000060  CALL RX, NULL, NULL
```
This calls the function at `0xa2` with a parameter of `0x6e49` in `RX`. 
```assembly
0000a2  WRIT RX
0000a4  BSWP RX
0000a6  WRIT RX
0000a8  RTRV
```
This function writes the low 8 bits of `RX`, swaps the low and high bits, and then writes the low 8 bits again, outputting `49 6E`, or `"In"`. The rest of the program between `0x5a` and `0xa2` is a number of other calls in the same three line format as the one we just saw, each of which printing two characters of the string `"Incorrect Length!\n"`. So that confirms our thoughts on `0x0b` being a length check. Let's look at the final chunk of code which is run after input validation.
```assembly
000017  CPY RZ, RTRGT
000019  PUSH RZ
00001b  RCPF 0x0001, RX        ; SIGNSET 0x0001:SMAIN
00001e  RCPF 0x0001, RZ        ; SIGNSET 0x0001:SIN
000021  CMPL RZ
000023  XOR RX, RZ
000025  ICPY 0x00ff, RZ
000028  AND RX, RZ
00002a  WRIT RX
00002c  POP RZ
00002e  INC RZ
000030  ICPY 0x0000, RY
000033  CMP RZ, RY
000035  ICPY 0x003d, RTRGT
000038  JEQU 
000039  ICPY 0x0017, RTRGT
00003c  JUMP 
00003d  HALT 
```
There were a few bugs in here. On line `0x25`, this was originally `0x000f`, but the challenge dev confirmed that this was an assembler bug. Furthermore, 
`RZ` is still set to `0C` from just before the jump so this code would just forever increment `RZ` and read from empty `SMAIN` in an infinite loop as the `CMP RZ, RY` instruction is never true. My interpretation of this code was that the intention was to sequentially read `0C` (12) bytes of data from `SMAIN` and `SIN` respectively. It is my interpretation then that the instruction on line `0x30` should be changed to `ICPY 0x0000 RZ` and moved to be at the start of this block. I'll talk for the rest of the writeup as if this was the case, which will get the (almost) correct flag at the end.

First, `RZ` gets pushed into `RTRGT` to set the current read memory offset, and then a byte from `SMAIN` is read into `RX` and one from `SIN` is read into `RZ`, both offset by the previous value of `RZ`. As `RZ` is incremented until it reaches `0C`, this will read one by one the bytes just read in from stdin as well as the bytes from `SIN` that were in the original binary. The complement of `RZ` is taken, which is then XORed with `RX`. `RX` is then ANDed with `0xff`, which will yield the low byte of the word in the register, which is then outputted with `WRIT`. Then the offset is popped off the stack and incremented, completing the loop which runs for all 12 of the input characters before halting.

We can convert this reverse engineered code into a python script now.
```python
def compl(a):
    return a^65535

# these are the bytes which were written in SIN which we obtained from the
# raw binary file
SIN = bytes([0xbc, 0xac, 0xaf, 0xbf, 0xa8, 0xb6, 0x8f, 0xfa, 0x9c, 0xea, 0xff, 0xb6])

def perform_operation(s):
    global SIN
    s = s.encode("utf8")

    out = ""
    # iterate through SIN bytes and the user input
    for rz,rx in zip(SIN, s):
        # XOR with complement
        rx = rx ^ compl(rz)
        # AND with 0xff
        rx = rx & 0xff
        # WRIT
        out += chr(rx)

    return out

# handle input and length checking
inp = input()
if len(inp) != 12:
    print ("Incorrect length!")
else:
    print (perform_operation(inp))
```
We know the flag must be either the input or output to this program, and we need to deduce what the other one would be in order to find the flag. The challenge is easier if the flag is the input, so let's start with that. we know the flag is 12 characters in the form `ractf{#####}`, and that the obfuscated operation works on one character at a time. So let's see what entering the flag wrapper with random characters in the middle gives us.
```
> ractf{#####}
123412S&@6#4
```
Interesting! So for the valid characters we do know, we get `123412XXXXX4`. It looks like our target is to get an output of `123412341234`. Let's use my favourite method of character-by-character bruteforce:
```python
flag = ""
target = "123412341234"
# all printable ascii characters
all_chars = "".join([chr(i) for i in range(32, 127)])

# exit clause
while perform_operation(flag) != target:
    for c in all_chars:
        # check if correct addition
        if perform_operation(flag + c + "0"*(0xc - 1 - len(flag)))[:len(flag) + 1] == target[:len(flag) + 1]:
            # update flag and print
            flag += c
            print (flag)
            break
```
Running the program now, we get: `ractf{C1R'3}`
Hmmm. That doesn't look quite right. However, OSINT is our friend. The instruction set is called `Medea`, the name of a sorceress in Greek mythology, and possibly the most famous Greek sorceress and aunt of Medea is `Cerce`. So the flag is most likely either `ractf{C1Rc3}` or `ractf{C1RC3}`. I tried `ractf{C1Rc3}` and that was correct.

A slightly unsatisfying end there... I'm not entirely sure what was wrong either with my approach or the challenge itself that lead to that error, and I discussed it with the challenge dev who agreed something must be off somewhere but we couldn't figure it out. All in all probably the challenge that was most satisfying to get through and finally solve though :)
