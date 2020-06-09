
# EmojASM
### Writeup by arcayn, 200 points

`Some of you may remember EmojASM from last year - it's making a return and it's bigger and better than ever. Now with a 16-bit jump register, the challenges are more devilish than ever before. You can find the web interface at the address above; see if you can get the flag out of it.`

This challenge was based on coding some simple programs in the very cool custom [EmojASM](https://gist.github.com/Bentechy66/bce063ee26bb0ec2ae664d506ed28ad0#file-emojasm_16bitjmp_spec-md) esolang. Here's the specification for problem 1:

-   Each tape has been preloaded with some data.
-   For each position n, the byte on T1 at position n represents the position of T0[n] in the final flag.
-   For example, if the flag was 'flag', T0 would have something like f,a,l,g, and T1 01,03,02,04.
-   The flag data starts at the beginning of the tapes.
-   For convenience when practicing, the flag is also loaded onto T2 without shuffling. This is not the case in the real environment.

We have 3 registers, general purpose `X` and `Y`, the accumulator `A`, and the jump register `RJMP`, the low 8-bits of which are `A`, and three tapes `T0, T1, T2` which are used for memory.

Ok, let's just make sure we can read and write data. We're going to want to execute a program along the lines of:
```
while (data on T2):
	read a byte from T2
        output
```
To cat the flag. Note that the "output" instruction will output the byte currently in the accumulator, and reading from tape will put the byte into the accumulator, so we can do this legitimately. Assuming that null bytes indicate the end of the data on a tape, we can convert this into some assembly representing the emojiASM - hopefully the instructions are fairly self explanitory:

```assembler
000 shift_forwards T2
001 read T2
002 cmpz A
003 store X
004 accumulator_set 0x0A
005 je
006 load X
007 output
008 accumulator_set 0x00
009 jmp
00A halt
```
We are incrementing the tape T2, reading from it and comparing that with zero. We then have to store that inputted value in X (`store r` stores A into the register `r`) so we can write the address of the end of the loop into the `RJUMP` register (or in this case directly into the accumulator) and then jump to the end if the `equals` flag is set from the zero compare. Otherwise, we load X back into the accumulator and output it, then write 0 into the accumulator and jump back. In emoji, this looks like:
```
000 ➡️🎥
001 👁️🎥
002 ❔🗃️
003 📦🔨
004 ✉️😀😊
005 ⚖️
006 🎁🔨
007 📤
008 ✉️😀😀
009 🐰
00A 🗿
```
However, the offsets aren't done on an instruction by instruction basis, or even a character by character basis, but rather a unicode code point basis - and emoji can have multiple different lengths in unicode code points. Fortunately, there's a debug output which will let us see which instructions are getting executed when, which will let us  figure out the correct offsets. However, for now, since we just want to halt the program, we can load a memory address like 0xFF (😏😏) into RJMP and the program will halt when it tries to jump past the length of the program. All in all:
```
➡️🎥👁️🎥❔🗃️📦🔨✉️😏😏⚖️🎁🔨📤✉️😀😀🐰🗿
```
Which cats the flag just like we hoped! Now for the actual challenge: Let's plan what we'll do

1) Increment the pointer and read a byte of input from T1
2) Increment the pointer on T0 the number of times specified by the byte read from T1
3) Read the byte in that location on T0
4) Output that byte
5) Rewind the tape T0
6) Repeat until we encounter a null byte

Seems pretty simple!
```
000 shift_forwards T1
001 read T1
002 store X
003 cmpz X
004 accumulator_set 0x12
005 je
006 cmpz X
007 cmpz X
008 accumulator_set 0x0D
008 je
009 dec X
00A shift_forwards T0
00B accumulator_set 0x06
00C jmp
00D read T0
00E output
00F rewind T0
010 accumulator_set 0x00
011 jmp
012 halt
```
The reason `cmpz X` is repeated is because I removed two characters that were there previously and didn't want to have to recalculate the emoji offsets - I decided to leave it in to illustrate the hacks this language can drive you to take!

Finally: in emojis (note the offsets will be completely different)
```
➡️🎞️👁️🎞️📦🔨❔🔨✉️😊😍⚖️❔🔨❔🔨✉️😂😆⚖️🦔🔨➡️📼✉️😁😃🐰👁️📼📤⏪📼✉️😀😀🐰🗿
```
And it works! We read off the flag as `ractf{5huffl1n'}`
