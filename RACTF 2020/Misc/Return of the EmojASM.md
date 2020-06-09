# Return of the EmojASM
### Writeup by arcayn, 450 points
`Impressive work. But the emojasm gods have provided you with one more foul challenge. Once again, the web interface should be above.`

This was the second challenge involving the EmojASM esolang. The problem statement for this one seems much simpler, but that might not be the case...
-   Each tape has been preloaded with some data.
-   For each position n, the byte on T0 at position n should be XORed with the byte on T1[n] to produce the flag.
-   The flag data starts at the beginning of the tapes.

The first thing to note is that there is no XOR instruction in the EmojiASM instruction set, but we can emulate it with a bit of deduction; XOR is the same as OR, except that whenever AND would also return 1, XOR returns 0 instead, thus we get:
```
a ^ b = (a | b) - (a & b)
```
The next issue is the lack of a subtraction operation, but we can get around this too because we have a decrement instruction. The following pseudocode implements subtraction using only decrementation and control flow:
```
x - y = while y > 0:
	  dec x
	  dec y
```
Thank god for turing completeness. The last issue we face is that we only have two general purpose registers, but fortunately T2 is completely free, so we can write the result of our OR operation onto the tape, and be free to use X and Y to calculate the AND section. Our assembler ends up looking something like this:
```assembler
000 shift_forwards T2
001 shift_forwards T0
002 read T0
003 store X
004 set_accumulator 0xFF
005 cmpz A
006 je
007 shift_forwards T1
008 read T1
009 store Y
00A or X                  ; performs A|X
00B set_write T2          ; sets the write head on T2 to write A to the tape the next time it moves forwards
00C shift_forwards T2     ; writes A to T2
00D shift_backwards T2    ; repositions...
00E shift_forwards T2     ; the T2 input head has moved back over the space on the tape where we just wrote A, meaning that next time we call `read T2`, it will read A from T2's input head buffer
00F load Y
010 and X                 ; performs A&X
010 store Y
011 read T2               ; now the accumulator (result of our OR operation is read back in
012 store X               ; X = T1[n]|T0[n], Y = T1[n]&T0[n]
013 set_accumulator 0x1A
014 cmpz Y                ; subtraction loop
015 je
016 dec X
017 dec Y
018 set_accumulator 0x13
019 jmp
01A load X                ; X now at last contains T1[n]^T0[n]
01B output X
01C set_accumulator 0x00
01D jmp
01E halt
```
There are a few interesting things to note here, firstly is the fact that there is a comparison which is never equal, followed by a `je` instruction. This was because there was actually a null byte on the tape in the middle of data, so I had no way of checking where the data ended. Instead I just let the program get stuck in an infinite loop until the 50,000 instruction limit kicked in, as this would still print the flag exactly as required, and I just moved the accumulator comparison to after the re-setting of it so the offsets didn't change. Secondly, the way reading and writing from T2 works is very idiosyncratic, as first we have to move the tape head to write and clear the output buffer, then move the tape head back over where we just wrote, and then forward again to load the byte into the input buffer.

In emojis:
```
➡️🎥➡️📼👁️📼📦🔨✉️😈😈❔🗃️⚖️➡️🎞️👁️🎞️📦⛏️🎷🔨✏️🎥➡️🎥⬅️🎥➡️🎥🎁⛏️🍴🔨📦⛏️👁️🎥📦🔨✉️😄😍❔⛏️⚖️🦔🔨🦔⛏️✉️😃😊🐰🎁🔨📤✉️😀😀🐰🗿
```
And we get the flag: `ractf{x0rmoj1!}`
