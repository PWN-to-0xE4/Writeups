# John Cena

This challenge was fairly simple, but had one or two complications.

The first step was parsing the image. Before I could script it, I opened up
the image in GIMP to have a look at spacing. As it turned out, each braille
block was 30 pixels wide, but the heights weren't consistent. On odd rows it
was 43 pixels high, and even rows were 44 pixels high. There were 33 blocks to
a row, and 57 rows in the image.

After taking measurements, it was scripting time. I used `PIL` and `numpy`,
becuase I like python :P. The main chunker is shown below:

```py
i = Image.open("braille.png")
a = np.asarray(i)
a = a[:, 6:-6, :]

slices = []
ypos = 0
for row in range(57):
    for col in range(33):
        chunk = a[ypos: ypos+44, col * 30: (col + 1) * 30, :]
        slices.append(chunk)

    ypos += 44 if row % 2 else 43
```

Rather than multiplying the `row` value, I tracked the current y position
using the `ypos` variable, which allowed me to account for the varying row
heights. There were over a thousand individual chunks, so I've only put one of
them here for illustation:

![](https://i.imgur.com/z7QkAar.png)

After compiling the chunks, I needed to identify the circles within them.
Rather that using anything fancy, I just tested 6 pixels in each chunk, each
slightly off the centre of one of the circles. For larger circles, it would
hit a pink pixel, but smaller circles would hit a black pixel. This code for
this is below:

```py
data = ''
for i in slices:
    px = [
        i[4, 7, 0] > 50,
        i[19, 7, 0] > 50,
        i[34, 7, 0] > 50,

        i[4, 20, 0] > 50,
        i[19, 20, 0] > 50,
        i[34, 20, 0] > 50,
    ]
    p = ''.join(map(str, map(int, px)))
    data += lookup[p]
```

I converted each block into a 6-digit string of 0s and 1s, allowing me to map
it into a braille character using

```py
lookup = {
    '100000': '⠁',
    '110000': '⠃',
    '100100': '⠉',
    '100110': '⠙',
    '100010': '⠑',
    '110100': '⠋',
    '110110': '⠛',
    '110010': '⠓',
    '010100': '⠊',
    '010110': '⠚',
    '001111': '⠼',
    '000000': ' ',
}
```

The output braille, sadly, wasn't technically valid. The `⠼` character
normally indicates that the next sequence of characters create a number, until
a blank symbol is found. For example, `⠼⠁⠃` would be `12`. In this case,
however it was used to indicate that only the immediate next character was a
number. This means that same symbol of characteres decoded to `1B`. To decode
this, I wrote the horrible bit of python shown below:

```py
nums = '⠚⠁⠃⠉⠙⠑⠋⠛⠓⠊'
charas = ' abcdef???????'

is_num = False
out = ''
for i in BRAILLE:
    if i == '⠼':
        is_num = True
    else:
        idx = nums.index(i)
        out += str(idx) is_num else charas[idx]
        is_num = False
print(out)
```

This produced a hex string, shown below as a hexdump.

```
00000000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3e 00 01 00 00 00  |.ELF..............>.....|
00000018  80 00 40 00 00 00 00 00 40 00 00 00 00 00 00 00 e0 00 00 00 00 00 00 00  |..@.....@.......à.......|
00000030  00 00 00 00 40 00 38 00 01 00 40 00 04 00 03 00 01 00 00 00 07 00 00 00  |....@.8...@.............|
00000048  80 00 00 00 00 00 00 00 80 00 40 00 00 00 00 00 80 00 40 00 00 00 00 00  |..........@.......@.....|
00000060  49 00 00 00 00 00 00 00 49 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00  |I.......I...............|
00000078  00 00 00 00 00 00 00 00 b8 01 00 00 00 bf 01 00 00 00 be b4 00 40 00 31  |........¸....¿....¾´.@.1|
00000090  c9 67 8b 14 0e 83 c2 31 67 89 14 0e ff c1 83 f9 15 75 ee ba 15 00 00 00  |Ég....Â1g...ÿÁ.ù.uîº....|
000000a8  0f 05 b8 3c 00 00 00 31 ff 0f 05 00 26 1f 18 4a 3b 03 42 00 47 0a 00 42  |..¸<...1ÿ...&..J;.B.G..B|
000000c0  03 2e 04 32 41 44 31 04 4c 00 2e 73 68 73 74 72 74 61 62 00 2e 74 65 78  |...2AD1.L..shstrtab..tex|
000000d8  74 00 2e 64 61 74 61 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |t..data.................|
000000f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |........................|
00000108  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |........................|
00000120  0b 00 00 00 01 00 00 00 07 00 00 00 00 00 00 00 80 00 40 00 00 00 00 00  |..................@.....|
00000138  80 00 00 00 00 00 00 00 33 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |........3...............|
00000150  10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 11 00 00 00 01 00 00 00  |........................|
00000168  03 00 00 00 00 00 00 00 b4 00 40 00 00 00 00 00 b4 00 00 00 00 00 00 00  |........´.@.....´.......|
00000180  15 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00  |........................|
00000198  00 00 00 00 00 00 00 00 01 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00  |........................|
000001b0  00 00 00 00 00 00 00 00 c9 00 00 00 00 00 00 00 17 00 00 00 00 00 00 00  |........É...............|
000001c8  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |........................|
```

I didn't have Linux handy, and the binary wouldn't run in WSL, so I did the
less-than-obvious thing and converted it to python.

Running it through radare showed that it was grabbing some data, adding 49
(0x31) to each byte, then printing it out.

```
[0x00400080]> pdf
            ;-- section..text:
            ;-- section.LOAD0:
            ;-- rip:
/ (fcn) entry0 53
|   entry0 ();
|           ; CALL XREF from 0x00400080 (entry0)
|           0x00400080      b801000000     mov eax, 1                  ; [04] -rwx section size 73 named LOAD0
|           0x00400085      bf01000000     mov edi, 1
|           0x0040008a      beb4004000     mov esi, 0x4000b4           ; section..data ; "&\x1f\x18J;\x03B"
|           0x0040008f      31c9           xor ecx, ecx
|           ; CODE XREF from 0x004000a1 (entry0)
|       .-> 0x00400091      678b140e       mov edx, dword [esi + ecx]
|       :   0x00400095      83c231         add edx, 0x31               ; '1'
|       :   0x00400098      6789140e       mov dword [esi + ecx], edx
|       :   0x0040009c      ffc1           inc ecx
|       :   0x0040009e      83f915         cmp ecx, 0x15               ; 21
|       `=< 0x004000a1      75ee           jne 0x400091
|           0x004000a3      ba15000000     mov edx, 0x15               ; 21
|           0x004000a8      0f05           syscall
|           0x004000aa      b83c000000     mov eax, 0x3c               ; '<' ; 60
|           0x004000af      31ff           xor edi, edi
|           0x004000b1      0f05           syscall
            ;-- section_end..text:
\           0x004000b3  ~   0026           add byte [rsi], ah
            ;-- section..data:
|           ; DATA XREF from 0x0040008a (entry0)
|           0x004000b4      26             invalid                     ; [02] -rw- section size 21 named .data
[0x00400080]>
```

Running that in my python shell gave me

```py
>>> a = '261f184a3b034200470a0042032e0432414431044c'
>>> a = binascii.unhexlify(a)
>>> print(''.join(chr(i + 49) for i in a))
WPI{l4s1x;1s4_5crub5}
>>> 
```

and that was the flag.
