# Dimensionless Loading

### Writeup by tritoke, 250 Points

`This PNG looks to be valid, but when we open it up nothing loads. Any ideas?`

At the start of the challenge we are given ``flag.png``.
I tried opening it using ``feh`` - my chosen image viewer.
But it didn't open, as advertised.

## Diagnosing the fault
```
$ feh flag.png
libpng error: IHDR: CRC error
```

From above we can see that there is a ``CRC`` error in the ``IHDR`` chunk.
So lets take a look in a hex editor:

```
$ xxd flag.png | head -3

00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 0000 0000 0000 0806 0000 005b 8af0  .............[..
00000020: 3000 0020 0049 4441 5478 9cec bd09 90a4  0.. .IDATx......
```

Although this format can be a bit confusing it allows us to easily look at different fields,
without actually going to the effort to parse the chunks in code.

We now know the exact bits of the header chunk and can parse it manually:
```
chunk size: 0000 000d
chunk type: 4948 4452 (ascii values for IHDR)
32 bit BE width: 0000 0000
32 bit BE hieght: 0000 0000
bit depth: 08
color type: 06
compression method: 00
filter method: 00
interlace method: 00
CRC32: 5b8a f030
```

This makes it plain to see that the width and height of the image are wrong.
However because we still have the ``CRC`` we can recover the correct width and height,
by bruteforcing some likely combinations.

## Recovering the width and height

I have previously written code for parsing PNG chunks so I shall include it at the end.
All you need to know is that it produces a list of tuples,
each tuple represents the data in one chunk.
I.e. ``chunks = [(size, type, data, CRC)]``

Using the code I wrote before I now had the ``IHDR`` chunk, and so could begin parsing it:
```python
def parse_ihdr(chunk):
    *_, cd, _ = chunk
    return struct.unpack(">IIBBBBB", cd)
```

This simply says I want the second to last element of chunk - the chunk data,
and then I want to unpack it, interpreted as 2 BE Ints, then 5 Bytes.
This returns a tuple of the fields in the ``IHDR`` chunk.

Now that we have the data from the chunk we can go about recovering the width and height:
```python
def fix_ihdr(chunk):
    l, ct, cd, crc = chunk
    xl, yl, bd, col_t, cm, fm, im = parse_ihdr(chunk)

    for i, j in it.product(range(1, 3000), range(1, 3000)):
        new = b"IHDR" + struct.pack(">II", i, j) + cd[8:]
        if binascii.crc32(new) == crc:
            return (l, ct, struct.pack(">II", i, j) + cd[8:], crc)

    return chunk
```

I use the ``binascii`` module for its ``CRC32`` implementation,
and the ``itertools`` module because I'm too lazy to write a nested for loop.
The code then goes about trying every combination of width and height between (1,1) and (3000, 3000).
Each time re-calculating the ``CRC32`` value of the chunk so that we know when it is fixed.
This gives us a true size as ``1378x363`` and we can now reconstruct the PNG to get the flag:

![](imgs/a.png)

```
ractf{m1ss1ng_n0_1s_r34l!!}
```

- - -

### Final complete python script

```python
#!/usr/bin/env python
import struct
import binascii
import itertools as it


def read_header(pngfile):
    return pngfile.read(8)


def write_header(pngfile, header):
    pngfile.write(header)


def read_chunk(pngfile):
    (length,) = struct.unpack(">I", pngfile.read(4))
    chunk_type = pngfile.read(4).decode("UTF-8")
    chunk_data = pngfile.read(length)
    (crc,) = struct.unpack("!I", pngfile.read(4))
    return length, chunk_type, chunk_data, crc


def write_chunk(pngfile, length, chunk_type, chunk_data, crc):
    pngfile.write(
        struct.pack(">I", length)
        + chunk_type.encode("UTF-8")
        + chunk_data
        + struct.pack("!I", crc)
    )


def parse_ihdr(chunk):
    *_, cd, _ = chunk
    return struct.unpack(">IIBBBBB", cd)


def fix_ihdr(chunk):
    l, ct, cd, crc = chunk
    xl, yl, bd, col_t, cm, fm, im = parse_ihdr(chunk)

    for i, j in it.product(range(1, 3000), range(1, 3000)):
        new = b"IHDR" + struct.pack(">II", i, j) + cd[8:]
        if binascii.crc32(new) == crc:
            return (l, ct, struct.pack(">II", i, j) + cd[8:], crc)

    return chunk


chunks = []

with open("flag.png", "rb") as f:
    header = read_header(f)
    print(header)
    chunk = read_chunk(f)
    _, chunk_type, *_ = chunk
    chunks.append(fix_ihdr(chunk))
    while chunk_type != "IEND":
        chunk = read_chunk(f)
        chunks.append(chunk)
        _, chunk_type, *_ = chunk

with open("a.png", "wb") as f:
    write_header(f, header)
    for length, chunk_type, chunk_data, crc in chunks:
        write_chunk(f, length, chunk_type, chunk_data, crc)
```
