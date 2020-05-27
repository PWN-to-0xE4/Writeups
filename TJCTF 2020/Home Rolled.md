# Home Rolled

This challenge presented the player with some obfuscated python code (below),
and a network service running that code, which returned a different hex string
on each connection.

```py
import os,itertools
def c(l):
 while l():
  yield l
r,e,h,p,v,u=open,any,bool,filter,min,len
b=lambda x:(lambda:x)
w=lambda q:(lambda*x:q(2))
m=lambda*l:[p(e(h,l),key=w(os.urandom)).pop(0)for j in c(lambda:v(l))]
f=lambda l:[b(lambda:m(f(l[:k//2]),f(l[k//2:]))),b(b(l))][(k:=u(l))==1]()()
s=r(__file__).read()
t=lambda p:",".join(p)
o=list(itertools.permutations("rehpvu"))
exec(t(o[sum(map(ord,s))%720])+"="+t(b(o[0])()))
a=r("flag.txt").read()
print("".join(hex((g^x)+(1<<8))[7>>1:]for g,x in zip(f(list(range(256))),map(ord,a))))
```

Without going into too much detail about the obfuscation methods used here,
one interesting trick is the use of the file's content itself in the switching
of variable names. The file is read by `s=r(__file__).read()`, then the
subsequent call to `exec` makes use of that loaded file content. After some
deobfuscation, however, we get the following code:

```py
import random

def BalancedMerge(*args):
    ret = []
    while any(args):
        rand = random.choice(list(filter(bool, args)))
        ret.append(rand.pop(0))
    return ret

def BalancedShuffle(arr):
    k = len(arr)
    if len(arr) == 1:
        return arr

    return BalancedMerge(
        BalancedShuffle(arr[:k // 2]),
        BalancedShuffle(arr[k // 2:])
    )

FLAG = open("flag.txt").read()
print(
    "".join(
        hex(g ^ x)[2:]
        for g, x in zip(
            BalancedShuffle(list(range(256))),
            map(ord, FLAG)
        )
    )
)
```

The `BalancedMerge` and `BalancedShuffle` appear to implement the algorithms
described in http://ceur-ws.org/Vol-2113/paper3.pdf, hence the unusual naming
convention. Of note is that this is an unbiased shuffle. Because of this, that
code can be simplified to the following:

```py
import random

def shuffled(arr):
    random.shuffle(arr)
    return arr

FLAG = open("flag.txt").read()
print(
    "".join(
        hex(g ^ x)[2:]
        for g, x in zip(
            shuggled(list(range(256))),
            map(ord, FLAG)
        )
    )
)
```

This is considerably shorter. The flag is being XOR'd here with the numbers 0
though 255, shuffled randomly, and truncated as required. The important thing
to observe is that each value from 0 to 255 is used either 0 times, or 1 time,
but never more than once. The other thing we know is the flag starts with
`tjctf{` and ends in `}`, because that's the flag format.

This is potentially better illustrated with a nice table. Let's say that upon
connection to the service, we are sent the string
`3201c75e5bb7e5e1f396c94e699fea5b18295c07640ba3e9911d1db224a423836214dcc4d4b4`.

| Encrypted | 0x32 | 0x01 | 0xc7 | 0x5e | 0x5b | 0xb7 | 0xe5 | 0xe1 | 0xf3 | 0x96 | ... |
|-----------|------|------|------|------|------|------|------|------|------|------|-----|
| Flag      | t    | j    | c    | t    | f    | {    |      |      |      |      | ... |
| Key       | 70   | 107  | 164  | 42   | 61   | 204  | ?    | ?    | ?    | ?    | ... |

We can recover the start of the random key (and the final number) by XORing
the known parts of the flag with the encrypted text. Unfortunately, we still
have no way of calculating the `?`s in the key. We do now know a little bit
about them. That is, none of those `?`s will be 70, 107, 164, 42, 61, or 204.
This is important! In fact they can only be 249 of the possible 256 values.

Okay, okay, we really haven't solved anything there. That still leaves us with
3.2e+57 possible values for the flag. What we _have_ done, however, is found a
bias. Rather than the 256 possible values each character in the flag should
have, we've eliminated 7, leaving only 249 possible values. This means that if
we find every possible value, a **huge** number of times, one value should be
ever so slightly more common that the others.

Time to go collect lots of data!

I wrote a very quick and dirty script that connected to the network service
4,000 times, and dumped the output of each into a file. Then I went to make a
coffee.

The script to locate the bias is not especially pretty, but it gets the job
done. For each of the collected strings, every possible value for every
unknown character in the flag counts towards a counter. The characters that
were seen to be the "most possible" are then outputted for each character of
the flag.

```py
import binascii

data = open('data.txt').read().strip().split()
data = list(map(binascii.unhexlify, data))[:500]

possible = [{i: 0 for i in range(256)} for _ in range(31)]

for i in data:
    tot = list(range(256))
    tot.remove(i[0] ^ ord('t'))
    tot.remove(i[1] ^ ord('j'))
    tot.remove(i[2] ^ ord('c'))
    tot.remove(i[3] ^ ord('t'))
    tot.remove(i[4] ^ ord('f'))
    tot.remove(i[5] ^ ord('{'))
    tot.remove(i[37] ^ ord('}'))

    for j in tot:
        for k in range(6, 37):
            possible[k - 6][j ^ i[k]] += 1

print('tjctf{', end='')
for i in possible:
    m = max(i, key=lambda x: i[x])
    print(chr(m), end='', flush=True)
print('}')
```
