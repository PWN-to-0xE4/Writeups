# Snakes and ladders
### Writeup by arcayn, 200 points

`The flag is fqtbjfub4uj_0_d00151a52523e510f3e50521814141c. The attached file may be useful.`

This text looks encrypted,  and the python program attached is presumably used to generate it. If we try to run it in `decrypt` mode, then we get a `NotImplementedError`, so it looks like we'll have to do it ourselves. 

The important function (and its helper, `xor`) is:
```python
def xor(s1,s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

def encrypt(a):
    some_text = a[::2]

    randnum = 14
    text_length = len(some_text)
    endtext = ""
    for i in range(1, text_length + 1):
      weirdtext = some_text[i - 1]
      if weirdtext >= "a" and weirdtext <= "z":
          weirdtext = chr(ord(weirdtext) + randnum)
          if weirdtext > "z":
              weirdtext = chr(ord(weirdtext) - 26)
      endtext += weirdtext
    randtext = a[1::2]

    xored = xor("aaaaaaaaaaaaaaa", randtext)
    hex_xored = xored.encode("utf-8").hex()

    return endtext + hex_xored
```
We can see that this splits the plaintext into the odd and even position characters:
```python
# even letters stored here
some_text = a[::2]
# odd letters stored here
randtext = a[1::2]
```
`randtext` has minimal changes to it, just being XORed with the mask `"aaaaaaaaaaaaaaa"`. The mask is 15 bytes long, so lets take the 15 hex bytes off the end of the encrypted flag, and xor them with `"aaaaaaaaaaaaaaa"`.
```python
> xor("aaaaaaaaaaaaaaa", second_part.to_bytes(15, byteorder="big").decode("utf8"))
'at{33_0n_13yuu}'
```
From those odd-numbered characters, we can see we're definitely on the right lines. We could now attempt to actually reverse engineer the manipulation of the rest of the string, but we can make the observation that every even positioned character (iterated as `weirdtext`) is handled independently, meaning that any substring of the even ciphertext characters will yield the same substring of the even plaintext characters. We can exploit this and simply bruteforce the characters one at a time. Let's edit the function so it no longer splits the string up: we'll change
```python
some_text = a[::2]
```
to
```python
some_text = a
```
and 
```python
return endtext + hex_xored
```
to just
```python
return endtext
```
Add in our bruteforcer at the end of the script
```python
# initialise the string
first_part = "fqtbjfub4uj_0_d"
# create a string of all printable ascii characters
all_chars = "".join([chr(i) for i in range(32,127)])

current_plaintext = ""
# check for exit
while encrypt(current_plaintext) != first_part:
    # test all possible characters
    for c in all_chars:
        # test encryption
        t = encrypt(current_plaintext + c)
        # see if the substring matches
        if t == first_part[:len(t)]:
            # update the current state and print out
            current_plaintext += c
            print (current_plaintext)
            break
```
Finally, we combine the odd and even parts and output:
```python
flag = ""
for i,j in zip(current_plaintext, odd_letters):
    flag += i + j
print ("\n" + flag)
```

Running the program now gives us:
```
r
rc
rcf
rcfn
rcfnv
rcfnvr
rcfnvrg
rcfnvrgn
rcfnvrgn4
rcfnvrgn4g
rcfnvrgn4gv
rcfnvrgn4gv_
rcfnvrgn4gv_0
rcfnvrgn4gv_0_
rcfnvrgn4gv_0_p

ractf{n3v3r_g0nn4_g1v3_y0u_up}
```

And there's the flag.

