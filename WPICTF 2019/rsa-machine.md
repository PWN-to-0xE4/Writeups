# Cryptography 4: rsa machine

Whew. This one was actually really cool. We're given a TCP service, and
somehow have to get the flag from it.

The first thing the service spits out at us is an RSA public key. Running the
code a few time, it's a different key each time, so cracking the key was
mostly out of the window given TCP timeouts and the likes.

We're also given the source code on the service, so let's have a look at it
and see how it's abusable.

It tells us we have have two commands we can use: `sign` and `getflag`.

If we try using `sign`, sure enough it'll sign our provided message.

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAksUkSmn9SR7urK7bmTz9
s+NfHo6QzFsUE3qcnaukMt1D8X1MCqlXdLkaUgOKtjy02CRewOYL8QCaw/qwBpKQ
tWTrTCollIOLiYU47jXWyD1KXq6gNiDV1OarRsTqpoIGpoUqeS2OVS+9P/CNKdnf
tYgIY8cXYgEXGk29dryyen7I6pdbrDGtjdB7jXSxZEdtN6hn2JJ1XFLHM9Rok5NN
8Kv0ISMSzFPe4UvKaAwI36I0zgTnaycyG9z2zrYgxKHg0kbsSbA8zYxQqyn6lZGP
pzfLiuyZBH/4PDz1r0hxYVRX3EfQxjS2/2WcmYtW1HWCKTdZe7wXeQlm6y6gSMED
ZQIDAQAB
-----END PUBLIC KEY-----
sign example123
4643746136661362878544119740294890416849108776051358073717236448977582898361034626544069271835643199528019891962114731540175757542051502612839780000877358555345812968589398893173055792674336710224855976467718062668169084113617118121081473377424191028951274053453107800421846412985504518480937027246845965371744141564522995571510523296331387246941662695615470162760530029269230466962996890161510511747565484465299079139923032654570780499287096530341709091409396595187022397121214536189598499286565871832568411001512502922408911029420535481927157114831507901658286749851923545437723569366076342872929668666312062121802
```

The command we want though is `getflag` which will return the flag - provided
the argument to it is a signed version of `getflag`.

Having a look at the code though, there's a subtle problem with it. It's
using **textbook RSA**. This is a problem because we can abuse
`m_1^e * m_2^e = (m_1 * m_2)^e (mod n)`. That is, if we have two signed
messages, we can work out the signature for those two messages multipled
together (remember, all strings are just long numbers in RSA) provided we
have the public key, which we do.

First, let's work out what `getflag` is as a number:

```py
>>> int.from_bytes(b'getflag', 'big')
29103473210188135
```

Any nice ASCII characters that'll divide that cleanly? Yes.

```py
>>> for i in range(16, 255):
...     if (a // i == a / i) and (a // i * i == a):
...             print(i, a // i)
...
55 529154058367057
>>> chr(55)
'7'
```

(The reason for both those checks in the if is just because of floating point
fun)

Let's drop that other number back into bytes so we can sent it over the
socket:

```py
>>> int.to_bytes(529154058367057, 8, 'big')
b'\x00\x01\xe1CG\xae0Q'
```

What we need to do now is multiply the returned signatures for those two
strings, modulus it based off the public key, then we will have the signature
for `getflag`.

```py
from Crypto.PublicKey import RSA
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('rsamachine.wpictf.xyz', 31337))

# Load the provided public key
key = s.recv(4096)
pubkey = RSA.importKey(key)

# Signing 55
s.send(b'sign 7\n')
a_part = int(s.recv(4096).strip())

# Signing 529154058367057
s.send(b'sign \x00\x01\xe1CG\xae0Q\n')
b_part = int(s.recv(4096).strip())

# Abuse of textbook RSA
new_msg = (a_part * b_part) % pubkey.n

# Get the flag!
s.send(('getflag ' + str(new_msg) + '\n').encode('ascii'))
print(s.recv(4096).decode('latin-1'))
```

Sure enough, out came our flag! This is a really good example of why
textbook RSA should **never** be used for security - it's literally useless
after the first of a public key.
