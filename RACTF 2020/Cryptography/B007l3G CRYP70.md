# B007l3G CRYP70
### Writeup by arcayn, 350 points
`
While doing a pentest of a company called MEGACORP's network, you find these numbers laying around on an FTP server: 41 36 37 27 35 38 55 30 40 47 35 34 43 35 29 32 38 37 33 45 39 30 36 27 32 35 36 52 72 54 39 42 30 30 58 27 37 44 72 47 28 46 45 41 48 39 27 27 53 64 32 58 43 23 37 44 32 37 28 50 37 19 51 53 30 41 18 45 79 46 40 42 32 32 46 28 37 30 43 31 26 56 37 41 61 68 44 34 26 24 48 38 50 37 27 31 30 38 34 58 54 39 30 33 38 18 33 52 34 36 31 33 28 36 34 45 55 60 37 48 57 55 35 60 22 36 38 34. Through further analysis of the network, you also find a network service running. Can you piece this information together to find the flag?
`

The numbers are presumably encrypted text, and we get a web service to connect to. Let's see what this holds.
```
Welcome to MEGACORP's proprietary encryption service! Just type your message below and out will come the encrypted text!

Please enter the message you wish to encrypt:
```
Nice, an encryption oracle. Let's give it some ciphertexts.
```
Please enter the message you wish to encrypt: A
Your encrypted message is: 35 36 46 73

Please enter the message you wish to encrypt: AA
Your encrypted message is: 41 56 26 67 58 30 44 58

Please enter the message you wish to encrypt: AAA
Your encrypted message is: 67 37 59 27 52 34 46 58 38 56 34 62

Please enter the message you wish to encrypt: A
Your encrypted message is: 34 56 32 68

Please enter the message you wish to encrypt: A
Your encrypted message is: 60 34 36 60

Please enter the message you wish to encrypt: A
Your encrypted message is: 66 37 56 31
```
We can be pretty sure that this cipher is encrypting single characters at a time, where once plaintext character maps to four two-digit numbers, but these seem completely nondeterministic, and we don't know if previous characters affect later ones yet. What we're looking for is something that is constant across these 4 identical plaintexts:
```
66 37 56 31
60 34 36 60
34 56 32 68
35 36 46 73
```
Do you see it?
Just looking at the last two, we see that the first two digits are the same, the second two are different by twenty, then 10 and 10 again (yes not really but averaging out). Let's see what they sum to. Sure enough, every block of 4 numbers has the same sum - `190` here. Let's check what the sum of the plaintext `B` is.
```
65 + 30 + 50 + 44 = 189
```
Well the ascii values of A and B are 1 apart, so it makes sense that their ciphertexts here are 1 apart. Let's choose another character, like `0`:
```
37 + 67 + 69 + 34 = 207
```
`0` is 17 characters behind `A` in ascii, and `B` is 1 ahead, so it seems we've figured out the encryption scheme. Let's try the furthest extreme of the printable range - like `}`
```
 41 + 28 + 22 + 39 = 130
```
So then, the encryption function (just for turning into sums, not four numbers):
```python
def encrypt(c):
	return 255 - ord(c)
```
Seems consistent with our observations. Let's just make sure that the scheme does in fact work on single characters:
```
Please enter the message you wish to encrypt: AB
Your encrypted message is: 52 60 41 37 34 47 67 41

52 + 60 + 41 + 37 = 190
34 + 47 + 67 + 41 = 189
```
Perfect. Let's get some python to decrypt this string:
```python
ct = "..."

# convert the ciphertext into an array of ints
ct = [int(n) for n in ct.split(" ")]
# chunk the ciphertext into blocks of 4
cblocks = [ct[i : i + 4] for i in range(0, len(ct), 4)]

# iterate and solve
plaintext = "".join([chr(255 - sum(b)) for b in cblocks])
print (plaintext)
```
And we get the flag: `ractf{d0n7_r0ll_y0ur_0wn_cryp70}`
