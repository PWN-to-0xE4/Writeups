# It's as easy as access=0000
### Writeup by arcayn, 300 points

`
We found a strange service, it looks like you can generate an access token for the network service, but you shouldn't be able to read the flag... We think.
`

We get a service to connect to and the source code of that service. Connecting to the service, we get:
```
Would you like to:
[1] Create a guest token
[2] Read the flag
Your choice:
```
Entering `1`, we're given
```
{'token': '82ba75e0f2b56f6225124f4c0ed7c7d195124806f3d885484e26571b71b588b55ee35aaa8513b7ba10ba3e1f55020598'}
```
And it puts us back to the menu. Entering `2`,  and putting in that token we just received, we get:
```
Please enter your admin token: 82ba75e0f2b56f6225124f4c0ed7c7d195124806f3d885484e26571b71b588b55ee35aaa8513b7ba10ba3e1f55020598
Please enter your token's initialization vector: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
{'error': 'not authorized to read flag'}
```
OK. Let's take a look at the code. The functions we're probably interested in are:
```python
def get_flag(token, iv):
    token = bytes.fromhex(token)
    iv = bytes.fromhex(iv)
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(token)
        unpadded = unpad(decrypted, 16)
    except ValueError as e:
        return {"error": str(e)}
    if b"access=0000" in unpadded:
        return {"flag": FLAG}
    else:
        return {"error": "not authorized to read flag"}

def generate_token():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    token = f"access=9999;expiry={expires_at}".encode()
    iv = get_random_bytes(16)
    padded = pad(token, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()
    return {"token": ciphertext}
```
As we can see, the guest token given is a AES128-CBC encoded string defining our access level (and expiry, but we don't need to worry about that), along with our IV. If, when decrypted, the token contains `access=0000`, then we get the flag. As we are able to provide arbitrary initialization vectors, this is a classic setup for a bit-flipping attack.

When CBC AES is decrypted, the first block of the ciphertext is decrypted, and the plaintext XORed with the IV to yield the final first plaintext block. We can exploit this if we are able to manipulate the IV and know the form of the plaintext and want to change it. If we can manipulate the IV in the guest token we are given to, when XORed with the first plaintext block, switch the `access=9999` to `access=0000`, then we have it. We know the first block of the ciphertext in the guest token we are given is `access=9999;expi`, so lets xor these bytes with `access=0000;expi` to find the mask we want to use (keeping in mind that XOR is self-inverse). Python does this:
```python
> int.from_bytes(b'access=9999;expi', byteorder="big") ^ int.from_bytes(b'access=0000;expi', byteorder="big")
166671758180122361856
> '{0:016b}'.format(166671758180122361856)
'10010000100100001001000010010000000000000000000000000000000000000000'
```
That bitmask looks about right. Let's grab another guest token and split it up into IV (first 16 bytes) and the ciphertext (the rest).
```
IV: d098c8657f6ba263fca36285996d48ed
ciphertext: f9e4afd2437e9d7ac90d9c8d1c7b4d8af8ff6b76806288d5bd8ac34b1a4672d2
```
We don't have to touch the ciphertext, but lets xor that IV with the mask we found and get it in hex:
```python
> 166671758180122361856 ^ 0xd098c8657f6ba263fca36285996d48ed
277272716769159657944748155630909212909
> hex(277272716769159657944748155630909212909)
'0xd098c8657f6ba26af5aa6b85996d48ed'
```
Entering the ciphertext into the service as the token, and that modified IV as the IV gives us the flag: `ractf{cbc_b17_fl1pp1n6_F7W!}`
