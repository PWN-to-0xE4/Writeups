# Spentalkux

### Writeup by Segway, 300 points

`Spentalkux 🐍📦`

The challenge description has a snake and a package emoji, with the challenge name. A simple guess to make would be that Spentalkux is a Python package, which means it would be on PyPI: as a matter of fact, it [is!](https://pypi.org/project/spentalkux/) However, the project's description means that it is definitely not a good idea to blindly import the module, and the suspicion is increased when you look at the challenge's author.

The release history shows two versions of the package, both published on the same day. However, the more recent version has 13.37 as a package version, which probably indicates to look at it first (although it is the other version that actually contains the flag).

The code for the 13.37 version module is as follows:
```python
import base64
p="""
aW1wb3J0IHRpbWUKCmdvX2F3YXlfbXNncyA9IFsiR29vZGJ5ZSBub3cuIiwgIlRoYXQncyB5b3VyIGN1ZSB0byBsZWF2ZSwgYnJvIiwgIkV4aXQgc3RhZ2UgbGVmdCwgcGFsIiwgIk9GRiBZT1UgUE9QLiIsICJZb3Uga25vdyB3aGF0IEkgaGF2ZW4ndCBnb3QgdGltZSBmb3IgdGhpcyIsICJGb3JraW5nIGFuZCBleGVjdXRpbmcgcm0gLXJmLiJdCgp0aW1lLnNsZWVwKDEpCnByaW50KCJIZWxsby4iKQp0aW1lLnNsZWVwKDIpCnByaW50KCJDYW4gSSBoZWxwIHlvdT8iKQp0aW1lLnNsZWVwKDIpCnByaW50KCJPaCwgeW91J3JlIGxvb2tpbmcgZm9yIHNvbWV0aGluZyB0byBkbyB3aXRoICp0aGF0Ki4iKQp0aW1lLnNsZWVwKDIpCnByaW50KCJNeSBjcmVhdG9yIGxlZnQgdGhpcyBiZWhpbmQgYnV0LCBJIHdvbmRlciB3aGF0IHRoZSBrZXkgaXM/IEkgZG9uJ3Qga25vdywgYnV0IGlmIEkgZGlkIEkgd291bGQgc2F5IGl0J3MgYWJvdXQgMTAgY2hhcmFjdGVycy4iKQp0aW1lLnNsZWVwKDQpCnByaW50KCJFbmpveSB0aGlzLiIpCnRpbWUuc2xlZXAoMSkKcHJpbnQoIlp0cHloLCBJcSBpaXInanQgdnJ0ZHR4YSBxenh3IGxodSdnbyBneGZwa3J3IHR6IHBja3YgYmMgeWJ0ZXZ5Li4uICpmZmlpZXlhbm8qLiBOZXcgY2lrbSBzZWthYiBndSB4dXggY3NrZml3Y2tyIGJzIHpmeW8gc2kgbGdtcGQ6Ly96dXBsdGZ2Zy5jencvbHhvL1FHdk0wc2E2IikKdGltZS5zbGVlcCg1KQpmb3IgaSBpbiBnb19hd2F5X21zZ3M6CiAgICB0aW1lLnNsZWVwKDMpCiAgICBwcmludChpKQp0aW1lLnNsZWVwKDAuNSk=
"""
exec(base64.b64decode(p.encode("ascii")))
```
This is definitely not suspicious.

The decoded Base64 code gives us the following Python code:

```python
import time

go_away_msgs = ["Goodbye now.", "That's your cue to leave, bro", "Exit stage left, pal", "OFF YOU POP.", "You know what I haven't got time for this", "Forking and executing rm -rf."]

time.sleep(1)
print("Hello.")
time.sleep(2)
print("Can I help you?")
time.sleep(2)
print("Oh, you're looking for something to do with *that*.")
time.sleep(2)
print("My creator left this behind but, I wonder what the key is? I don't know, but if I did I would say it's about 10 characters.")
time.sleep(4)
print("Enjoy this.")
time.sleep(1)
print("Ztpyh, Iq iir'jt vrtdtxa qzxw lhu'go gxfpkrw tz pckv bc ybtevy... *ffiieyano*. New cikm sekab gu xux cskfiwckr bs zfyo si lgmpd://zupltfvg.czw/lxo/QGvM0sa6")
time.sleep(5)
for i in go_away_msgs:
    time.sleep(3)
    print(i)
time.sleep(0.5)
```

Through ~putting the text through a cipher identifier~ calculating the index of coincidence on the text, the text appears to have been encrypted with a Vigenère cipher. The program text tells us that the key is 10 characters long, so the text can be easily decrypted by an online solver. The found key is none other than `SPENTALKUX`, and the plaintext is obtained:

```
Hello, If you're reading this you've managed to find my little... *interface*. The next stage of the challenge is over at https://pastebin.com/raw/BCiT0sp6
```

The link leads to a large hexdump. Decoding the hexdump shows that the hexdump is a PNG image, due to the presence of the `PNG` string.

The image is the following text on a red background:
```
look back into the past...
find what you have forgotten...
01011111 01101000 01100101 01110010 01110010 01101001 01101110 01100111
```

The binary string decodes into `_herring`, which matches with the red background to form `red_herring`, which is, unsurprisingly, a red herring.

The message suggests that we need to look at a past version of something. Since the challenge centers around a Python package, the next step is most likely looking at the 0.9 version of spentalkux.

The old module code is as follows:
```python
import base64
p="""
aW1wb3J0IHRpbWUKCmdvX2F3YXlfbXNncyA9IFsiVGhpcyBpcyB0aGUgcGFydCB3aGVyZSB5b3UgKmxlYXZlKiwgYnJvLiIsICJMb29rLCBpZiB5b3UgZG9uJ3QgZ2V0IG91dHRhIGhlcmUgc29vbiBpbWEgcnVuIHJtIC1yZiBvbiB5YSIsICJJIGRvbid0IHdhbnQgeW91IGhlcmUuIEdPIEFXQVkuIiwgIkxlYXZlIG1lIGFsb25lIG5vdy4iLCAiR09PREJZRSEiLCAiSSB1c2VkIHRvIHdhbnQgeW91IGRlYWQgYnV0Li4uIiwgIm5vdyBJIG9ubHkgd2FudCB5b3UgZ29uZS4iXQoKdGltZS5zbGVlcCgxKQpwcmludCgiVXJnaC4gTm90IHlvdSBhZ2Fpbi4iKQp0aW1lLnNsZWVwKDIpCnByaW50KCJGaW5lLiBJJ2xsIHRlbGwgeW91IG1vcmUuIikKdGltZS5zbGVlcCgyKQpwcmludCgiLi4uIikKdGltZS5zbGVlcCgyKQpwcmludCgiQnV0LCBiZWluZyB0aGUgY2hhb3RpYyBldmlsIEkgYW0sIEknbSBub3QgZ2l2aW5nIGl0IHRvIHlvdSBpbiBwbGFpbnRleHQuIikKdGltZS5zbGVlcCg0KQpwcmludCgiRW5qb3kgdGhpcy4iKQp0aW1lLnNsZWVwKDEpCnByaW50KCJKQTJIR1NLQkpJNERTWjJXR1JBUzZLWlJMSktWRVlLRkpGQVdTT0NUTk5URkNLWlJGNUhUR1pSWEpWMkVLUVRHSlZUWFVPTFNJTVhXSTJLWU5WRVVDTkxJS041SEszUlRKQkhHSVFUQ001UkhJVlNRR0ozQzZNUkxKUlhYT1RKWUdNM1hPUlNJSk40RlVZVE5JVTRYQVVMR09OR0U2WUxKSlJBVVlPRExPWkVXV05DTklKV1dDTUpYT1ZURVFVTENKRkZFR1dEUEs1SEZVV1NMSTVJRk9RUlZLRldHVTVTWUpGMlZRVDNOTlVZRkdaMk1ORjRFVTVaWUpCSkVHT0NVTUpXWFVOM1lHVlNVUzQzUVBGWUdDV1NJS05MV0UyUllNTkFXUVpES05SVVRFVjJWTk5KREM0M1dHSlNGVTNMWExCVUZVM0NFTlpFV0dRM01HQkRYUzRTR0xBM0dNUzNMSUpDVUVWQ0NPTllTV09MVkxFWkVLWTNWTTRaRkVaUlFQQjJHQ1NUTUpaU0ZTU1RWUEJWRkFPTExNTlNEQ1RDUEs0WFdNVUtZT1JSREM0M0VHTlRGR1ZDSExCREZJNkJUS1ZWR01SMkdQQTNIS1NTSE5KU1VTUUtCSUUiKQp0aW1lLnNsZWVwKDUpCmZvciBpIGluIGdvX2F3YXlfbXNnczoKICAgIHRpbWUuc2xlZXAoMikKICAgIHByaW50KGkpCnRpbWUuc2xlZXAoMC41KQ=="""
exec(base64.b64decode(p.encode("ascii")))
```

When the script is decoded, we are greeted with even more passive-aggressive text and brilliant humour from the challenge author:

```python
import time

go_away_msgs = ["This is the part where you *leave*, bro.", "Look, if you don't get outta here soon ima run rm -rf on ya", "I don't want you here. GO AWAY.", "Leave me alone now.", "GOODBYE!", "I used to want you dead but...", "now I only want you gone."]

time.sleep(1)
print("Urgh. Not you again.")
time.sleep(2)
print("Fine. I'll tell you more.")
time.sleep(2)
print("...")
time.sleep(2)
print("But, being the chaotic evil I am, I'm not giving it to you in plaintext.")
time.sleep(4)
print("Enjoy this.")
time.sleep(1)
print("JA2HGSKBJI4DSZ2WGRAS6KZRLJKVEYKFJFAWSOCTNNTFCKZRF5HTGZRXJV2EKQTGJVTXUOLSIMXWI2KYNVEUCNLIKN5HK3RTJBHGIQTCM5RHIVSQGJ3C6MRLJRXXOTJYGM3XORSIJN4FUYTNIU4XAULGONGE6YLJJRAUYODLOZEWWNCNIJWWCMJXOVTEQULCJFFEGWDPK5HFUWSLI5IFOQRVKFWGU5SYJF2VQT3NNUYFGZ2MNF4EU5ZYJBJEGOCUMJWXUN3YGVSUS43QPFYGCWSIKNLWE2RYMNAWQZDKNRUTEV2VNNJDC43WGJSFU3LXLBUFU3CENZEWGQ3MGBDXS4SGLA3GMS3LIJCUEVCCONYSWOLVLEZEKY3VM4ZFEZRQPB2GCSTMJZSFSSTVPBVFAOLLMNSDCTCPK4XWMUKYORRDC43EGNTFGVCHLBDFI6BTKVVGMR2GPA3HKSSHNJSUSQKBIE")
time.sleep(5)
for i in go_away_msgs:
    time.sleep(2)
    print(i)
time.sleep(0.5)
```
The text is encoded with base32. Since it appears that the text has undergone a variety of encodings, [Cyberchef's](https://gchq.github.io/CyberChef/) Magic module allows us to dispense of most of them to arrive at the following string:

```
Ea`I"Ap[6t20:Wp0ed`-?SQG?1NI(a@l$>t
```

For reference, the text is first decoded from Base32, then decoded from Base64, unzipped using Gzip, decoded from binary twice, and finally decoded from hex.

This string is encoded with Base85. Decoding the Base85 gives us the flag `ractf{My5t3r10u5_1nt3rf4c3?}`
