# Really Secret Algorithm
### Writeup by arcayn, 300 points
```
We've received a weird message, but it's not in a format we've ever seen before.


  -*-*-*- BEGIN ARR ESS AYY MSG -*-*-*-
     0000000000000000000000000000000
     0000000000000000000000000000000
     0000000000000000000000000000000
     0000000000000000000000000000000
     0000000000000000000000000000000
     00000s&nYASMBl==Raa6f1mSybO1&`P
     n=MSlA^HVasQovKL?f9nB=?Wjz*-}bj
     4rNeU}9v(Tcn16Ji;Mjv?)4T@pD@76=
     9j%)LevT&=&p%BMcIckO@P450UqkjIR
     6DT^igJmh5<xI<alHa3p;VuZ%5HWp>1
                #T6e(?T*2I
                  00962
     jx@>fERjV6gRSH!+pdv<kOoEVD#<P05
     <nAMIT@fYQOcbQ{VfQh+sli_--_zE8)
     G@9Y^2j=XLkGz;kZTPS&eJtOKwM~!V6
     SmtDRCJ%568a_utlnc?ywyQ^??W!-Ro
     `%%d9c?q+nQ*s<4Sn4@*0vXe9sl<*c8
                  *WY0^
   -*-*-*- END ARR ESS AYY MSG -*-*-*-


We also recovered a snippet of the generator function, but we've not been able to get anywhere with it.


def encrypt(message):
    p,q=rsa.prime_pair(bits=1024)
    ct=base64.b85encode(rsa.encrypt(rsa.solve_for(p=p,q=q,e=e),message.encode()))
    ct=b'\n'.join(ct[i:i+31].center(41)for i in range(0,len(ct),31))
    p,q=int.to_bytes(p,128,'big'),int.to_bytes(q,128,'big')
    s,key=0,bytearray()
    for(i,j)in zip(p,q):
        key.append(i^s)
        key.append((j^(s:=s^i),s:=s^j)[0])
    key=base64.b85encode(key)
    key=b'\n'.join(key[i:i+31].center(41)for i in range(0,len(key),31))
    e_str=base64.b85encode(int.to_bytes(e,4,'big')).center(41)
    return b'  -*-*-*- BEGIN ARR ESS AYY MSG -*-*-*-\n' + key + b'\n' + e_str + b'\n' + ct + b'\n' + b'   -*-*-*- END ARR ESS AYY MSG -*-*-*-\n'

```
This was a reversing challenge in disguise. We're some strange text, and the python used to generate it:
```python
def encrypt(message):
    p,q=rsa.prime_pair(bits=1024)
    ct=base64.b85encode(rsa.encrypt(rsa.solve_for(p=p,q=q,e=e),message.encode()))
    ct=b'\n'.join(ct[i:i+31].center(41)for i in range(0,len(ct),31))
    p,q=int.to_bytes(p,128,'big'),int.to_bytes(q,128,'big')
    s,key=0,bytearray()
    for(i,j)in zip(p,q):
        key.append(i^s)
        key.append((j^(s:=s^i),s:=s^j)[0])
    key=base64.b85encode(key)
    key=b'\n'.join(key[i:i+31].center(41)for i in range(0,len(key),31))
    e_str=base64.b85encode(int.to_bytes(e,4,'big')).center(41)
    return b'  -*-*-*- BEGIN ARR ESS AYY MSG -*-*-*-\n' + key + b'\n' + e_str + b'\n' + ct + b'\n' + b'   -*-*-*- END ARR ESS AYY MSG -*-*-*-\n'
```
So just like Really Simple Algorithm, we're given everything we need to decrypt the ciphertext, except this time we're going to need to work for it.
Visually we can see where the three sections are, so let's pull them out:
```python
e_str = "00962"
ct  = "jx@>fERjV6gRSH!+pdv<kOoEVD#<P05<nAMIT@fYQOcbQ{VfQh+sli_--_zE8)G@9Y^2j=XLkGz;kZTPS&eJtOKwM~!V6SmtDRCJ%568a_utlnc?ywyQ^??W!-Ro`%%d9c?q+nQ*s<4Sn4@*0vXe9sl<*c8*WY0^"
key = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000s&nYASMBl==Raa6f1mSybO1&`Pn=MSlA^HVasQovKL?f9nB=?Wjz*-}bj4rNeU}9v(Tcn16Ji;Mjv?)4T@pD@76=9j%)LevT&=&p%BMcIckO@P450UqkjIR6DT^igJmh5<xI<alHa3p;VuZ%5HWp>1#T6e(?T*2I"
```
`e_str` is a base85 encoding of the bytes which the `e` public exponent used in this encryption represents. We can reverse this with a one-liner:
```python
> int.from_bytes(base64.b85decode(e_str), byteorder="big")
65537
```
Same for `ct`:
```python
> int.from_bytes(base64.b85decode(ct), byteorder="big")
99860594127018908794158834191193241523130963241776507981252591495991917500700391136315550911410747730355512069677894278882869016148102263664033592640008912612299974810513062400731422845727549254941662464478708866098010588377570106442046342432065620078039609128230066039712041115582348192500069030066835644725
```
`key` is a bit different. First each of `p,q` is converted to a byte string. Then we iterate through each byte `i` in `p` and `j` in `q`. After getting through a little obfuscation, largely based on the new python 3.8 walrus operator (`:=`), we see that we alternate bytes `i` and `j` in the output string, and each byte is XORed with the previous one as the `key` byte string is constructed, with a seed of 0. Finally the `key` byte string is base85 encoded. We can reverse this whole process with a small python script:
```python
dec_key = base64.b85decode(key)
i_s = b''
j_s = b''

s = 0
for i,d in enumerate(dec_key):
    t = d^s
    s = d
    if i%2 == 0:
        i_s += bytes([t])
    else:
        j_s += bytes([t])
p = int.from_bytes(i_s, byteorder="big")
q = int.from_bytes(j_s, byteorder="big")
```
And finally we do the RSA math in Sage:
```python
> p = 8935533316664982385690426241789463156779334270200983340957286950060861311077151464930402912151709770833375547368974424564809135614170092179811531622097999
> q = 11379478034699907676633030046472807804044882783405443091999142030427354686298593670992789218031609011985520050382686352162426667346054932520656108554445759
> e = 65537
> ct = 99860594127018908794158834191193241523130963241776507981252591495991917500700391136315550911410747730355512069677894278882869016148102263664033592640008912612299974810513062400731422845727549254941662464478708866098010588377570106442046342432065620078039609128230066039712041115582348192500069030066835644725
> phi = (p - 1) * (q - 1)
> n = p * q
> d = inverse_mod(e, phi)
> pow(ct, d, n)
183802254535729688441422466855678202790709660852167686422214013
```
Converting this output to bytes, we get the flag: `ractf{DoY0uLik3MyW4lrus35}`
