#!/usr/bin/env python
import itertools as it

ascii_lowercase = "abcdefghijklmnopqrstuvwxyz"
punctuation = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

message = "paddingandstuffaaaaaaaaa_tjctf{bens really do make you frtalot}"
key = "akfymcx"

assert len(message) == 63 and set(message).issubset(set(ascii_lowercase + punctuation))
assert len(key) == 7 and set(key).issubset(set(ascii_lowercase))
assert message.count("tjctf{") == 1 and message.count("}") == 1 and message.count(" ") == 5

def get_key_indexes(n):
    i, j, k = n % 3, n // 3 % 7, n // 21
    return i, j, k

out = []
for n, m in enumerate(message):
    i,j,k = get_key_indexes(n)
    out.append(
        ord(m)
      ^ ord(key[i])
      ^ ord(key[j])
      ^ ord(key[k])
    )

print(str(out)[1:-1])

exit()

out = []
for k, j, i in it.product(range(3), range(7), range(3)):
    out.append(
        ord(message[i + (3 * j) + (21 * k)])
      ^ ord(key[j])
      ^ ord(key[i])
      ^ ord(key[k])
    )

print(str(out)[1:-1])

exit()

print(
    str(
        [
            x
            for z in [
                [
                    [
                        ord(message[i + (3 * j) + (21 * k)])
                      ^ ord(key[j])
                      ^ ord(key[i])
                      ^ ord(key[k])
                        for i in range(3)
                    ]
                    for j in range(7)
                ]
                for k in range(3)
            ]
            for y in z
            for x in y
        ]
    )[1:-1]
)
