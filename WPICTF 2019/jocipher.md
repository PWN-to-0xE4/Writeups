# Cryptography 2: jocipher
This challenge presented you with the code
`PIY{zsxh-sqrvufwh-nfgl}` and a file named `jocipher.pyc`.
This file is a python bytecode file for Python 2, which sucks
becuase Python 3 reigns supreme. Instead of just running
`python2` instead of `python`, I dropped into a decompiler,
and then just grabbed the source code. Again not being a
massive fan of the use of globals, I rewrote it (partially - I
didn't do the encoding function), to get
```py
NUM = '0123456789'
FIRST = 'qwertyuiop'
SECOND = 'asdfghjkl'
THIRD = 'zxcvbnm'
LETTERS = FIRST + SECOND + THIRD

def decode(string, shift):
    result = ''
    shift *= -1
    for n, char in enumerate(string.lower()):
        if char in NUM:
            new_char = NUM[(NUM.index(char) + shift) % len(NUM)]
            result += new_char
        elif char in LETTERS:
            lookup = FIRST if char in FIRST else SECOND if char in SECOND else THIRD
            new_char = lookup[(lookup.index(char) + shift) % len(lookup)]
            result += new_char.upper() if string[n].isupper() else new_char
        else:
            result += char

    return result
 ```
Of interest here is that it's using a standard ceaser shift,
but instead of the whole alphabet it's operating on rows on a
QWERTY keyboard.
That done, it was time to bruteforce the key. All flags start
with `WPI{` so a quick run though of shifts from 0 to 100
listed quite a few shifts starting with `WPI`. Of those, only
one actually contained English in the flag (a good sign), and
that was `48`. Lo and behold, the flag was
`WPI{xkcd-keyboard-mash}`.