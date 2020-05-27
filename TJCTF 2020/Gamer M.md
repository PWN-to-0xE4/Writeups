# Gamer M

```py
import random

def shuffle(s):
    for i in range(len(s)):
        j = random.randint(0, len(s) - 1)
        s[i], s[j] = s[j], s[i]
    return s

def combat(level):
    rps = ["rock", "paper", "scissors"]
    crit = rps[random.randint(0, 2)]
    if crit == "rock":
        print("A disciple stands in your way! Take your action!")
    elif crit == "paper":
        print("A disciple blocks your way! Take your action!")
    elif crit == "scissors":
        print("A disciple stalls your advance! Take your action!")

    print("\tChoose your weapon ('rock', 'paper', 'scissors')")
    if input("\tChoice: ").lower().strip() == crit:
        print("Sucess!")
        for name, c in level:
            print("%s dropped: %s" % (name, c))
        print("You rest and continue your journey.\n")
        return 1
    else:
        print(
            "It wasn't very effective! The disciple counters with a seven page combo of punches and you die."
        )
        print("Try again when you reincarnate.")
        return 0

def game():
    flag = open("flag.txt").read().strip()
    names = shuffle([i.strip() for i in open("names.txt").readlines()])
    match = [(names[i], flag[i]) for i in range(len(flag))]

    levels = shuffle(
        [
            shuffle(match[::5]),
            shuffle(match[1::5]),
            shuffle(match[2::5]),
            shuffle(match[3::5]),
            shuffle(match[4::5]),
        ]
    )

    print(
        "Welcome to the temple.\n"
        + "\n"
        + "You will face five tests.\n"
        + "Each test involves combat against five disciples.\n"
        + "Each disciple holds a key.\n"
        + "Combine the keys to unlock the scroll's message."
    )

    for n, level in enumerate(levels):
        print()
        print("- = - Level %i - = - " % (n + 1))
        if not combat(level):
            return

    print("You triumphed over all trials!")

if __name__ == "__main__":
    game()
```

While there's quite a bit going on in this challenge, there are only a handful
of things that are going to be important for solving it.

1. The game of RPS is dead easy to automate based on the prompt;
2. The flag is chunked into 5 blocks, like `1234512345123451234512345`;
3. Each block is shuffled individually, then the order of the 5 blocks is shuffled;
4. The shuffler function is actually not perfectly random.

Of these, 4 is probably the hardest to notice. If we use this shuffle function
to shuffle the array `[0, 1, 2, 3, 4]` a million times, then look at the
average output, what we see is `[4, 0, 1, 2, 3]`. If we do it again, we get
that exact same pattern. In fact, no matter how many times we run it, we'll,
on average, see `[4, 0, 1, 2, 3]`, and this is where the bias comes in.

To be able to abuse this bias, we need a lot of data, so I wrote a script that
could play the game automatically (and 10 times simultaniously, too) which
then dumped the outputted letters into a nice long JSON file.

A single game then looks somewhat like this:

```js
[
    ["A", "2", "C", "t", "r"],
    ["x", "F", "J", "f", "}"],
    ["6", "t", "{", "0", "R"],
    ["3", "e", "j", "b", "i"],
    ["5", "4", "o", "c", "n"]
]
```

On paper, we now have a number of different shuffles we need to reverse in
order to get the flag. In reality, it's not so hard. The flag is going to
start with `tjctf{`, so we can have a look and see if we can find that in the
data. There are two cases of `t`, but only one of `{`, so we know which of the
5 blocks goes first. Repeating this logic for the remainder of `jtcf`, we can
re-order that chunk of blocks into this:

```js
[
    ["6", "t", "{", "0", "R"],
    ["3", "e", "j", "b", "i"],
    ["5", "4", "o", "c", "n"],
    ["A", "2", "C", "t", "r"],
    ["x", "F", "J", "f", "}"]
]
```

Doing this automatically to all of the 1000 collected chunks means we can now
focus on all of the #1 chunks, all of the #2 chunks, and so on.

The logic for un-shuffling the data is deceptively simple: The letter that
appears most as the 5th letter (index 4) is probably the first letter in that
block. The character that appears most as the first letter (index 0) is most
likely the second letter, and so on. The short script I used for this is
below.

```py
import json
d = open('data2.json').read()
d = json.loads(d)

unique = ['{', 'j', 'c', 'C', 'f']
flag = [0] * 25
for n, unq in enumerate(unique):
    data = []
    for i in d:
        for j in i:
            if unq in j:
                data.append(j)

    for m, i in enumerate([4, 0, 1, 2, 3]):
        idx = [j[i] for j in data]

        mx = max(set(idx), key=idx.count)
        flag[m * 5 + n] = mx
print(''.join(flag))
```

This script also handles reconstruction of the flag from the 5 blocks, which
saves us a little time. The output from the script, however, isn't perfect.

```
0jot}{i5AJ0borFRenCx6342}
```

This is likely due to only having 1000 data points. As it would happen though,
the only mistakes it made was the duplication of the letters `0`, `o`, and
`}`. We know those letters won't be at the start, so we can fix the start of
the flag (`tjctf{`) and leave the second occurances of those letters where
they are. This gives the flag!
