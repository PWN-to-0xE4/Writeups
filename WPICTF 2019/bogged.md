# Cryptography 3: bogged

This challenge was an interesting one. We were presented with a TCP service,
and then a `leaked_source.py`.

When we connect to the service, it's something like this (a little whitespace
removed):
```
BOGDANOFF:

Bonjour...
We have access to the Binance backdoor, and got you into a compromised teller station.
We need you to steal tethered cryptocurrency from people's wallets.
We were halted by an unfortunate countermeasure in the teller system, but we have an account ready to recieve the stolen crypto.
Steal the currency from cryptowojak123. Transfer it to not_b0gdan0ff.
Transfer everything... then we will kill him, and find another.
Do not fail us.

Welcome to the Binance Teller Terminal!
Please remember to use admin-issued auth tokens with each account transfer!

Either enter a command or one of the following keywords:

accounts: List of accounts currently on the system.
history: A history of prior terminal commands.
help: A reminder on how to use this terminal.

Command:
>>>help

You may either withdraw funds from an account or deposit funds to an account.
Withdraw with the following command:
withdraw ACCOUNT_NAME
Deposit with the following command:
deposit ACCOUNT_NAME
Commands may be chained, as follows:
withdraw ACCOUNT_NAME;deposit ACCOUNT_NAME;...

An authorization token unique to the command contents must exist for the transaction to succeed!
(Sorry, but we have to protect from malicious employees.)
Contact admin@dontactuallyemailthis.net to get auth tokens for different transfer commands!

Command:
>>>accounts

cryptowojak123
sminem.1337
xXwaltonchaingangXx
john.doe
not_b0gdan0ff

Command:
>>>history

///// TRANSACTION HISTORY //////////////////////////

Command:
>>>withdraw john.doe
Auth token:
>>>b4c967e157fad98060ebbf24135bfdb5a73f14dc
Action successful!

Command:
>>>withdraw john.doe;deposit xXwaltonchaingangXx
Auth token:
>>>455705a6756fb014a4cba2aa0652779008e36878
Action successful!

Command:
>>>withdraw cryptowojak123;deposit xXwaltonchaingangXx
Auth token:
>>>e429ffbfe7cabd62bda3589576d8717aaf3f663f
Action successful!

Command:
>>>withdraw john.doe
Auth token:
>>>b4c967e157fad98060ebbf24135bfdb5a73f14dc
Action successful!

////////////////////////////////////////////////////

Command:
>>>withdraw john.doe
Auth token:
>>>test

Error: Auth token does not match provided command..

Command:
>>>withdraw john.doe
Auth token:
>>>b4c967e157fad98060ebbf24135bfdb5a73f14dc

Action successful!
```

What we have to do is `withdraw cryptowojak123;deposit not_b0gdan0ff`.
Although not shown in those few interactions with the terminal, if we just
tried it we'd need an auth token for it, which we don't have. About those
auth tokens though..  They're 40 digits long; smells like SHA1. Being super
smart, when doing this challenge I didn't actually realise we had the leaked
source. Said source would have confirmed this though with
```py
def generate_command_token(command, secret):
    hashed = hashlib.sha1(secret+command).hexdigest()
    return hashed
```
What I found by experimenting (but could have found out quite easilly) was
that there's a secret being concatinated on before before the command before
hashing.

This is where it gets interesting. SHA1 as a hashing function is broken
because a collision can be caused, but there's a bigger problem here: SHA1 is
being used as a HMAC token with a constant secret. That's bad, really bad.
Let's abuse that!!

The thing with SHA1 is that you can work out the hash of a new string,
provided that you already have the hash of an existing string, and your new
string starts with that existing one. The best part here though is that
**you don't need the secret**. This is called a SHA1 padding/length extension
attack. Because I felt like it, I chose my known one to be `withdraw
cryptowojak123;deposit xXwaltonchaingangXx`, which had the auth token of
`e429ffbfe7cabd62bda3589576d8717aaf3f663f` (see the `history` command above). Because `;` is a command seperator, we just need to get `;withdraw cryptowojak123;deposit not_b0gdan0ff` concatinated onto that command.

Does first withdrawing from one account, depositing it, then trying to
withdraw from that same account make any sense? No. Did the challenge care?
No. Do I, therefore, care? Also no.

Being a fairly common vulnerability, I found a libray online called `shaext`
that can abuse it for us. Python time!

```py
import socket

from shaext import shaext

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('bogged.wpictf.xyz', 31337))

# Flush the buffer
s.recv(4096), s.recv(4096)

ORIGINAL = "withdraw cryptowojak123;deposit xXwaltonchaingangXx"
SIGNIATURE = "e429ffbfe7cabd62bda3589576d8717aaf3f663f"
MSG_APPEND = ";withdraw cryptowojak123;deposit not_b0gdan0ff"

for keylen in range(200):
    print('keylen = {}'.format(keylen))

    sha1 = shaext(ORIGINAL, keylen, SIGNIATURE)
    sha1.add(MSG_APPEND)
    new_msg, new_sig = sha1.final()

    s.send(new_msg + b'\n')
    s.recv(4096), s.recv(4096)
    s.send(new_sig.encode() + b'\n')
    ret = s.recv(4096) + s.recv(4096)

    if b'WPI{' in ret:
        flag = ret.split(b'WPI{')[-1].split(b'}')[0]
        flag = b'WPI{' + flag + b'}'
        print(flag)
        break
```

That's actually quite painless. Most of that is just boilerplate, with heavy
lifting being done by the shaext library. What's important here though is
that we don't actually know the length of `secret`. This is one of the things
needed for the attack to work, but luckily we can just try everything until
one works :D.

If we let that script run, we get
```py
keylen = 0
keylen = 1
keylen = 2
keylen = 3
keylen = 4
keylen = 5
keylen = 6
keylen = 7
keylen = 8
keylen = 9
keylen = 10
keylen = 11
keylen = 12
keylen = 13
keylen = 14
keylen = 15
keylen = 16
WPI{duMp_33t_aNd_g@rn33sh_H1$_wAg3$}
```

Oh hey. A flag. Very nice. Let's have a look at what the actual command it
used was though.

```
withdraw cryptowojak123;deposit xXwaltonchaingangXx\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x18;withdraw cryptowojak123;deposit not_b0gdan0ff
```

What we can se here is that we have the original command that we used as our
starting place, then it adds a large amount of padding, based off the keylen,
then drops out extra command onto the end for us. When the server goes to
hash that string, the hash it computes ends up being the same as the hash we
guessed it as, and so it lets us run the command.
