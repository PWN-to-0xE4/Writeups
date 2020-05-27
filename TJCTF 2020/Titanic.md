# Titanic
## 35 points - Writeup by Ana :)

This challenge presents us with the following description:

`I wrapped tjctf{} around the lowercase version of a word said in the 1997 film "Titanic" and created an MD5 hash of it: 9326ea0931baf5786cde7f280f965ebb.`

Instantly we can see that the flag will look something like `tjctf{interesting}`, and we have to create a wordlist from the script of Titanic, which we then bruteforce until we find the matching hash.

I tried to script minimally for this challenge as this was at the very start of the CTF (and I am lazy), so I copied all of http://sites.inka.de/humpty/titanic/script.html into https://convertcase.net/ and shifted it into lowercase.

Then, I pasted the output from that into https://www.ipvoid.com/remove-punctuation/, and removed full stops, commas and colons. Anything that wasn't a hyphen or apostrophe seemed deletable to me, as those could form a part of a word and sure enough, the flag did contain an apostrophe.

Next, I used https://texthandler.com/text-tools/remove-double-spaces/ to remove any double spaces, and finally I used https://www.browserling.com/tools/spaces-to-newlines to get my final output. I then saved this to a file which I named `wordlist.txt`. However, this isn't all ready for cracking yet - I then used the following Python script in order to quickly wrap each word on each newline in `tjctf{}` so that I could then crack the hashes properly. Here's the script I used:

```python
with open('wordlist.txt', 'r') as f:
    content = f.readlines()
    with open('output.txt', 'w')as o:
        for x in content:
            o.write('tjctf{' + x.strip() + '}\n')
```

Finally, after saving the hash into `hash.md5`, we can simply run it through john using `john hash.md5 -w=./output.txt --format=Raw-md5`
We then crack the hash to get the flag - `tjctf{ismay's}`
