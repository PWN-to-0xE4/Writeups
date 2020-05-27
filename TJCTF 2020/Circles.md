# Circles
## 10 points - Writeup by Ana :)

This challenge was quite interesting to complete. We are first given the following challenge description:

`Some typefaces are mysterious, like this one - its origins are an enigma wrapped within a riddle, indeed.`

We are also provided with the flag, but each letter has been replaced by a symbol. We can tell it's the encoded flag from the curly brackets surrounding it, but we need to somehow figure out exactly what encoded it and revert the text to its normal format.

![](https://raw.githubusercontent.com/PWN-to-0xE4/Writeups/master/TJCTF%202020/Circles.png)

We can fill in a few letters since we know the flag is wrapped in `tjctf{}`, but this doesn't help a lot - we need to find the font (which is indicated by the fact that a typeface is mentioned in the description). Speaking of the description, we can start by googling that, which leads us to https://www.fonts.com/. It's clear that we need to find the font here.

Here's the tricky part - finding the font itself. The website has way too many fonts to go through individually, so refining search criteria is essential. After trying a few different search permutations, we are led to the right font once we search with the word `circular`!

Now that we're linked to the font's page (https://www.fonts.com/search/all-fonts?ShowAllFonts=All&searchtext=USF%20Circular%20Designs), we can start trying to decode the flag! I typed in all the alphanumeric characters in the preview box to see all the characters we needed.

![](https://raw.githubusercontent.com/PWN-to-0xE4/Writeups/master/TJCTF%202020/circles1.png)
![](https://raw.githubusercontent.com/PWN-to-0xE4/Writeups/master/TJCTF%202020/circles2.png)
![](https://raw.githubusercontent.com/PWN-to-0xE4/Writeups/master/TJCTF%202020/circles3.png)

Finally, we can use this as a reference to decode the flag - which is `tjctf{B3auT1ful_f0Nt}`.
