# Vandalism

### Writeup by dvoak, 250 points

`That admin panel was awfully bare. There must be some other page, but we've no idea where it is. *Just to clarify, ractf{;)} is the greedy admins stealing all the flags, it's not the actual flag.*`

In The X Headers, X-OptionalHeader == Location: /__adminPortal

Navigating there, it's been vandalized.

View-Source reveals zalgo text.

Unzalgo with any website, although you could just figure it out from looking at it:
https://cable.ayra.ch/zalgo/

## Flag: ractf{h1dd3n1npl4n3s1ght}
