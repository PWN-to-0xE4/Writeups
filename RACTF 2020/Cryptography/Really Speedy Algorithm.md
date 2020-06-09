# Really Speedy Algorithm
### Writeup by arcayn, 350 points
`
Connect to the network service to get the flag. The included template script may be of use.
`

This one was a bit different. This time, we're given a service to connect to, but instead of giving us a single RSA math problem like in Really Simple Algorithm, we're given 100, and we only get 200ms to answer each one. The parameters we can be given is any one of `p, q, n, phi, e, pt, ct, d`, and we could be asked for any one of the above which we can trivially derive from what we have been given. The challenge comes with some boilerplate code for interacting with the server, but broadly our strategy is to just grab everything we're sent for each question and load them into memory. Once a question is asked, it would be a lot of work to figure out the precise chain of calculations we need to do to get the value we want, but we probably have enough room in 200ms to derive everything we can with the data we're given and then just output whatever the sever asked for. We're going to use SageMath for fast math and we're going to run the file as a `.spyx` which will take advantage of automatic Cython compilation for extra speed. I won't paste all the code along with the networking boilerplate but it's available in `speedy.spyx`. Here's the routine which computes all our different possibilities (each variable is initialized to `-1` if it hasn't been given input).

```python
if P == -1:
    if N != -1 and Q != -1:
        P = N//Q
    elif PHI != -1 and Q != -1:
        P = (PHI//(Q-1)) + 1
        
if Q == -1:
    if N != -1 and P != -1:
        Q = N//P
    elif PHI != -1 and P != -1:
        Q = (PHI//(P-1)) + 1

if PHI == -1:
    if P != -1 and Q != -1:
        PHI = (P-1)*(Q-1)

if N == -1:
    if P != -1 and Q != -1:
        N = P*Q

if D == -1:
    if E != -1 and PHI != -1:
        D = inverse_mod(PHI,E)

if PT == -1:
    if CT != -1 and D != -1 and N != -1:
        PT = pow(CT,D,N)
        
if CT == -1:
    if PT != -1 and E != -1 and N != -1:
        CT = pow(PT,E,N)
```
There were a few teething problems with the service to begin with. The script was running slow on the server side which meant that it was often exceeding the 200ms time limit despite my code being fast enough. By about midnight on the first day though traffic had died down enough to be able to successfully submit. We run the script and get the flag `ractf{F45t35tCryp70gr4ph3rAr0und}`

Out of curiosity I timed how fast my script performed the calculations in comparison to the `200ms` time limit. For the attempt here to get the flag, my slowest calculation was `30.1ms`, so the inefficiency of calculating everything never became an issue
