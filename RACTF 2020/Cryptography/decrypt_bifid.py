import PyKrak
import random
import math

def decrypt_bifid(ciphertext, key, period):
    # compute keysquare indices for efficiency
    indices = {}
    characters = {}
    for i,c in enumerate(key):
        indices[c] = str(i//5) +  str(i%5)
        characters[str(i//5) +  str(i%5)] = c
    # pad with spaces
    ciphertext += ' ' * (len(ciphertext) % period)
    # chunk ciphertext
    ciphertext_chunks = [ciphertext[i : i + period] for i in range(0, len(ciphertext), period)]

    # decrypt
    plaintext = ""
    for chunk in ciphertext_chunks:
        # write out row
        row = "".join([indices[c] for c in chunk.replace(" ", "")])
        for i in range(len(row)//2):
            # read off letters column-wise
            plaintext += characters[row[i] + row[i + len(row)//2]]

    return plaintext

def swap_letters(key):
    a = random.randint(0,len(key) - 1)
    b = random.randint(0,len(key) - 1)
    s = list(key)
    s[a],s[b] = s[b],s[a]
    return ''.join(s)

START_TEMP = 20
COOLING_RATE = 0.1/10000
def T(time):
    t = START_TEMP - (COOLING_RATE * time)
    return t

def P(e0, e1, t):
    if e0 - e1 > 0:
        return 1.1
    if t == 0:
        return 0
    return math.exp( ((e0 - e1) / t) )
    
def simulated_annealing(ciphertext, iterations, period):
    # initialise to some more sensible values
    best_key = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    best_score = 100000
    best_plaintext = ""
    # use a quadgram scorer this time
    scorer = PyKrak.Scorers.MarkovScorer([4])
    for i in range(iterations):
        # use a mutation function to make a small change to the key
        # in this case swapping a letter
        temp_key = swap_letters(best_key)
        # decode the ciphertext with temp_key
        temp_plaintext = decrypt_bifid(ciphertext, temp_key, period)
        # score the result (assuming a smaller-is-better approach)
        temp_score = scorer.score(temp_plaintext)
        # apply the simulated annealing
        if P(best_score, temp_score, T(i)) > random.random():
            best_score = temp_score
            best_key = temp_key
            best_plaintext = temp_plaintext
            print (best_plaintext)
    return best_plaintext



ct = "DPKFCLISLAKWMDWERUKWXPDIDBRADATRTMOLKKGNYUEIELDEOCVRTUMFLCVGRBSVSDTHDKWMHOGTAECOMWEYMITWOSSEFKFBEAWKSAEOKSRSNZRNEORLTHISDWZCORQSRAMYVSIRIRGECZIDRMMVCRHGBYEWSLSOCWMBULGKDADELQUBWKLFCMWGQRYSPAEZBDAPIRGWSQSFACLUMARVERUILKBAATNOFCKWWATCKKIIUSWDEIAPKSWSGOHCFYMSDODSMUORATDEKUNRRSGNETHDWPHRGAEODLLOEFHBEOWCQWNAOBRUWWCCHOSOLUACCXPWABEAWAROHARO"
period = 5
print (simulated_annealing(ct, 100000, period))
        
