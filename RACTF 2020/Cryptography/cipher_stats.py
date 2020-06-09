import json
import math

with open("cipherstatsdata.txt") as f:
    jsonblob = f.read()

cipher_types = json.loads(jsonblob)

LOGDI = [
    [4,7,8,7,4,6,7,5,7,3,6,8,7,9,3,7,3,9,8,9,6,7,6,5,7,4],
    [7,4,2,0,8,1,1,1,6,3,0,7,2,1,7,1,0,6,5,3,7,1,2,0,6,0],
    [8,2,5,2,7,3,2,8,7,2,7,6,2,1,8,2,2,6,4,7,6,1,3,0,4,0],
    [7,6,5,6,8,6,5,5,8,4,3,6,6,5,7,5,3,6,7,7,6,5,6,0,6,2],
    [9,7,8,8,8,7,6,6,7,4,5,8,7,9,7,7,5,9,9,8,5,7,7,6,7,3],
    [7,4,5,3,7,6,4,4,7,2,2,6,5,3,8,4,0,7,5,7,6,2,4,0,5,0],
    [7,5,5,4,7,5,5,7,7,3,2,6,5,5,7,5,2,7,6,6,6,3,5,0,5,1],
    [8,5,4,4,9,4,3,4,8,3,1,5,5,4,8,4,2,6,5,7,6,2,5,0,5,0],
    [7,5,8,7,7,7,7,4,4,2,5,8,7,9,7,6,4,7,8,8,4,7,3,5,0,5],
    [5,0,0,0,4,0,0,0,3,0,0,0,0,0,5,0,0,0,0,0,6,0,0,0,0,0],
    [5,4,3,2,7,4,2,4,6,2,2,4,3,6,5,3,1,3,6,5,3,0,4,0,5,0],
    [8,5,5,7,8,5,4,4,8,2,5,8,5,4,8,5,2,4,6,6,6,5,5,0,7,1],
    [8,6,4,3,8,4,2,4,7,1,0,4,6,4,7,6,1,3,6,5,6,1,4,0,6,0],
    [8,6,7,8,8,6,9,6,8,4,6,6,5,6,8,5,3,5,8,9,6,5,6,3,6,2],
    [6,6,7,7,6,8,6,6,6,3,6,7,8,9,7,7,3,9,7,8,9,6,8,4,5,3],
    [7,3,3,3,7,3,2,6,7,2,1,7,3,2,7,6,0,7,6,6,6,0,3,0,4,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6,0,0,0,0,0],
    [8,6,6,7,9,6,6,5,8,3,6,6,6,6,8,6,3,6,8,8,6,5,6,0,7,1],
    [8,6,7,6,8,6,5,7,8,4,6,6,6,6,8,7,4,5,8,9,7,4,7,0,6,2],
    [8,6,6,5,8,6,5,9,8,3,3,6,6,5,9,6,2,7,8,8,7,4,7,0,7,2],
    [6,6,7,6,6,4,6,4,6,2,3,7,7,8,5,6,0,8,8,8,3,3,4,3,4,3],
    [6,1,0,0,8,0,0,0,7,0,0,0,0,0,5,0,0,0,1,0,2,1,0,0,3,0],
    [7,3,3,4,7,3,2,8,7,2,2,4,4,6,7,3,0,5,5,5,2,1,4,0,3,1],
    [4,1,4,2,4,2,0,3,5,1,0,1,1,0,3,5,0,1,2,5,2,0,2,2,3,0],
    [6,6,6,6,6,6,5,5,6,3,3,5,6,5,8,6,3,5,7,6,4,3,6,2,4,2],
    [4,0,0,0,5,0,0,0,3,0,0,2,0,0,3,0,0,0,1,0,2,0,0,0,4,4]
]

SDD = [
    [0,3,4,2,0,0,1,0,0,0,4,5,2,6,0,2,0,4,4,3,0,6,0,0,3,5],
    [0,0,0,0,6,0,0,0,0,9,0,7,0,0,0,0,0,0,0,0,7,0,0,0,7,0],
    [3,0,0,0,2,0,0,6,0,0,8,0,0,0,6,0,5,0,0,0,3,0,0,0,0,0],
    [1,6,0,0,1,0,0,0,4,4,0,0,0,0,0,0,0,0,0,1,0,0,4,0,1,0],
    [0,0,4,5,0,0,0,0,0,3,0,0,3,2,0,3,6,5,4,0,0,4,3,8,0,0],
    [3,0,0,0,0,5,0,0,2,1,0,0,0,0,5,0,0,2,0,4,1,0,0,0,0,0],
    [2,0,0,0,1,0,0,6,1,0,0,0,0,0,2,0,0,1,0,0,2,0,0,0,0,0],
    [5,0,0,0,7,0,0,0,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,5,0,0,0,4,0,0,0,1,1,3,7,0,0,0,0,5,3,0,5,0,0,0,8],
    [0,0,0,0,6,0,0,0,0,0,0,0,0,0,5,0,0,0,0,0,9,0,0,0,0,0],
    [0,0,0,0,6,0,0,0,5,0,0,0,0,4,0,0,0,0,0,0,0,0,1,0,0,0],
    [2,0,0,4,2,0,0,0,3,0,0,7,0,0,0,0,0,0,0,0,0,0,0,0,7,0],
    [5,5,0,0,5,0,0,0,2,0,0,0,0,0,2,6,0,0,0,0,2,0,0,0,6,0],
    [0,0,4,7,0,0,8,0,0,2,2,0,0,0,0,0,3,0,0,4,0,0,0,0,0,0],
    [0,2,0,0,0,8,0,0,0,0,4,0,5,5,0,2,0,4,0,0,7,4,5,0,0,0],
    [3,0,0,0,3,0,0,0,0,0,0,5,0,0,5,7,0,6,0,0,3,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9,0,0,0,0,0],
    [1,0,0,0,4,0,0,0,2,0,4,0,0,0,2,0,0,0,0,0,0,0,0,0,5,0],
    [1,1,0,0,0,0,0,1,2,0,0,0,0,0,1,4,4,0,1,4,2,0,4,0,0,0],
    [0,0,0,0,0,0,0,8,3,0,0,0,0,0,3,0,0,0,0,0,0,0,2,0,0,0],
    [0,4,3,0,0,0,5,0,0,0,0,6,2,3,0,6,0,6,5,3,0,0,0,0,0,6],
    [0,0,0,0,8,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
    [6,0,0,0,2,0,0,6,6,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0,0],
    [3,0,7,0,1,0,0,0,2,0,0,0,0,0,0,9,0,0,0,5,0,0,0,6,0,0],
    [1,6,2,0,0,2,0,0,0,6,0,0,2,0,6,2,1,0,2,1,0,0,6,0,0,0],
    [2,0,0,0,8,0,0,0,0,6,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,9]
]


def get_ic(ct):
    cc = [0] * 26
    
    for ch in ct:
        cc[ch] += 1
    su = sum([cc[i] * (cc[i] - 1) for i in range(26)])
    return (su*1000) / (len(ct) * (len(ct) - 1))

def get_max_ic(ct):
    mx = 0
    max_period = 15

    for period in range(1, max_period + 1):
        cc = [[0] * 26] * max_period
        idx = 0
        for ch in ct:
            cc[idx][ch] += 1
            idx = (idx + 1) % period

        z = 0
        for i in range(period):
            x = 0
            y = 0
            for j in range(26):
                x += cc[i][j] * (cc[i][j] - 1)
                y += cc[i][j]
            if y > 1:
                z += x / (y * (y - 1))

        z = z / period
        if z > mx:
            mx = z
    return 1000 * mx

def get_kappa(ct):
    max_period = 15
    mx = 0

    for period in range(1, max_period + 1):
        cc = 0
        for i in range(len(ct) - period):
            if ct[i] == ct[i + period]:
                cc += 1
        z = cc / (len(ct) - period)
        if z > mx:
            mx = z

    return 1000 * mx

def get_dic(ct):
    cc = [0] * (26**2)
    for i in range(len(ct) - 1):
        cc[ct[i] + (26 * ct[i + 1])] += 1
    su = 0
    for i in range(26**2):
        su += cc[i] * (cc[i] - 1)
    return (su * 10000) / ((len(ct) - 1) * (len(ct) - 2))

def get_even_dic(ct):
    cc = [0] * (26**2)
    for i in range(0, len(ct) - 1, 2):
        cc[ct[i] + (26 * ct[i + 1])] += 1
    su = 0
    for i in range(26**2):
        su += cc[i] * (cc[i] - 1)
    return (su * 10000) / ((len(ct)//2) * ((len(ct)//2) - 1))

def get_lr(ct):
    reps = [0] * 11
    for i in range(len(ct)):
        for j in range(i + 1, len(ct)):
            n = 0
            while j + n < len(ct) and ct[i + n] == ct[j + n]:
                n += 1
            if n > 10:
                n = 10
            reps[n] += 1

    return ( 1000 * math.sqrt(reps[3]) ) / len(ct)

def get_rod(ct):
    su_all = 0
    su_odd = 0

    for i in range(len(ct)):
        for j in range(i + 1, len(ct)):
            n = 0
            while j + n < len(ct) and ct[i + n] == ct[j + n]:
                n += 1
            if n > 1:
                su_all += 1
                if (j - i) % 2 == 1:
                    su_odd += 1

    if su_all == 0:
        return 50
    return 100 * (su_odd / su_all)

def get_logdi(ct):
    score = 0
    for i in range(len(ct) - 1):
        score += LOGDI[ct[i]][ct[i + 1]]
    return (score * 100) / (len(ct) - 1)

def get_sdd(ct):
    score = 0
    for i in range(len(ct) - 1):
        score += SDD[ct[i]][ct[i + 1]]
    return (score * 100) / (len(ct) - 1)

def score_ciphertext(s):
    ct = [ord(ch) - 65 for ch in s.upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    if len(ct) < 50:
        print ("Ciphertext too short to find meaningful values. Aborting")
        return

    cipher_stats = {
        "IC": get_ic(ct),
        "MIC": get_max_ic(ct),
        "MKAP": get_kappa(ct),
        "DIC": get_dic(ct),
        "EDI": get_even_dic(ct),
        "LR": get_lr(ct),
        "ROD": get_rod(ct),
        "LDI": get_logdi(ct),
        "SDD": get_sdd(ct)
    }

    possible = []
    for cipher in cipher_types.keys():
        X = 0
        for stat in cipher_stats.keys():
            sigma = cipher_types[cipher][stat][1]
            mu = cipher_types[cipher][stat][0]
            if stat == "IC":
                sigma += 0.001
            if mu == 0:
                X += cipher_stats[stat]
            else:
                X += abs((cipher_stats[stat] - mu) / sigma)
        possible.append([cipher, round(X, 2)])
    return [cipher_stats, sorted(possible, key= lambda n : n[1])]

ciphertext = input("Enter ciphertext: ")
print ()
ctext_score = score_ciphertext(ciphertext)
for s in ctext_score[0].keys():
    print (s + ": " + str(round(ctext_score[0][s], 2)), end="   ")
print ("\n")
for c in ctext_score[1][:15]:
    print (c[0] + " " + str(c[1]))


    
            
        
        
