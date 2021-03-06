# NS.MOV

### Writeup by Segway, 350 points

`https://youtu.be/DO_sBpC2xbw`

The video consists of a male voice dictating numbers. After a while, the numbers are repeated.
The numbers provided are all two digits, and the pauses between numbers imply that the numbers form pairs.
The numbers are as follows:

```
32 82 94 63 35 64 46 99 55 81 89 43 58 84 89 96 87 35 35 23 62 93 89 45 76 57 49 89 67 47 98 14 46 87 44 24 68 54 78 47 82 54 98 11 57 86 82 47 69 28 29 52 19 97 33 64 55 84 94 42 72 46 82 41 75 37 21 37 61 73 96 84 91 56 92 49 66 55 47 78 64 44 66 46 58 67 18 38 79 61 65 32 66 38 54 95 99 12 34 95 65 97 11 43 49 67 84 53 94 61 88 44 65 39 56 67 85 59 13 61 38 82 41 29 68 39 59 79 84 33 91 58 37 73 35 79 99 26 34 22 95 45 43 74 48 84 42 67 83 69 49 85 26 58 17 49 75 57 71 38 61 94 88 44 65 39 95 36 49 79 23 39 42 94 19 62 36 71 33 85 59 71 88 57 84 56 81 61 35 99 41 29 61 79 86 55 36 64 45 68 69 83 93 32 31 63 63 31 36 86 36 69 43 72 49 69 45 75 89 34 78 32 46 39 63 75 12 56 37 79 99 23 99 47 36 69 12 96 38 74 43 82 25 45 68 54 41 72 33 69 98 11 59 93 71 58 54 22 64 96
```

We can form a list of pairs in Python using `list(zip(*[iter(s)]*2))`:

```
[(32, 82), (94, 63), (35, 64), (46, 99), (55, 81), (89, 43), (58, 84), (89, 96), (87, 35), (35, 23), (62, 93), (89, 45), (76, 57), (49, 89), (67, 47), (98, 14), (46, 87), (44, 24), (68, 54), (78, 47), (82, 54), (98, 11), (57, 86), (82, 47), (69, 28), (29, 52), (19, 97), (33, 64), (55, 84), (94, 42), (72, 46), (82, 41), (75, 37), (21, 37), (61, 73), (96, 84), (91, 56), (92, 49), (66, 55), (47, 78), (64, 44), (66, 46), (58, 67), (18, 38), (79, 61), (65, 32), (66, 38), (54, 95), (99, 12), (34, 95), (65, 97), (11, 43), (49, 67), (84, 53), (94, 61), (88, 44), (65, 39), (56, 67), (85, 59), (13, 61), (38, 82), (41, 29), (68, 39), (59, 79), (84, 33), (91, 58), (37, 73), (35, 79), (99, 26), (34, 22), (95, 45), (43, 74), (48, 84), (42, 67), (83, 69), (49, 85), (26, 58), (17, 49), (75, 57), (71, 38), (61, 94), (88, 44), (65, 39), (95, 36), (49, 79), (23, 39), (42, 94), (19, 62), (36, 71), (33, 85), (59, 71), (88, 57), (84, 56), (81, 61), (35, 99), (41, 29), (61, 79), (86, 55), (36, 64), (45, 68), (69, 83), (93, 32), (31, 63), (63, 31), (36, 86), (36, 69), (43, 72), (49, 69), (45, 75), (89, 34), (78, 32), (46, 39), (63, 75), (12, 56), (37, 79), (99, 23), (99, 47), (36, 69), (12, 96), (38, 74), (43, 82), (25, 45), (68, 54), (41, 72), (33, 69), (98, 11), (59, 93), (71, 58), (54, 22), (64, 96)]
```

XORing each pair provides us with the following string:
```
racMfrn9t4ctuhlly4radio}Y)ractf{n0t4cmually4radio}  ractf{n0t4ctually4radi\x16d  ractf{~0t-ct|all@4radi\x16}  ractf{n\tt4jtLally4radif}  '
```

The string appears to be a repeated transmission of the flag, but with distortions.

Through handy guessing, we can reconstruct the flag as `ractf{n0t4ctually4radio}`
