# Teleport

### Writeup by Ana, 300 Points

`One of our admins plays a strange game which can be accessed over TCP. He's been playing for a while but can't get the flag! See if you can help him out.`

In this challenge, we are given a service to connect to via Netcat, as well as some challenge source code which goes as follows:

```python
import math

x = 0.0
z = 0.0
flag_x = 10000000000000.0
flag_z = 10000000000000.0
print("Your player is at 0,0")
print("The flag is at 10000000000000, 10000000000000")
print("Enter your next position in the form x,y")
print("You can move a maximum of 10 metres at a time")
for _ in range(100):
    print(f"Current position: {x}, {z}")
    try:
        move = input("Enter next position(maximum distance of 10): ").split(",")
        new_x = float(move[0])
        new_z = float(move[1])
    except Exception:
        continue
    diff_x = new_x - x
    diff_z = new_z - z
    dist = math.sqrt(diff_x ** 2 + diff_z ** 2)
    if dist > 10:
        print("You moved too far")
    else:
        x = new_x
        z = new_z
    if x == 10000000000000 and z == 10000000000000:
        print("ractf{#####################}")
        break
```

Also, when connecting to the service, we can see that we have to input a new position in order to move to it - however, the program calculates a distance from your current position to the new position via the Pythagorean theorem, and if this distance is greater than 10, we waste one go in our current position. 

Furthermore, we can see that we only have 100 turns of being able to move, and since the position we have to reach is (10000000000000, 10000000000000), we can effectively conclude we must somehow get to this position by cheating the system, as it is impossible otherwise. 

I noticed something interesting about the coordinates - they all have a datatype of `float`. This makes sense as floats are used to represent decimal numbers, which usually arise from the square-root stage of calculating a hypotenuse from Pythagoras - nonetheless, it is equally easy to abuse a float in this case, by casting something that is _not a number_ to it. 

And when I say not a number, I really mean it - after looking through this reference for floats (https://www.geeksforgeeks.org/float-in-python/) I saw this:

The method accepts:

1. **A number :** Can be an Integer or a floating point number.
2. A String :
   - Must contain numbers of any type.
   - Any left or right whitespaces or a new line is ignored by the method.
   - Mathematical Operators can be used.
   - Can contain NaN, Infinity or inf (any cases)

We can therefore cast NaN to the coordinates, and since NaN isn't a number, the Pythagorean theorem cannot give a defined result of the distance being less than 10, and hopefully, we can get our flag:

````
Enter next position(maximum distance of 10): NaN, NaN 
Current position: nan, nan
Enter next position(maximum distance of 10): 10000000000000, 10000000000000
ractf{fl0at1ng_p01nt_15_h4rd}
````

We now have the flag!