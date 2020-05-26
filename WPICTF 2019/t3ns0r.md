# Stegonography 5: T3ns0r
Oh boy. This one was fun. The downloaded files contained a
`readme.txt` with just
```
kernel_size=n
stride=n-1
rotation=True
mirror=False
```
and then a file called `data.npy` containing a large numpy array.
Given that readme, I had assumed there might be something to do with
colvolution, but upon loading the array into python I was presented
with a `(1540, 24, 24, 3)` array. In other words, 1540 images, all
with a red, green, and blue channel, and 24x24 pixels in size. Time
to have a look in them!

```py
import numpy as np
import cv2
data = np.load('data.npy')
for n, i in enumerate(data):
    cv2.imwrite(f'images/{n}.png', i)
```

It was.. underwhelming. All the images had a large amount of static,
any by nature of being 24x24 pixels, I couldn't tell much about what
they were. I had forgotten the one hint though, the readme file. If
we assumed that these images were orinally one large image, that had
had a convolutional filter pass over it, then we could expect to get
a large number of sub-images out. Taking the kernel size to be 24, a
stride of 23 would imply that each image shared a strip 1 pixel wide,
with at least two other images (because of corners).

Unfortunatly, the tiles weren't provided in a logical order. Because
of this, I wrote an algorithm that first "locked" a single tile into
place. It then iterated over every single other tile, trying them in
all 4 rotations on all free edges, until one worked. That new tile
was then "locked" into place in the rotation that matched, and the
cycle repeated (except this time instead of checking just around one
tile, there are now two to check). Although not maximally efficient,
this is a quick and easy algorithm to use, and produces the image
needed at the end -- or so I though.

It turns out that some of the tiles had black borders, and thus had
lots of different matches with tiles they weren't meant to match to.
Instead of assuming that these tiles were edge pieces (turns out they
were :D) I just had the algorithm ignore any edges with just black on
them. This isn't much of a problem because the tiles with black edges
still have some sites without black edges.

I ran the code, went an made a coffee, and when I came back lo and
behold there was a picture of Kanzaki Ranko holding a sign
encouraging me to go and vote Yang 2020 with ample noise applied to
the image. Oh, and it had a flag on it. The final part of this
challenge was working out what was an uppercase `i` or a lower case
`L`. This is why flags should be serifed. Reeeee.

![Kanzaki Ranko](./t3ns0r.png)

And here's the ~~wonderful~~ code I used to piece together the image:

```py
import numpy as np
import cv2


d = np.load('data.npy')

kernel = 24
stride = 23

taken_pos = []


class Tile:
    def __init__(self, cont):
        self.cont = cont
        self.rot = 0
        self.around = 0

        self.x = self.y = None

    def match(self, other):
        sides = ['top', 'left', 'bottom', 'right']

        cont = np.rot90(self.cont, self.rot)

        if (self.x, self.y - 1) not in taken_pos:
            s_top = cont[:1, :]
            if np.any(s_top > 0.1):
                for i in range(4):
                    o = np.rot90(other.cont, i)[-1:, :]
                    if np.all(o == s_top):
                        other.x = self.x
                        other.y = self.y - 1
                        taken_pos.append((self.x, self.y - 1))
                        other.rot = i
                        self.around += 1
                        return True

        if (self.x, self.y + 1) not in taken_pos:
            s_bot = cont[-1:, :]
            if np.any(s_bot > 0.1):
                for i in range(4):
                    o = np.rot90(other.cont, i)[:1, :]
                    if np.all(o == s_bot):
                        other.x = self.x
                        other.y = self.y + 1
                        taken_pos.append((self.x, self.y + 1))
                        other.rot = i
                        self.around += 1
                        return True

        if (self.x - 1, self.y) not in taken_pos:
            s_left = cont[:, :1]
            if np.any(s_left > 0.1):
                for i in range(4):
                    o = np.rot90(other.cont, i)[:, -1:]
                    if np.all(o == s_left):
                        other.x = self.x - 1
                        other.y = self.y
                        taken_pos.append((self.x - 1, self.y))
                        other.rot = i
                        self.around += 1
                        return True

        if (self.x + 1, self.y) not in taken_pos:
            s_right = cont[:, -1:]
            if np.any(s_right > 0.1):
                for i in range(4):
                    o = np.rot90(other.cont, i)[:, :1]
                    if np.all(o == s_right):
                        other.x = self.x + 1
                        other.y = self.y
                        taken_pos.append((self.x + 1, self.y))
                        other.rot = i
                        self.around += 1
                        return True

        return False


tiles = [Tile(i) for i in d]
matched = [tiles.pop(1000)]
matched[0].x = 100
matched[0].y = 100
taken_pos.append((0, 0))


while tiles:
    for j in matched:
        if j.around == 4:
            continue
        print(len(tiles))
        for i in tiles:
            if j.match(i):
                tiles.remove(i)
                matched.append(i)
                break


new_img = np.zeros((20000, 20000, 3))
done = []

for t in matched:
    x = t.x * stride
    y = t.y * stride

    new_img[y:y+kernel, x:x+kernel, :] = np.rot90(t.cont, t.rot)

cv2.imwrite('out.png', new_img)
```