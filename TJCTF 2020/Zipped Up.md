# Zipped Up

This challenge was a fairly standard recursive archive extraction challenge
with a slight twist in that the file containing the flag isn't actually the
one nested the deepest.

The code rather speaks for itself, so without further ado, here it is.

```py
import tarfile, io
from zipfile import ZipFile
import sys

sys.setrecursionlimit(100000)


def handle(name, data):
    if name.endswith('.txt'):
        if b'n0t_th3_fl4g' not in data:
            print(data)
            quit()
    elif '.tar' in name:
        extract_tar(data, name.split('.')[-1])
    elif '.kz3' in name:
        extract_zip(data)


def extract_zip(data):
    dat = io.BytesIO()
    dat.write(data)
    dat.seek(0)
    zip_file = ZipFile(dat)

    for name in zip_file.namelist():
        data = zip_file.read(name)
        handle(name, data)


def extract_tar(data, mode):
    dat = io.BytesIO()
    dat.write(data)
    dat.seek(0)
    tar_file = tarfile.open(fileobj=dat, mode='r:' + mode)

    for i in tar_file:
        data = tar_file.extractfile(i).read()
        handle(i.name, data)


if __name__ == '__main__':
    extract_tar(open('1.tar.bz2', 'rb').read(), 'bz2')
```
