from pwnlib.tubes import remote
completed = 0
prompt_key = "Please enter the secret key to encrypt the data with:"
prompt_plain = "Please enter the data that you would like to encrypt:"
prompt_enced = "Your encrypted message is:"

r = remote.remote('95.216.233.106', 13691)

all_chars = "".join([chr(i) for i in range(32,127)])

sums = []
for c in all_chars:
	buf = r.recvuntil([b'\n', b': ']).decode('utf-8')[:-1]
	while buf[:len(prompt_key)] != prompt_key:
		print (buf)
		buf = r.recvuntil([b'\n', b': ']).decode('utf-8')[:-1]
	r.sendline((c).encode('utf8'))
	buf = r.recvuntil([b'\n', b': ']).decode('utf-8')[:-1]
	while buf[:len(prompt_plain)] != prompt_plain:
		print (buf)
		buf = r.recvuntil([b'\n', b': ']).decode('utf-8')[:-1]
	r.sendline((' ').encode('utf8'))
	
	buf = r.recvline().decode('utf-8')[:-1]
	while buf[:len(prompt_enced)] != prompt_enced:
		print (buf)
		buf = r.recvline().decode('utf-8')[:-1]
	sums.append(buf[len(prompt_enced):])
	
	print (' ', c)
	
for c in all_chars:
	buf = r.recvuntil([b'\n', b': ']).decode('utf-8')[:-1]
	while buf[:len(prompt_key)] != prompt_key:
		print (buf)
		buf = r.recvuntil([b'\n', b': ']).decode('utf-8')[:-1]
	r.sendline((c).encode('utf8'))
	
	buf = r.recvuntil([b'\n', b': ']).decode('utf-8')[:-1]
	while buf[:len(prompt_plain)] != prompt_plain:
		print (buf)
		buf = r.recvuntil([b'\n', b': ']).decode('utf-8')[:-1]
	r.sendline(('~').encode('utf8'))
	
	buf = r.recvline().decode('utf-8')[:-1]
	while buf[:len(prompt_enced)] != prompt_enced:
		print (buf)
		buf = r.recvline().decode('utf-8')[:-1]
	sums.append(buf[len(prompt_enced):])
	
	print ('~', c)
	
print (sums)

