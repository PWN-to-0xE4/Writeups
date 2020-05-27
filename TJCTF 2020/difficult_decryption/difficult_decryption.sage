# Set up provided information in text file

encoded = 12259991521844666821961395299843462461536060465691388049371797540470 # Sage assumes integer literals are its own type
alice_key = 232042342203461569340683568996607232345
bob_key = 76405255723702450233149901853450417505
base, modulus = 5, 491988559103692092263984889813697016406
mod_base = Mod(base, modulus)

# Calculate A (and B, because why not ) using Pohlig-Hellman (helpfully done by Sage very quickly)

A = discrete_log(alice_key,mod_base)
B = discrete_log(bob_key,mod_base)

# Calculate the shared key (from both perspectives)

shared_key_alice = int(pow(bob_key,A,modulus)) # Sage returns its own integer type, which is incompatible with bitwise XOR
shared_key_bob = int(pow(alice_key,B,modulus))
assert shared_key_alice == shared_key_bob


# Decode the message and print the flag
decoded = encoded ^^ shared_key_alice # Sage uses ^ for expoentiation, rather than bitwise XOR

flag = bytes.fromhex(hex(decoded)[2:]).decode("ascii") # tjctf{Ali3ns_1iv3_am0ng_us!}
print(flag)
