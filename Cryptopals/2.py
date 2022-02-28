# Write a function that takes two equal-length buffers and produces their XOR combination.
# If your function works properly, then when you feed it the string: 
# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against: 
# 686974207468652062756c6c277320657965
# ... should produce: 
# 746865206b696420646f6e277420706c6179

import base64
from binascii import hexlify, unhexlify

input1 = input("Enter string 1: ")
input2 = input("Enter string 2: ")

u1 = unhexlify(input1)
u2 = unhexlify(input2)

xored = []
l1 = len(u1)
l2 = len(u2)

if l1 == l2:
	del l2
	for i in range(0,l1):
		xored.append(u1[i]^u2[i])

print("Xored list is:")
print(xored)

output = ''

for i in xored:
	output = output + '{:x}'.format(i)

print("Your output after hex encoding the xored list is:")
print(output)
