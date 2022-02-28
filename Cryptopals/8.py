import base64
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from collections import Counter

with open("8.txt","r") as f:
	file = f.read()

enc_list = file.split('\n')

l = 16

for enc in enc_list:
	broken_list = []
	unhex = unhexlify(enc)
	for i in range(0,len(unhex), l):
		broken_list.append(unhex[i:i+l])
	d = Counter(broken_list)
	c = [x for x in d if d[x]>1]
	if len(c) >=1:
		print(d)
		print(enc)
		print(enc_list.index(enc))
