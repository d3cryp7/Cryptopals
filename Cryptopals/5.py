from binascii import hexlify,unhexlify
import math

with open("5.txt","rb") as f:
	file = f.read()


k = "ICE"

key = k * int(len(file)/len(k))

list = []

for i in range(0,len(file)):
	list.append(file[i]^ord(key[i]))

st = b''

for i in list:
	st += ('{:02x}'.format(i)).encode()

print("Xored output is:\n")
print(st)
