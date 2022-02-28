from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import base64
from binascii import hexlify,unhexlify

def topad(string,size):
	strlen = len(string)
	if size == strlen:
		return string
	num = size-(strlen%size)
	pad = unhexlify('{:02x}'.format(num)) * num
	return string+pad

def getsize():
	invalid = True
	error = "Invalid input enter a number multiple of 8"
	while invalid:
		size = input("Enter block size: ")
		try:
			ret = int(size)
			assert(ret%8==0)
			invalid = False
		except:
			print("Error :" + error)
	return ret

string = input("Enter string to pad: ")
size = getsize()

print(topad(string.encode(),size))
