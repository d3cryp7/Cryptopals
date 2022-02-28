from Crypto.Cipher import AES
from  Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
import random
from collections import Counter

def do_ecb(key,padded):
	cipher = AES.new(key,AES.MODE_ECB)
	return cipher.encrypt(padded)

def do_cbc(key,padded,IV):
	cipher = AES.new(key,AES.MODE_CBC,IV)
	return cipher.encrypt(padded)

def crypto(data):
	a = random.randrange(5,10)
	#b = random.randrange(5,10)
	randomize = get_random_bytes(a) + data.encode() + get_random_bytes(a)
	padded = pad(randomize,16)
	key = get_random_bytes(16)
	method = random.randrange(2)
	if method == 1:
		return do_ecb(key,padded)
	else:
		IV = get_random_bytes(16)
		return do_cbc(key,padded,IV)


def detect(enc_data):
	print("\nAttempting to find the cipher mode...")
	chunks = []
	for i in range(0,len(enc_data),16):
		chunks.append(enc_data[i:i+16])
	frequ = Counter(chunks)
	count = 0
	for key in frequ:
		count += frequ[key]
	if count > len(frequ):
		print("Data encrypted in ECB mode")
	else:
		print("Data encrypted in CBC mode")

data = "a"*60

enc_data = crypto(data)

print(enc_data)

detect(enc_data)
