from Crypto.Cipher import AES
from  Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from binascii import unhexlify
import base64
import random
from collections import Counter

enc_key = b'w\x9b\x1a\xf8\xde5\x19[\x95H\xfcOj\x9f\x06X' #key = get_random_bytes(16)

a = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

to_dec_a = a.replace("\n","")
decoded_a = base64.b64decode(to_dec_a)

def do_ecb(k,padded):
	cipher = AES.new(k,AES.MODE_ECB)
	return cipher.encrypt(padded)


def crypto(data):
	randomize = data + decoded_a
	padded = pad(randomize,16)
	return do_ecb(enc_key,padded)


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

# For finding block size. The encrypted output length increases by 16 for every few input lengths
# so we can conclude that the block size is 16

def find_block_size():
	lengths = []
	diff = []
	for i in range(120):
		data = "a" * i
		enc_data = crypto(data.encode())
		l = len(enc_data)
		if l not in lengths:
			lengths.append(l)
	for i in range(len(lengths)):
		try:
			diff.append(lengths[i+1]-lengths[i])
		except:
			pass
	if len(set(diff)) == 1:
		print("Block size is: " + str(diff[0]))

# For finding the cipher mode, we send repeated characters of large length
# so during encryption, at least a couple of blocks of plain text will be same
# when these blocks get encrypted by ECB mode, they produce same encrypted blocks
# we then divide the encrypted output into 16 characters chunks and then count
# how many time each of these chunks were repeated in the encrypted output
# if atleast one block is repeated atleast twice, we know it's ECB mode
def find_cipher_mode():
	data = "a" * 120
	enc_data = crypto(data)
	detect(enc_data)

# We intentionally send one byte less than 16. The unknown string when appended to our input,
# the first letter of that unknown string will be the 16th byte of first block along with our 15 byte input
# upon enc, we get the encrypted value of the first letter of unknown string on the 16th position of our enc output
# now we do another enc call, this time we will brute force the 16th byte in our input with all 0-255 decimal ascii 
# the value b/w 0-255 that produces same encrypted 16th byte as the 16th byte that we got from attempt where
# we sent 15 byte input is the correct 1st byte of the unknown string.
# Store this correctly guessed character and repeat iteration by decreasing input byte length (15,14,13..so on)
# we will find up to 16 characters of the unknown string.

guessed = b''
for i in range(495,-1,-1):
	data = "a" * i
	enc_data = crypto(data.encode())
	try:
		to_match = enc_data[:496]
	except:
		pass

	for i in range(00,256):
		dat = data.encode() + guessed + unhexlify('{:02x}'.format(i))
		enc_data_guessed = crypto(dat)
		to_check = enc_data_guessed[:496]
		if to_match == to_check:
			guessed+=unhexlify('{:02x}'.format(i))
			#print(guessed)
			break
print(guessed[:len(guessed)-1])

