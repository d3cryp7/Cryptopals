from Crypto.Cipher import AES
from  Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from binascii import unhexlify
import base64
import random
from collections import Counter

'''
random_bytelen_encoded = b'MjA=' #base64.b64encode(str(random.randint(5,35)).encode())
random_byte_len = int(base64.b64decode(random_bytelen_encoded).decode('utf-8'))
'''
prefix_bytes = b't;{\xe3cw\xea\x93\xbe\xb1\x19Z\xddF$\x1b\x8d\x80\xfb\xdd' #get_random_bytes(random_byte_len)
enc_key = b'\x18\xefK,\x0c\xcc9\xf4\xe5\x8fK\xd4O\xbc_\x8b' #get_random_bytes(16)

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
	randomize = prefix_bytes + data + decoded_a
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

# We need to find the minimum number of A's to send to keep the prefix chars intact during our
# brute force guessing of the postfix chars. So we send 100 A's and then copy the encrypted value
# of a block of A's. We then loop over sending 0 to 100 A's during each iteration, we break the result
# enc in to 16 byte blocks and check if the block is equal to encrypted A's block value.
# If we found our first block for 'i' num of A's, we break the loop and return the number of
# A's that took to produce one A's block and how many blocks of encrypted bytes are present until
# this continuous A's block is hit.

def calc_blocks_inputs():
	for i in range(100):
		data = "A" * i
		enc_data = crypto(data.encode())
		#print(enc_data)
		blocks = []
		counter = 0 
		for j in range(0,len(enc_data),16):
			counter+=1
			if enc_data[j:j+16] == b'\xb4\xc4@\x89\xf5`2@\x85\xc7\xfc\xd2%\xc9J\x0b':
				'''
				print("Number of A's to get a full block: " + str(i))
				print("Number of blocks until block of A's: " + str(counter))
				'''
				return counter,i

def getPrefixBlockLen():
	block_count, num_of_dummy_chars = calc_blocks_inputs()
	# block count is 3 where 3rd block is all A's. So we consider the previous 2 blocks alone
	length_to_subtract_from = (block_count-1) * 16
	'''
	# the number of bytes in 2 blocks is 32, from that subtract the number of A's on the second block
	# to get the lenghth of unknown prefix string.
	'''
	len_of_prefix_string = length_to_subtract_from - (num_of_dummy_chars-16)
	'''
	print("Number of A's to send at a minimum: " + str(num_of_dummy_chars))
	print("Length of prefix string: " + str(len_of_prefix_string))
	'''
	return num_of_dummy_chars,len_of_prefix_string

min_chars,prefix_len = getPrefixBlockLen()

# We intentionally send one byte less than 16. The unknown string when appended to our input,
# the first letter of that unknown string will be the 16th byte of first block along with our 15 byte input
# upon enc, we get the encrypted value of the first letter of unknown string on the 16th position of our enc output
# now we do another enc call, this time we will brute force the 16th byte in our input with all 0-255 decimal ascii 
# the value b/w 0-255 that produces same encrypted 16th byte as the 16th byte that we got from attempt where
# we sent 15 byte input is the correct 1st byte of the unknown string.
# Store this correctly guessed character and repeat iteration by decreasing input byte length (15,14,13..so on)
# we will find up to 16 characters of the unknown string.

def start_guess():
	guessed = b''
	print(prefix_len)
	max_chars = ((min_chars-1) + (16*30))
	for i in range(max_chars,-1,-1):
		data = "A" * i
		enc_data = crypto(data.encode())
		try:
			to_match = enc_data[:max_chars + prefix_len + 1]
		except:
			pass

		for i in range(256):
			dat = data.encode() + guessed + unhexlify('{:02x}'.format(i))
			enc_data_guessed = crypto(dat)
			to_check = enc_data_guessed[:528]
			if to_match == to_check:
				guessed+=unhexlify('{:02x}'.format(i))
				#print(guessed)
				break
	print(guessed[:len(guessed)-1])

start_guess()

'''
data = "A" * 27
enc_data = crypto(data.encode())
to_match = enc_data[47]

for i in range(1,256):
	dat = data.encode() + unhexlify('{:02x}'.format(i))
	enc_data_guessed = crypto(dat)
	#print(enc_data_guessed)
	to_check = enc_data_guessed[47]
	if to_match == to_check:
		guessed=unhexlify('{:02x}'.format(i))
		print(guessed)
		break
'''

