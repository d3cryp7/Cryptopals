from binascii import unhexlify, hexlify
from Crypto.Cipher import AES
from  Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
import base64
import random
from collections import Counter

key = b'I\xe2\x0b\xa1\xc67\x96!dR#\xfc\xb0\x88B\xb9' #get_random_bytes(16)
IV = b's?\x1d*\x17k0\xd2\xe0j\xaf\xfap\xb5\xf7(' #get_random_bytes(16)

def form_input(data):
	prefix = "comment1=cooking%20MCs;userdata="
	suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
	data = data.replace(';','";"')
	data = data.replace('=','"="')
	return prefix + data + suffix

def do_pad(to_pad):
	l = len(to_pad)
	x = 16-l%16
	return to_pad+(unhexlify('{:02x}'.format(x))*x)

def enc(to_pad):
	data = do_pad(to_pad)
	cipher = AES.new(key,AES.MODE_CBC,IV)
	return cipher.encrypt(data)

def dec(cipher_txt):
	decipher = AES.new(key,AES.MODE_CBC,IV)
	d = decipher.decrypt(cipher_txt)
	return unpad(d,16)

def check_admin(cipher_txt):
	plain_txt = dec(cipher_txt)
	split = plain_txt.split(b";")#plain_txt.decode('utf-8').split(";")
	for kv in split:
		d = {kv.split(b"=")[0]:kv.split(b"=")[1]}
		if b'admin' in d:
			return d[b'admin']==b"true"
	return("admin not found")

'''

-> Length of the prefix string is 32 bytes, so we know it's 2 blocks
-> Now the user input will be starting from the 3rd block
-> For CBC we know by modifying a char on 1 block will affect the 2 block char at the same position
-> so we need to have at least 32 bytes user controlled data such that we can form the expected admin=true in 2nd block by modifying 1st block both of which is attacker controlled
-> I have used 3 blocks of user controlled data
-> I will have the expected admin=true formed in 3rd block by modifying encrypted 2 block
-> Using CBC bit flipping technique, we will change an 'a' to ';' and another 'a' to '=' chars
-> when validating for admin , our input will pass and return true
'''

data = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbaaaaaaadminatrue"
to_pad = form_input(data).encode()
cipher_txt = enc(to_pad)
print('Original ciphertext:')
print(cipher_txt)
print('\nFlipped ciphertext:')
flipped = b'\xf4\xbb\x8e\xf3\x8fP\x1b\x0e\xa9K\x1a-\x06\x8eB\xff\xb5\xc6\x1b\xb6X\xd4z\x87\x16V\xf6u\x14,\x11\x9e\x06\x00\x12Y\xd8\xa0\xea\x99\xb5\xf2\xc4\xd5(\xb2\xe4<1\x9f\xac\xf8\xb6\tX\xb0\xad\xe4Y\x9a\xd8\xd9S"Q\xd3h\x03\x14\x952\xe1\x91\x8c\xb8\x95q\xcf\x1c\xb9EU\xec\x82\xa2(\xb1K\x834\xf8\xf7\xc4"\'\x8e\xe2\xfb\xfc\xc9\xfb`\x83V\xdf\xd2\x89.u\x16TL\x9c)\xdea}<\xd1\xad\xa0\xd2\xd1\xc7m\xb5p\t'
print(flipped)
plain_txt = dec(cipher_txt)
print('\nDecrypted Original ciphertext:')
print(plain_txt)
flipped_plain_txt = dec(flipped)
print('\nDecrypted Flipped ciphertext:')
print(flipped_plain_txt)
print('\ndoing admin validation on flipped text....')
print(check_admin(flipped))

'''
# manual bit flipping calculation
\x53 ^ dec(x) = \x61
dec(x) = \x53 ^ \x61
\x53 ^ \x32 = \x61
? ^ \x32 = \x3b
? = \x32 ^ \x3b
-------------------
\xc6 ^ dec(x) = \x61
dec(x) = \xc6 ^ \x61
? ^ \xa7 = \x3d
? = \xa7 ^ \x3d
'''

