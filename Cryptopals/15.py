from binascii import unhexlify
'''
from Crypto.Cipher import AES
from  Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
import base64
import random
from collections import Counter
'''

def check_pkcs(padded):
	if len(padded)%16 == 0:
		return 16
	elif len(padded)%8 == 0:
		return 8
	else:
		raise ValueError("Neither pkcs#7 or pkcs#5. Check your input")

b = b"ICE ICE BABY\x04\x04\x04\x04"

def upad(to_unpad):
	block_size  = check_pkcs(to_unpad)
	blocks = []
	for i in range(0,len(to_unpad),block_size):
		blocks.append(to_unpad[i:i+block_size])
	padded = blocks.pop()
	remaining = b''
	for b in blocks:
		remaining += b
	digit = padded[-1] # take the last byte in the input as reference to num of padded chars
	#print("Int value of last byte is: " + str(digit))
	pad_chars = unhexlify('{:02x}'.format(digit)) * digit # multiply the padded char to it's int value. Ex. if padding is \x04 then multiply by 4
	#print("Padded chars block to compare with: " + pad_chars.decode('utf-8'))
	if padded[-(digit):] == pad_chars: # check if the padded portion of the input is same as the expected padding for the last byte. So if \x04 is last byte we are expecting 4 continuous \x04 chars after the unpadded chars
		return remaining+padded[:-(digit)]
	else:
		raise ValueError("Incorrect padding")

padded = b"aaaaaaaaaaaaaaaaaaaaaaa\t\t\t\t\t\t\t\t\t"

print(upad(padded))
	
	
	
