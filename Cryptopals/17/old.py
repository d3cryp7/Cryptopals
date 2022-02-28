from binascii import unhexlify, hexlify
from Crypto.Cipher import AES
from  Crypto.Random import get_random_bytes
from Crypto.Random.random import choice
from Crypto.Util.Padding import pad,unpad
import base64
import random
from collections import Counter

strings_list = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

key = b'I\xe2\x0b\xa1\xc67\x96!dR#\xfc\xb0\x88B\xb9' #get_random_bytes(16)
IV = b's?\x1d*\x17k0\xd2\xe0j\xaf\xfap\xb5\xf7(' #get_random_bytes(16)

def check_pkcs(padded):
	if len(padded)%16 == 0:
		return 16
	elif len(padded)%8 == 0:
		return 8
	else:
		raise ValueError("Neither pkcs#7 or pkcs#5. Check your input")

def do_unpad(to_unpad):
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

def do_pad(to_pad):
	l = len(to_pad)
	x = 16-l%16
	return to_pad+(unhexlify('{:02x}'.format(x))*x)

def enc(to_pad):
	data = pad(to_pad,16)#do_pad(to_pad)
	cipher = AES.new(key,AES.MODE_CBC,IV)
	return cipher.encrypt(data)

def dec(cipher_txt):
	decipher = AES.new(key,AES.MODE_CBC,IV)
	d = decipher.decrypt(cipher_txt)
	try:
		do_unpad(d)
		return True,d
	except:
		return False,None

def do_brute(cts,n):
	for num in range(256):
		x = cts[len(cts)-2]
		cts[len(cts)-2] = x[:15]+ unhexlify('{:02x}'.format(num))
		to_dec = b''
		for seg in cts:
			to_dec+=seg
		check,plain_txt = dec(to_dec)
		if check == True:
			print("Number that returned valid padding: " + str(num))
			print("Calculating the plain text value...")
			e7 = hex(cipher_text[len(cipher_text)-16-1]) # encrypted previous block last byte
			i15 = hex(int(hex(num),16) ^ int('0x1',16)) # intermediate text
			c15 = hex(int(e7,16) ^ int(i15,16)) # cleartext
			print(c15)
			print("computing second byte...")
			e7_2 = int(i15,16) ^ int('0x2',16)
		

def brute(cts,cipher_text):
	guesses = []
	for num in range(256):
		x = cts[len(cts)-2]
		cts[len(cts)-2] = get_random_bytes(15) + unhexlify('{:02x}'.format(num)) #x[:15]+ unhexlify('{:02x}'.format(num))
		to_dec = b''
		for seg in cts:
			to_dec+=seg
		check,plain_txt = dec(to_dec)
		if check == True:
			print("Number that returned valid padding: " + str(num))
			#print(plain_txt)
			print("Calculating the plain text value...")
			e7 = hex(cipher_text[len(cipher_text)-16-1]) # encrypted previous block last byte
			i15 = hex(int(hex(num),16) ^ int('0x1',16)) # intermediate text
			c15 = hex(int(e7,16) ^ int(i15,16)) # cleartext
			print(c15)
			print("computing second byte...")
			e7_2 = int(i15,16) ^ int('0x2',16)
			for num1 in range(256):
				cts[len(cts)-2] = x[:14]+ unhexlify('{:02x}'.format(num1)) + unhexlify('{:02x}'.format(e7_2))
				to_dec1 = b''
				for seg1 in cts:
					to_dec1+=seg1
				check1,plain_txt1 = dec(to_dec1)
				if check1 == True:
					print("Number that returned valid 2nd padding: " + str(num1))
					i14 = hex(int(hex(num1),16)^int('0x2',16))
					e6 = hex(cipher_text[len(cipher_text)-16-1-1])
					c14 = hex(int(e6,16) ^ int(i14,16))
					print(c14)
					break		
			break
	return True,guesses

def guess_padding(cipher_text):
	hit = False
	while hit==False:
		cts = []
		for i in range(0,len(cipher_text),16):
			cts.append(cipher_text[i:i+16])
		hit,guesses = brute(cts,cipher_text)
	


#chosen = choice(strings_list).encode()
chosen = b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl'
cipher_txt = enc(chosen)
#cipher_txt = b'fQ\xb1@\ta{ii\xa0\x15Vp\xb6a\x84h\xfe^V=^F\xb6\xb60\xf3\xabt\xe9\xc4\xae\xf8\xcf\xe9+UJ\xb9F\xa5\xf1\x16o\xa2I\xeci>:P\x08\x8b\xb17\xf4\xae\xf0\xd56\x8f\xcf7s'
print('Ciphertext:')
print(cipher_txt)
#plain_txt = dec(cipher_txt)
print('\nPlaintext:')
#print(plain_txt)
guess_padding(cipher_txt)

