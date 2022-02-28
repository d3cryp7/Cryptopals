from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad #,pad
import base64
from binascii import hexlify,unhexlify

IV = b'\x00' * 16
key = b'YELLOW SUBMARINE'

'''
with open('10.txt','r') as f:
	file = f.read()

file = file.replace("\n","")
decoded = base64.b64decoded(file)
'''

def pad(string,size):
        strlen = len(string)
        if size == strlen:
                return string
        num = size-(strlen%size)
        pad = unhexlify('{:02x}'.format(num)) * num
        return string+pad

def decrypto(key,IV,cryptData):
	decipher = AES.new(key,AES.MODE_CBC,IV)
	data = unpad(decipher.decrypt(cryptData),16)
	return data

def encrypto(key,IV,data):
	padded = pad(data,16)
	cipher = AES.new(key,AES.MODE_CBC,IV)
	cryptData = cipher.encrypt(padded)
	return cryptData

def custom_enc(xored):
        cipher = AES.new(key,AES.MODE_ECB)
        data = cipher.encrypt(xored)
        return data

def do_xor(chunk,previous_enc_block):
	xored = b''
	if len(chunk)!=len(previous_enc_block):
		raise ValueError("Input lengths for XOR funcion don't match")
	for i in range(len(chunk)):
		xored+=unhexlify('{:02x}'.format(chunk[i]^previous_enc_block[i]))
	return xored

def do_chunks(data):
	padded = pad(data,16)
	plain_chunks = []
	for i in range(0,len(padded),16):
		plain_chunks.append(padded[i:i+16])
	return plain_chunks

def do_custom_enc(plain_chunks):
	enc_value = b""
	prev_enc_block = IV
	for i in range(len(plain_chunks)):
		xored = do_xor(plain_chunks[i],prev_enc_block)
		enced = custom_enc(xored)
		enc_value += enced
		prev_enc_block = enced
	return enc_value


#string = input("Enter string to encrypt: ")
string = "Hello how are you doing"

plain_chunks = do_chunks(string.encode())
enc_value = do_custom_enc(plain_chunks)

print(enc_value)

'''
cryptData = encrypto(key,IV,string.encode())

print(cryptData)

print("\ndecrypted.........")

data = decrypto(key,IV,cryptData)

print(data)
'''


