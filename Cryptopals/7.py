from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
import base64

with open("7.txt","rb") as f:
	enc_file = f.read()

decoded = base64.b64decode(enc_file)
k = b'YELLOW SUBMARINE'
cipher = AES.new(k,AES.MODE_ECB)
data = cipher.decrypt(decoded)
print(data)
