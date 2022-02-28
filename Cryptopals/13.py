from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from binascii import hexlify,unhexlify
import base64

value = 'foo=bar&baz=qux&zap=zazzle'

def parsing(params):
	params_list = params.split('&')
	d = {}
	for i in params_list:
		l = i.split('=')
		a = l[0]
		b = l[1]
		d[a] = b
	return d

def profile_for(email):
	if '&' not in email and '=' not in email:
		d = {}
		d['email'] = email
		d['uid'] = 10
		d['role'] = 'user'
		return d
	else:
		raise ValueError("Invalid email")

def encodeToParam(dictionary):
	params = ''
	for key in dictionary:
		if params == '':
			params += key + '=' + str(dictionary[key])
		else:
			params += '&' + key + '=' + str(dictionary[key])
	return params

# key = get_random_bytes(16)
key = b'\xd7\x0e@ \x15\x9aG!\x88D7c\xcf\x8e\xf8\xa2'

def crypto(parameters):
	padded = pad(parameters,16)
	#print(padded)
	cipher = AES.new(key,AES.MODE_ECB)
	return cipher.encrypt(padded)

def decrypto(ciphertext):
	decipher = AES.new(key,AES.MODE_ECB)
	try:
		padded = decipher.decrypt(ciphertext)
		return unpad(padded,16)
	except Exception as e:
		return None #print('Error during decryption:\n' + str(e))
'''
email_addr = "foo@bar.com"
d = profile_for(email_addr)

params = encodeToParam(d)

cipher_text = crypto(params.encode())
print(b"Params before encryption: " + params.encode())
print('\n')
print(b"Params after encryption: " + cipher_text)
print('\n')

input_val = b'LQ\xb1\xb74Z\x8d\xadL\xa1 \xa1\xeaN\x82\x9f\xd5\xb7\xd8\x9fl$\xe9A\xe7%\xe4\xda3\xdc;\xaf\x0e\xfb\x86@\xc9\xb9\xa7\x02\xaa\xdf\xf3N\\\xa9\xc9X'

plain_text = decrypto(input_val)
print(b"Params after decryption: " + plain_text)
print('\n')
print(b"Parsed decrypted output: ")
print(parsing(plain_text.decode('utf-8')))
'''
def getBlockSize():
	lengths = []
	for i in range(256):
		to_encode = profile_for('a'*i)
		params = encodeToParam(to_encode)
		l = len(crypto(params.encode()))
		if l not in lengths:
			lengths.append(l)
	#print(lengths)
	diffs = []
	for j in range(len(lengths)):
		try:
			diffs.append(lengths[j+1]-lengths[j])
		except:
			break
	if len(set(diffs)) <=1:
		print(set(diffs).pop())
		

#getBlockSize()

to_encode = profile_for("foooo@bar.com")
params = encodeToParam(to_encode)
output = crypto(params.encode())
part1 = output[0:(len(output)-16)]

to_encode2 = profile_for("foooo@bar.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0bcom")
params2 = encodeToParam(to_encode2)
#print(params2)
output2 = crypto(params2.encode())
part2 = output2[16:32]
#print(output2)
cracked = part1+part2
print(cracked)
print(decrypto(cracked))
#print(decrypto(b'\xc7\xac\xe9\x18\x83-\x1dO\x02\xc94D\xba\x9b\x81\xb6\x0b\xfc*_tTH+\xa0^\x89\xa4Qm\xe1\x0f"D\x0e\xe2Gp\x94u/\xdel7\xad\xbe5>'))

'''
for i in range(256):
	guessed= unhexlify('{:02x}'.format(i))
	try:
		out = decrypto(b'LQ\xb1\xb74Z\x8d\xadL\xa1 \xa1\xeaN\x82\x9f\xd5\xb7\xd8\x9fl$\xe9A\xe7%\xe4\xda3\xdc;\xaf\x0e\xfb\x86@\xc9\xb9\xa7\x02\xaa\xdf\xf3N\\\xa9\xc9' + guessed)
		if out != None:		
			print(b"Success for character: " + guessed)
			print(out)
	except:
		pass
'''
