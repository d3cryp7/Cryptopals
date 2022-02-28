import base64
from binascii import hexlify,unhexlify

with open("6.txt","r") as f:
	b64encoded_file = f.read()

to_decode = b64encoded_file.replace("\n","")

b64decoded_file = base64.b64decode(to_decode)

keysize = list(range(2,41))

s1 = "this is a test".encode()
s2 = "wokka wokka!!!!".encode()

def getHammingDistance(s1,s2):
	if len(s1) == len(s2):
		x1 = hexlify(s1)
		x2 = hexlify(s2)
		#b1 = bin(int(x1,16))[2:]
		#b2 = bin(int(x2,16))[2:]
		int1 = int(x1,16)
		int2 = int(x2,16)
		dst = []
		xored = int1 ^ int2
		bined = bin(xored)[2:]
		#dst.append()
		for i in bined: #loop n store in a list
			dst.append(int(i))
		#	try:
		#		for i in range(0,len(b1)):
		#			dst.append(int(b1[i])^int(b2[i])) 
		#	except:
		#		print("b1 was: " + b1) 			
		#		print("b2 was: " + b2)
	else:
		print("lengths don't match, check you inputs!")
	return sum(dst)

#print(getHammingDistance(s1,s2))

def getKeySize(b64decoded_file):
	distances = []
	for k in keysize:
		chunks = []
		dist = []
		for i in range(0,len(b64decoded_file),k):
			chunks.append(b64decoded_file[i:i+k])
		#print("length of chunks is: " + str(len(chunks)) + " ............\n")
		present = True
		while present:
			if len(chunks) >= k:
				chunk1 = chunks[0]
				chunk2 = chunks[1]
			else:
				break
			if (len(chunk2) < k):
				break
			d = getHammingDistance(chunk1,chunk2)/k
			dist.append(d)
			del chunks[0],chunks[0]
			if len(chunks) == 0:
				present = False
			#dict = {"key_len" : k, "distance" : d}
		#distances.append(dict)
		average = sum(dist)/len(dist)
		dict = {"keylen":k,"distance":average}
		distances.append(dict)
	return (sorted(distances, key=lambda x:x['distance'])[0])

#keylen = getKeySize(b64decoded_file)
keylen = 29

def final_chunks(b64decoded_file,keylen):
	cipher_chunks = []
	for i in range(0,len(b64decoded_file),keylen):
		cipher_chunks.append(b64decoded_file[i:i+keylen])
	return cipher_chunks


def transpose(cipher_chunks,keylen):
	transposed = []
	for i in range(0,keylen):
		group = b''
		for chunk in cipher_chunks:
			try:
				group+=unhexlify(('{:02x}'.format(chunk[i]).encode()))
			except:
				pass
		transposed.append(group)
	return transposed

cipher_chunks = final_chunks(b64decoded_file,keylen)
transposed = transpose(cipher_chunks,keylen)

frequency = {}
frequency["a"] = 8.2/100
frequency["b"] = 1.5/100
frequency["c"] = 2.8/100
frequency["d"] = 4.3/100
frequency["e"] = 13/100
frequency["f"] = 2.2/100
frequency["g"] = 2/100
frequency["h"] = 6.1/100
frequency["i"] = 7/100
frequency["j"] = 0.15/100
frequency["k"] = 0.77/100
frequency["l"] = 4/100
frequency["m"] = 2.4/100
frequency["n"] = 6.7/100
frequency["o"] = 7.5/100
frequency["p"] = 1.9/100
frequency["q"] = 0.095/100
frequency["r"] = 6/100
frequency["s"] = 6.3/100
frequency["t"] = 9.1/100
frequency["u"] = 2.8/100
frequency["v"] = 0.98/100
frequency["w"] = 2.4/100
frequency["x"] = 0.15/100
frequency["y"] = 2/100
frequency["z"] = 0.074/100
frequency[" "] = 0.1
dict_list=[]

def do_xor(org):
	for i in range(0,128):
		dictionary = {}
		dictionary["byte"] = hex(i)
		dictionary["xored_string"] = bytewiseXor(org,i)
		dict_list.append(dictionary)

def bytewiseXor(string,byte):
	rets = b''
	for i in string:
		rets = rets + unhexlify('{:02x}'.format(i^byte))
	return(rets)

def score(hexstring):
	sum = 0
	xs = hexstring.decode('utf-8').lower()
	for i in xs:
		try:
			sum+=frequency[i]
		except:
			pass #print("cannot find the character")
	return(sum)

keys = b''

for org in transposed:
	dict_list=[]
	do_xor(org)
	for i in range(0,128):
		dict_list[i]["score"] = score(dict_list[i]["xored_string"])
		dict_list[i]["org_string"] = org
	key = unhexlify((sorted(dict_list, key = lambda i: i['score'], reverse = True)[0]['byte'][2:].encode()))
	keys+=key

#print(keys)

k = b'Terminator X: Bring the noise'



decrypted_primary= []

for chunk in cipher_chunks:
	list = []
	for i in range(0,len(chunk)):
		list.append(chunk[i]^k[i])
	decrypted_primary.append(list)

decrypted_secondary = []

for i in decrypted_primary:
	st = b''
	for j in i:
		st += ('{:02x}'.format(j)).encode()
	decrypted_secondary.append(st)

decrypted_final = b''

for i in decrypted_secondary:
	decrypted_final+=unhexlify(i)

#print(decrypted_final)

with open('6_solved.txt','wb') as f:
	f.write(decrypted_final)


