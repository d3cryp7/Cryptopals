from binascii import hexlify,unhexlify
import codecs
codecs.register_error("strict", codecs.ignore_errors)
#string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
string = "0e3647e8592d35514a081243582536ed3de6734059001e3f535ce6271032"
org = unhexlify(string)
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

def main():
	print("\n........Starting XOR..........\n")
	do_xor(org)
	print("\n........Calculating Score.........\n")
	for i in range(0,128):
		dict_list[i]["score"] = score(dict_list[i]["xored_string"])
	print("\n........Printing Score.........\n")
	print(sorted(dict_list, key = lambda i: i['score'], reverse = True)[0])

if __name__ == '__main__':
    main()
