# Convert hex to base64
# the string 
# 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
# should produce
# SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

#!/usr/bin/python3

import base64
from binascii import hexlify, unhexlify

input = input("Enter the string: ")

print("Base64 encoded output is %s" % base64.b64encode(unhexlify((input))))
