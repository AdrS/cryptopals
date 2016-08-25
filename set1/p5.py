import math
from p2 import *
def repeating_xor(pt, key):
	#note this is basically a vignere cipher
	#use detect single char xor to find key length
	expanded = key * int(math.ceil(float(len(pt))/len(key)))
	return xor(pt, expanded[:len(pt)])

if __name__ == "__main__":
	pt = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key = "ICE"
	ct = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".decode('hex')
	assert(repeating_xor(pt, key) == ct)
