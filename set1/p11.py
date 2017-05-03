import aes, os, random

def gen_key(length=16):
	'''generate random aes key'''
	return os.urandom(length)

def encryption_oracle(m):
	key = gen_key()
	prefix = os.urandom(random.randint(5,10))
	suffix = os.urandom(random.randint(5,10))

	pt = prefix + m + suffix
	
	#use ECB half the time and CBC the other half
	if ord(os.urandom(1)) % 2:
		print 'ECB'
		return aes.encrypt_ecb(pt, key)
	else:
		print 'CBC'
		iv = os.urandom(16)
		#don't return iv (otherwise length will give difference away
		return aes.encrypt_cbc(pt, key, iv)[16:]

def detect_mode():
	'''distiguishes between CBC and ECB modes given encryption oracle access'''
	pt = 'a'*(11 + 11 + 32)
	ct_blocks = aes.splitBlocks(encryption_oracle(pt))
	if ct_blocks[1] == ct_blocks[2]:
		print 'ECB'
	else:
		print 'probably CBC'
