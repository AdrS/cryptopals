import aes, os, random, base64
from byte_frequency_ranking import ranking

def gen_key(length=16):
	'''generate random aes key'''
	return os.urandom(length)

#consistent key
key = gen_key()
secret =  base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

def encryption_oracle(m):
	'''returns AES-ECB(random prefix || m || secret || padding, key)'''
	randomPrefix = os.urandom(ord(os.urandom(1)))
	return aes.encrypt_ecb(randomPrefix + m + secret, key)

def get_pad_ct(pad_letter, oracle=encryption_oracle, block_size=16):
	#get aes(pad_letter*block_size)
	assert(len(pad_letter) == 1)

	c = oracle(pad_letter * (3*block_size))

	#because the prefix is random, the first equal blocks are almost
	#guarrenteed to be enc(pad_letter*block_size)
	blocks = aes.splitBlocks(c, block_size)

	i = 0
	while blocks[i] != blocks[i + 1]: i += 1
	return blocks[i]

def decrypt(oracle=encryption_oracle):
	block_size = 16
	#1) get enc(r || 3 blocks of as || secret || padding)
	#	find first pair of adjacent blocks that are equal =>
	#	the equal blocks are both: enc(aaa...a)
	cpa = get_pad_ct('a')

	#2) repeat previous step to find enc(bbb...b)
	cpb = get_pad_ct('b')

	known_prefix = ''
	while True:
		#while full message not known
		#3) want: enc( ..... known_prefix <next byte of secret> <block boundary> ....)

		pad_len = 2*block_size - len(known_prefix) % block_size  - 1
		assert(block_size <= pad_len)
		assert(pad_len < 2*block_size)

		#when <next byte of secret> is last byte of block
		#
		#c = enc(r || b*bloc_size a*pad_len secret || padding)
		#
		#has the blocks enc(b*block_size) || enc(a*block_size) next to each other

		#find lb = last block of ciphertext when <next secret byte is aligned>
		aligned = False
		while not aligned:
			c = oracle('b'*block_size + 'a'*pad_len)
			blocks = aes.splitBlocks(c, block_size)

			#check if next byte of secret is next to block boundary
			for i in range(len(blocks) - 1):
				if blocks[i] == cpb and blocks[i + 1] == cpa:
					#it is
					#soff = index last block - index of enc(a*block_size) + 1
					soff = len(blocks) - (i + 1)
					lb = blocks[-1]
					aligned = True
					break

		found = False
		for guess in ranking:
			#get c = enc(r || a*pad_len known_prefix guess a*pad_len secret || padding)
			#where guess is algined with byte boundary (this happends when c ends with lb
			while True:
				c = oracle('a'*pad_len + known_prefix + guess + 'a'*pad_len)
				if c.endswith(lb): break
				#~block_size requests
			blocks = aes.splitBlocks(c, block_size)

			#TODO: check these indicies (not correct ones)
			#blocks[-soff] = first block before secret
			#blocks[-soff - 1] = enc(end of known prefix guess)

			#offset from first block before secret to block with <next byte of secret
			coff = (pad_len + len(known_prefix) + 1)/block_size

			if blocks[-soff - 1] == blocks[-soff + coff - 1]:
				known_prefix += guess
				print known_prefix
				found = True
				break
		if not found: return known_prefix

if __name__ == '__main__':
	#test get_pad_ct
	assert(get_pad_ct('a') == aes.encrypt_ecb('a'*16, key)[:16])
	print decrypt()
