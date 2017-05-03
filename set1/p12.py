import aes, os, random, base64
from byte_frequency_ranking import ranking

def gen_key(length=16):
	'''generate random aes key'''
	return os.urandom(length)

#consistent key
key = gen_key()
secret = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

def encryption_oracle(m):
	return aes.encrypt_ecb(m + secret, key)

def encryption_oracle_cbc(m):
	iv = os.urandom(16)
	return aes.encrypt_cbc(m + secret, key, iv)[16:]

def detect_block_size():
	'''determines block size of cipher oracle is using
	idea: becaues oracle is using a block cipher, the ciphertext length
	must be a multiple of the block size. We can keep encrypting longer
	messages until the ciphertext length increases. This increase will
	be the block size'''
	ct_blank = encryption_oracle('')
	i = 1
	while True:
		ct = encryption_oracle('a'*i)
		if len(ct) != len(ct_blank):
			return len(ct) - len(ct_blank)
		i = i + 1
	
def is_ecb_mode(block_size=16, oracle=encryption_oracle):
	'''distiguishes between CBC and ECB modes given encryption oracle access'''
	ct_blocks = aes.splitBlocks(oracle('a'*(2*block_size)), block_size)
	return ct_blocks[0] == ct_blocks[1]

def decrypt(oracle=encryption_oracle):
	block_size = detect_block_size()
	if not is_ecb_mode(block_size, oracle):
		raise Exception('Does not use ecb mode')

	#known secret prefix
	prefix = ''

	#idea: expand known prefix one byte at a time
	#length of:
	#'a'*(block_size - (len(prefix) % block_size) - 1) + prefix + guess_byte
	#is multiple of block size all but last byte is known
	#try each possible value of next byte. For correct guess, ct blocks match first blocks of:
	#'a'*(block_size - (len(prefix) % block_size) - 1) + secret

	while True:
		#determine next byte of secret
		pad_len = block_size - (len(prefix) % block_size) - 1
		found_next = False
		#try most common (ascii) bytes first to speed up search
		for guess in ranking:
			pt = 'a'*pad_len + prefix + guess + 'a'*pad_len
			ct_blocks = aes.splitBlocks(oracle(pt), block_size)
			i = (pad_len + len(prefix) + 1)/block_size
			if ct_blocks[i - 1] == ct_blocks[2*i - 1]:
				prefix += guess
				found_next = True
				print prefix
				break
		#Assume we are at end of secret when this occurs
		if not found_next:
			return prefix

def test_is_ecb_mode():
	assert(is_ecb_mode())
	assert(not is_ecb_mode(oracle=encryption_oracle_cbc))

if __name__ == '__main__':
	test_is_ecb_mode()
	print decrypt()
