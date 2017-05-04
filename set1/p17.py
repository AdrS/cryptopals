import aes, base64, os, random
from byte_frequency_ranking import ranking

key = os.urandom(16)
pts = [
	'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
	'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
	'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
	'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
	'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
	'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
	'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
	'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
	'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
	'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
]
pts = [base64.b64decode(pt) for pt in pts]

def get_ciphertext():
	iv = os.urandom(16)
	return aes.encrypt_cbc(random.choice(pts), key, iv)

def valid_padding(ct):
	try:
		aes.decrypt_cbc(ct, key)
	except aes.InvalidPadding:
		return False
	return True

def xor_tail(s, tail):
	'''xors the end of s with tail'''
	return ''.join(aes.xor(s, '\x00'*(len(s) - len(tail)) + tail))

def decrypt_ciphertext(ct):
	ct_blocks = aes.splitBlocks(ct)
	pt_blocks = []
	#for each block (except iv)
	for i in range(1,len(ct_blocks)):
		#Consider the first i blocks:
		#iv || c1,1 c1,2 c1,3 ... c1,16 || ... || ci,1 ci,2 ... ci,16
		suffix = ''
		#determine bytes in ith block working backward
		for _ in range(16):
			#try guessing each possible byte value
			found = False
			for g in ranking:
				#setting:
				#c'_{i - 1} = c_{i - 1} xor 00..0 || guess|| suffix
				#causes c_i to decrypt to:
				#m_i xor 00..0 || guess|| suffix = m_i1 ...x00000
				#	where x = 0 iff the guess is correct
				#slen = len(suffix)
				#t1 = '\x00'*(15 - slen) + g + suffix
				#t2 = '\x00'*(15 - slen) + chr(slen + 1)*(slen + 1)
				#setting:
				#c'_{i - 1} = c_{i - 1} xor t1 xor t2
				#causes c_i to decrypt to
				#m_i xor t1 xor t2
				#mi,1 mi,2 .. ((mi,k xor guess) xor (slen + 1)) 
				#which has valid padding if the guess is correct
				cp = xor_tail(ct_blocks[i - 1], g + suffix)
				cp = xor_tail(cp, chr(len(suffix) + 1)*(len(suffix) + 1))
				ct = ct_blocks[:i - 1]
				ct.append(cp)
				ct.append(ct_blocks[i])
				if valid_padding(''.join(ct)):
					suffix = g + suffix
					found = True
					break
			if not found:
				raise Exception("could not find value of byte")
		pt_blocks.append(suffix)
	return aes.remove_pkcs7_padding(''.join(pt_blocks))

def get_plaintext():
	return decrypt_ciphertext(get_ciphertext())
