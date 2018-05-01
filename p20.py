import base64
import os
import aes
import p3 #crack single byte xor

def load_pts(path='20.txt'):
	pts = []
	with open(path,'r') as f:
		for line in f:
			pts.append(base64.b64decode(line.strip()))
	return pts

def get_cts(pts):
	'''encrypts plain texts with the same key and the fixed nonce 0'''
	key = os.urandom(16)
	return [aes.encrypt_ctr(pt, key, 0) for pt in pts]

def find_key(cts):
	#sort by length
	cts = sorted(cts, key=lambda x: -len(x))

	key_len = len(cts[0])
	key_stream = []

	eng_freq = p3.corpus_distr() #'/mnt/c/Users/adrian/Downloads/datasets/cornell movie-dialogs corpus/PLAIN_TEXT_MOVIE_CONVERSATIONS.txt')

	for i in range(key_len):
		#get bytes encrypted with same byte of key stream
		cur_bytes = ''.join([c[i] for c in [ct for ct in cts if len(ct) > i]])
		ranking = p3.crack_single_byte_xor(cur_bytes, eng_freq)
		best = ranking[0]

		#find key stream byte for best candidate plain text byte
		k = chr(ord(best[0]) ^ ord(cts[0][i]))
		key_stream.append(k)
	return ''.join(key_stream)

def crack_reused_keystream(cts):
	key = find_key(cts)
	for ct in cts:
		print ''.join(aes.xor(ct, key))

if __name__ == '__main__':
	#note first letters of each decryption are messed up because frequency
	#distribution for first letter of a sentence is skewed towards uppercase
	cts = get_cts(load_pts())
	crack_reused_keystream(cts)
