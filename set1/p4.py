from p3 import *

def read_strings(path='4.txt'):
	strs = []
	with open(path, 'r') as f:
		for l in f:
			strs.append(l.strip().decode('hex'))
	return strs

def detect_single_char_xor(strs, corpus_distr):
	return rank((crack_single_byte_xor(s, corpus_distr)[0] for s in strs), corpus_distr)

if __name__ == '__main__':
	pass
