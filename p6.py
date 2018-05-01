import base64
from p3 import *
from p5 import *

def hamming_distance(s1, s2):
	assert(len(s1) == len(s2))
	hd = 0
	for c1, c2 in zip(s1, s2):
		b = ord(c1) ^ ord(c2)
		#1 bits of b corrispond to the differeing bits in c1 and c2
		while b:
			if b & 1: hd += 1
			b >>= 1
	return hd

def load_b64_file(path='6.txt'):
	with open(path, 'r') as f:
		data = f.read()
		return base64.b64decode(''.join(data.split()))

def ith_block(text, block_size, i):
	return text[block_size * i: block_size * (i + 1)]

def get_key_size(text, maxks = 40):
	assert(len(text) >= maxks * 4)
	hds = []
	for ks in range(2, maxks + 1):
		hd = hamming_distance(ith_block(text, ks, 0), ith_block(text, ks, 1))
		hd += hamming_distance(ith_block(text, ks, 1), ith_block(text, ks, 2))
		hds.append((ks, float(hd)/ks)) #store normalized distances
	hds.sort(key=lambda x: x[1]) #rank by smallest distance
	return [i[0] for i in hds]

def group_by_index(text, key_size):
	'''puts characters in text into groups based and congruence of index modulo key_size'''
	groups = []
	for i in range(key_size):
		group = [text[j] for j in range(i, len(text), key_size)]
		groups.append(''.join(group))
	return groups

def break_for(text, key_size, corpus):
	groups = group_by_index(text, key_size)
	key = []
	#for each group, treat group as single character xor
	for g in groups:
		gpt = crack_single_byte_xor(g, corpus)[0]
		key.append(chr(ord(gpt[0]) ^ ord(g[0])))
	return ''.join(key)

def break_repeating_key_xor(text, maxks=40, numks=10):
	ks = get_key_size(text, maxks) #get ranking of possible key sizes
	
	corpus =  corpus_distr()
	res = []
	for i in range(numks):
		key = break_for(text,ks[i], corpus)
		pt = repeating_xor(text, key)
		score = difference_score(pt, corpus)
		res.append((key, pt, score))
	res.sort(key=lambda x: x[2])
	return res
		
def test_hamming_distance():
	assert(hamming_distance("this is a test", "wokka wokka!!!") == 37)
	assert(hamming_distance("yolo", "yolo") == 0)
	assert(hamming_distance('\xff\x00\xf0','\xff\xff\xff') == 12)

def test_ith_block():
	assert(ith_block('abcdABCDefghasfd', 4, 0) == 'abcd')
	assert(ith_block('abcdABCDefghasdfd', 4, 1) == 'ABCD')

def test_group_by_index():
	assert(group_by_index('hello', 1) == ['hello'])
	assert(group_by_index('hello', 7) == ['h','e','l','l','o','',''])
	assert(group_by_index('hello', 2) == ['hlo','el'])

if __name__ == "__main__":
	test_hamming_distance()
	test_ith_block()
	test_group_by_index()
