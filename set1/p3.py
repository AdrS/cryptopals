from p2 import *

def byte_freq(s):
	freq = [0]*256
	for c in s:
		freq[ord(c)] += 1
	freq = [float(f)/len(s) for f in freq]
	return freq

def compare_distributions(d1, d2):
	'''returns the sum of squared differences between the two distributions'''
	return sum([(a - b) ** 2 for a,b in zip(d1, d2)])

def possible_decryptions(ct):
	return [xor(ct, chr(b)*len(ct)) for b in range(256)]

def difference_score(pt, corpus_distr):
	freq = byte_freq(pt)
	return compare_distributions(freq, corpus_distr)

def rank(pts, corpus_distr):
	r = [(difference_score(pt, corpus_distr), pt) for pt in pts]
	r.sort(key=lambda x: x[0])
	return [p[1] for p in r]

def corpus_distr(path='hamlet.txt'):
	with open(path, 'r') as f:
		return byte_freq(f.read())

def crack_single_byte_xor(ct, corpus_distr):
	return rank(possible_decryptions(ct), corpus_distr)
