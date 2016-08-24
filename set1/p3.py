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

def english_score(text, engl_distr):
	freq = byte_freq(text)
	return compare_distributions(freq, engl_distr)

def crack_single_byte_xor(ct):
	with open('hamlet.txt', 'r') as f:
		engl_distr = byte_freq(f.read())
	pos = []
	for b in range(256):
		pt = xor(ct, chr(b) * len(ct))
		diff = english_score(pt, engl_distr)
		pos.append((diff, pt))
	pos.sort(key=lambda x: x[0])
	return [p[1] for p in pos]

