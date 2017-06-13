import time
import os
import math
from mersenne_twister import *

def num_bits(n):
	b = 0
	while n:
		b += 1
		n >>= 1
	return b

def urandint(rmin, rmax):
	'''generate uniformly randomnumber in [rmin, rmax] using urandom'''
	diff = rmax - rmin

	#count number of bits of entropy needed
	bits = num_bits(diff)

	#generate numbers until one is in range [0, diff]
	while True:
		num = 0
		b = bits

		rand_bytes = os.urandom(int(math.ceil(bits/float(8))))
		i = 0
		#add random bits a byte at a time
		while b >= 8:
			num <<= 8
			num |= ord(rand_bytes[i])
			b -= 8
			i += 1
		if b > 0:
			num <<= b
			#only use the bits we need
			mask = (1<<b) - 1
			num |= ord(rand_bytes[i]) & mask
		if num <= diff: break

	return rmin + num

def get_output():
	#wait for a random amount of time
	time.sleep(urandint(40, 1000))
	seed = int(time.time())
	mt = MersenneTwister(seed)

	#wait for a random amount of time
	time.sleep(urandint(40, 1000))
	return mt.extract_number(), seed

def crack_seed(start_time, output):
	while True:
		mt = MersenneTwister(start_time)
		if mt.extract_number() == output:
			return start_time
		start_time += 1

def test_num_bits():
	assert(num_bits(0) == 0)
	assert(num_bits(1) == 1)
	assert(num_bits(2) == 2)
	assert(num_bits(3) == 2)
	assert(num_bits(4) == 3)

if __name__ == '__main__':
	output, real_seed = get_output()
	end_time = int(time.time())
	start_time = end_time - 2*1000
	print 'Lower bound on seeding time: ',  start_time
	print 'Got %d as output' % output
	print 'Cracking seed...'
	seed = crack_seed(start_time, output)
	print 'Found seed: ', seed
	print 'Actual seed: ', real_seed
