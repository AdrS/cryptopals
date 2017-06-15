from util import *
from struct import pack, unpack

#source: Wikipedia
def get_padding(message_len):
	#pre process message length must be multiple of 64 bytes
	#last 8 bytes are original message length in bits
	#first padding byte is 0x80
	#rest are zeros
	pad_len = 64 - ((message_len + 1 + 8) % 64)
	return '\x80' + '\0'*pad_len + pack('>Q', 8*message_len)

def left_rotate32(i, s):
	'''rotates bits in i left by s places'''
	return (i >> (32 - s)) | int32(i << s)

class Sha1:
	def __init__(self, state = None, ml = 0):
		if state:
			assert(len(state) == 20)
			assert(ml % 64 == 0)
			h0, h1, h2, h3, h4 = unpack('>5I', state)
			self.h0, self.h1, self.h2, self.h3, self.h4 = h0, h1, h2, h3, h4
		else:
			self.h0 = 0x67452301
			self.h1 = 0xEFCDAB89
			self.h2 = 0x98BADCFE
			self.h3 = 0x10325476
			self.h4 = 0xC3D2E1F0

		self.ml = ml
		self.data = ''

	def add(self, new_data):
		self.ml += len(new_data)
		self.data += new_data

		#for each 512 bit chunk of message
		while len(self.data) >= 64:
			#split chunk into 16 32-bit bit endian words
			w = list(unpack(">16I", self.data[:64]))
			self.data = self.data[64:]

			for i in range(16, 80):
				tmp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
				w.append(left_rotate32(tmp, 1))

			a, b, c, d, e = self.h0, self.h1, self.h2, self.h3, self.h4

			for i in range(80):
				if i < 20:
					f = (b & c) | ((~b) & d)
					k = 0x5A827999
				elif i < 40:
					f = b ^ c ^ d
					k = 0x6ED9EBA1
				elif i < 60:
					f = (b & c) | (b & d) | (c & d)
					k = 0x8F1BBCDC
				else:
					f = b ^ c ^ d
					k = 0xCA62C1D6
				tmp = int32((left_rotate32(a, 5) + f + e + k + w[i]))
				e = d
				d = c
				c = left_rotate32(b, 30)
				b = a
				a = tmp

			self.h0 = int32(self.h0 + a)
			self.h1 = int32(self.h1 + b) 
			self.h2 = int32(self.h2 + c)
			self.h3 = int32(self.h3 + d)
			self.h4 = int32(self.h4 + e)

	def digest(self):
		self.add(get_padding(self.ml))
		assert(not self.data)
		assert(self.ml % 64 == 0)
		d = pack('>5I', self.h0, self.h1, self.h2, self.h3, self.h4)
		self.__init__()
		return d

def test_left_rotate():
	for i in range(0, 100, 7):
		assert(left_rotate32(i, 0) == i)
	assert(left_rotate32(0xabcdef01, 4) == 0xbcdef01a)
	assert(left_rotate32(0xabcdef01, 8) == 0xcdef01ab)
	assert(left_rotate32(0xabcdef01, 12) == 0xdef01abc)
	assert(left_rotate32(0xabcdef01, 16) == 0xef01abcd)

def test_sha():
	#test vectors from https://www.di-mgt.com.au/sha_testvectors.html
	s = Sha1()
	h = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'.decode('hex')
	assert(s.digest() == h)

	s = Sha1()
	s.add('abc')
	h = 'a9993e364706816aba3e25717850c26c9cd0d89d'.decode('hex')
	assert(s.digest() == h)

	s = Sha1()
	s.add("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
	h = '84983e441c3bd26ebaae4aa1f95129e5e54670f1'.decode('hex')
	assert(s.digest() == h)
	
	s = Sha1()
	s.add("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
	h = 'a49b2446a02c645bf419f995b67091253a04a259'.decode('hex')
	assert(s.digest() == h)

	s = Sha1()
	s.add('a'*1000000)
	h = '34aa973cd4c4daa4f61eeb2bdbad27316534016f'.decode('hex')
	assert(s.digest() == h)

if __name__ == '__main__':
	test_left_rotate()
	test_sha()
