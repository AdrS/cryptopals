from util import *
from struct import pack, unpack

#based off of: https://static.aminer.org/pdf/PDF/000/120/420/the_md_message_digest_algorithm.pdf
#and rfc 1320

def get_padding(message_len):
	#pre process message length must be multiple of 64 bytes
	#last 8 bytes are original message length in bits
	#first padding byte is 0x80
	#rest are zeros
	pad_len = 64 - ((message_len + 1 + 8) % 64)
	return '\x80' + '\0'*pad_len + pack('<Q', 8*message_len)

def left_rotate32(x, n):
	'''rotates bits in i left by s places'''
	return (x >> (32 - n)) | int32(x << n)

def f(x,y,z): return (x & y) | ((~x) & z)
def g(x,y,z): return (x & y) | (x & z) | (y & z)
def h(x,y,z): return x ^ y ^ z

def r1(a,b,c,d,x,s): return left_rotate32(int32(a + f(b,c,d) + x), s)
def r2(a,b,c,d,x,s): return left_rotate32(int32(a + g(b,c,d) + x + 0x5a827999), s)
def r3(a,b,c,d,x,s): return left_rotate32(int32(a + h(b,c,d) + x + 0x6ed9eba1), s)

class MD4:
	def __init__(self, state = None, ml = 0):
		if state:
			assert(len(state) == 16)
			assert(ml % 64 == 0)
			self.a, self.b, self.c, self.d = unpack('<4I', state)
		else:
			self.a = 0x67452301
			self.b = 0xefcdab89
			self.c = 0x98badcfe
			self.d = 0x10325476

		self.ml = ml
		self.data = ''

	def add(self, new_data):
		self.ml += len(new_data)
		self.data += new_data

		#for each 512 bit chunk of message
		while len(self.data) >= 64:
			#split chunk into 16 32-bit bit endian words
			x = unpack("<16I", self.data[:64])
			self.data = self.data[64:]

			a, b, c, d = self.a, self.b, self.c, self.d

			a = r1(a,b,c,d, x[0], 3)
			d = r1(d,a,b,c, x[1], 7)
			c = r1(c,d,a,b, x[2],11)
			b = r1(b,c,d,a, x[3],19)
			a = r1(a,b,c,d, x[4], 3)
			d = r1(d,a,b,c, x[5], 7)
			c = r1(c,d,a,b, x[6],11)
			b = r1(b,c,d,a, x[7],19)
			a = r1(a,b,c,d, x[8], 3)
			d = r1(d,a,b,c, x[9], 7)
			c = r1(c,d,a,b,x[10],11)
			b = r1(b,c,d,a,x[11],19)
			a = r1(a,b,c,d,x[12], 3)
			d = r1(d,a,b,c,x[13], 7)
			c = r1(c,d,a,b,x[14],11)
			b = r1(b,c,d,a,x[15],19)

			a = r2(a,b,c,d, x[0], 3)
			d = r2(d,a,b,c, x[4], 5)
			c = r2(c,d,a,b, x[8], 9)
			b = r2(b,c,d,a,x[12],13)
			a = r2(a,b,c,d, x[1], 3)
			d = r2(d,a,b,c, x[5], 5)
			c = r2(c,d,a,b, x[9], 9)
			b = r2(b,c,d,a,x[13],13)
			a = r2(a,b,c,d, x[2], 3)
			d = r2(d,a,b,c, x[6], 5)
			c = r2(c,d,a,b,x[10], 9)
			b = r2(b,c,d,a,x[14],13)
			a = r2(a,b,c,d, x[3], 3)
			d = r2(d,a,b,c, x[7], 5)
			c = r2(c,d,a,b,x[11], 9)
			b = r2(b,c,d,a,x[15],13)

			a = r3(a,b,c,d, x[0], 3)
			d = r3(d,a,b,c, x[8], 9)
			c = r3(c,d,a,b, x[4],11)
			b = r3(b,c,d,a,x[12],15)
			a = r3(a,b,c,d, x[2], 3)
			d = r3(d,a,b,c,x[10], 9)
			c = r3(c,d,a,b, x[6],11)
			b = r3(b,c,d,a,x[14],15)
			a = r3(a,b,c,d, x[1], 3)
			d = r3(d,a,b,c, x[9], 9)
			c = r3(c,d,a,b, x[5],11)
			b = r3(b,c,d,a,x[13],15)
			a = r3(a,b,c,d, x[3], 3)
			d = r3(d,a,b,c,x[11], 9)
			c = r3(c,d,a,b, x[7],11)
			b = r3(b,c,d,a,x[15],15)

			self.a = int32(self.a + a)
			self.b = int32(self.b + b) 
			self.c = int32(self.c + c)
			self.d = int32(self.d + d)

	def digest(self):
		self.add(get_padding(self.ml))
		assert(not self.data)
		assert(self.ml % 64 == 0)
		d = pack('<4I', self.a, self.b, self.c, self.d)
		self.__init__()
		return d

def md4(message):
	m = MD4()
	m.add(message)
	return m.digest()

def test_md4():
	#test vectors from: https://en.wikipedia.org/wiki/MD4
	assert(md4("") == '31d6cfe0d16ae931b73c59d7e0c089c0'.decode('hex'))
	assert(md4("a") == 'bde52cb31de33e46245e05fbdbd6fb24'.decode('hex'))
	assert(md4("abc") == 'a448017aaf21d8525fc10ae87aa6729d'.decode('hex'))
	assert(md4("message digest") == 'd9130a8164549fe818874806e1c7014b'.decode('hex'))
	assert(md4("abcdefghijklmnopqrstuvwxyz") == 'd79e1c308aa5bbcdeea8ed63df412da9'.decode('hex'))
	assert(md4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == '043f8582f241db351ce627e153e7f0e4'.decode('hex'))
	assert(md4("12345678901234567890123456789012345678901234567890123456789012345678901234567890") == 'e33b4ddc9c38f2199c3e7b164fcc0536'.decode('hex'))

if __name__ == '__main__':
	test_md4()
