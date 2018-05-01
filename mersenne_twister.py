#see Wikipedia
#various constants
w, n, m, r = 32, 624, 397, 31
l, a = 18, 0x9908B0DF
u, d = 11, 0xFFFFFFFF
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
f = 1812433253
lower_mask = (1 << r) - 1
upper_mask = ~lower_mask

class MersenneTwister(object):
	def __init__(self, seed):
		self.index = n
		self.MT = [0]*n
		self.MT[0] = seed
		for i in range(1, n):
			self.MT[i] = f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (w - 2))) + i
			#only keep lowest 32 bits
			self.MT[i] &= 0xFFFFFFFF
	def extract_number(self):
		if self.index >= n:
			self.twist()
		y = self.MT[self.index]
		y = y ^ ((y >> u) & d)
		y = y ^ ((y << s) & b)
		y = y ^ ((y << t) & c)
		y = y ^ (y >> l)

		self.index += 1
		return y & 0xFFFFFFFF
	def twist(self):
		for i in range(n):
			x = (self.MT[i] & upper_mask) + (self.MT[(i + 1) % n] & lower_mask)
			xA = x >> 1
			if x % 2:
				xA = xA ^ a
			self.MT[i] = self.MT[(i + m) % n] ^ xA
		self.index = 0
