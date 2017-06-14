import os, struct
from mersenne_twister import * #MersenneTwister

def temper(y):
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)
	return y

def untemper(y):
	y ^= (y >> 18)
	y ^= ((y << 15) & 0xEFC60000)

	#this does not??

	###The next transformation is the hardest to invert

	#forward transform:
	#abcdefghijklmnopqrstuvwxyzABCDEF
	#left shift by 7
	#=>
	#hijklmnopqrstuvwxyzABCDEF0000000
	#and
	#10011101001011000101011010000000
	#=>
	#h00klm0o00r0tu000y0A0CD0F0000000
	#h    00 k   l     m   0 o   00 r   0 t    u   000 y   0 A   0 C    D   0 F   0000000
	#xor
	#a    bc d   e     f   g h   ij k   l m    n   opq r   s t   u v    w   x y   zABCDEF
	#=>
	#(a^h)bc(d^k)(e^l)(f^m)g(h^o)ij(k^r)l(m^t)(n^u)opq(r^y)s(t^A)u(v^C)(w^D)x(y^F)zABCDEF

	#reversing:
	#(a^h)bc(d^k)(e^l)(f^m)g(h^o)ij(k^r)l(m^t)(n^u)opq(r^y)s(t^A)u(v^C)(w^D)x(y^F)zABCDEF
	#xor
	#                                                          A 0   C    D 0   F
	#Note: A 0CD0 F000 0000 == (y << 7) & 1 0110 1000 0000 == (y << 7) & 1680
	#
	#==>
	#(a^h)bc(d^k)(e^l)(f^m)g(h^o)ij(k^r)l(m^t)(n^u)opq(r^y)stuvwxyzABCDEF

	y ^= ((y << 7) & 0x1680)

	#(a^h)bc(d^k)(e^l)(f^m)g(h^o)ij(k^r)l(m^t)(n^u)opq(r^y)stuvwxyzABCDEF
	#xor
	#                                       t    u 000   y
	#Note:  tu0 00y0 0000 0000 0000 == (y << 7) &  110 0010 0000 0000
	#Note:  tu00 0y00 0000 0000 0000 == (y << 7) &  1100 0100 0000 0000 0000 == (y << 7) & 0xc4000
	#==>
	#(a^h)bc(d^k)(e^l)(f^m)g(h^o)ij(k^r)lmnopqrstuvwxyzABCDEF
	y ^= ((y << 7) & 0xc4000)

	#(a^h)bc(d^k)(e^l)(f^m)g(h^o)ijklmnopqrstuvwxyzABCDEF
	#(a^h)bc(d^k)(e^l)(f^m)g(h^o)ij(k^r)lmnopqrstuvwxyzABCDEF
	#xor
	#               l    m 0   o 00   r
	#Note: lm0o 00r0 0000 0000 0000 0000 0000 == (y << 7) & 0xd20 0000
	#==>
	#(a^h)bc(d^k)efghijklmnopqrstuvwxyzABCDEF
	y ^= ((y << 7) & 0xd200000)

	#(a^h)bc(d^k)efghijklmnopqrstuvwxyzABCDEF
	#xor
	#   h 00   k
	#abcdefghijklmnopqrstuvwxyzABCDEF
	y ^= ((y << 7) & 0x90000000)

	#forward transform:
	#abcd efgh ijkl mnop qrst uvwx yzAB CDEF
	#shift right by 11
	#0000 0000 000a bcde fghi jklm nopq rstu
	# xor
	#=>
	#abcd efgh ijk(l^a) (m^b)(n^c)(o^d)(p^e) (q^f)(r^g)(s^h)(t^i) (u^j)(v^k)(w^l)(x^m) (y^n)(z^o)(A^p)(B^q) (C^r)(D^s)(E^t)(F^u)

	#reversing:
	#abcd efgh ijk(l^a) (m^b)(n^c)(o^d)(p^e) (q^f)(r^g)(s^h)(t^i) (u^j)(v^k)(w^l)(x^m) (y^n)(z^o)(A^p)(B^q) (C^r)(D^s)(E^t)(F^u)
	#xor
	#0000 0000 000   a     b    c    d    e     f    g    h     i    j    k    0    0  ...
	#
	#Note a bcde fghi jk00 0000 0000 == (y >> 11) & 0x01f fc00
	#==>
	#abcd efgh ijkl mnop qrst uv(w^l)(x^m) (y^n)(z^o)(A^p)(B^q) (C^r)(D^s)(E^t)(F^u)

	y ^= ((y >> 11) & 0x1ffc00)

	#abcd efgh ijkl mnop qrst uv(w^l)(x^m) (y^n)(z^o)(A^p)(B^q) (C^r)(D^s)(E^t)(F^u)
	#xor
	#0000 0000 0000 0000 0000 00   l    m     n    o    p    q     r    s    t    u
	#
	#note: l ... u == (y >> 11) & 0x3ff
	#y ^= ((y >> 11) & 0x3ff)
	y ^= ((y >> 11) & 0x3ff)
	return y

def recover_state(outputs):
	assert(len(outputs) == 624)
	return [untemper(o) for o in outputs]

def clone(outputs):
	assert(len(outputs) == 624)
	mt = MersenneTwister(0)
	#swap out state with state recovered from output
	mt.MT = recover_state(outputs)
	return mt

def rand32():
	return struct.unpack('!I', os.urandom(4))[0]

if __name__ == '__main__':
	mt = MersenneTwister(rand32())
	#clone generator from 624 output bytes
	mtCloned = clone([mt.extract_number() for _ in range(624)])

	assert(mt.MT == mtCloned.MT)
	for _ in range(1000):
		assert(mt.extract_number() == mtCloned.extract_number())
