import os, struct

def randomUint16():
	return struct.unpack("!H", os.urandom(2))[0]

def randomUint32():
	return struct.unpack("!I", os.urandom(4))[0]

def randomUint64():
	return struct.unpack("!Q", os.urandom(8))[0]

def xor(a, b):
	assert(len(a) == len(b))
	return ''.join([chr(ord(c) ^ ord(d)) for c, d in zip(a,b)])

def is_ascii(bs):
	for b in bs:
		if ord(b) >= 128:
			return False
	return True
