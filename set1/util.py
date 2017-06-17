import os, struct
import hashlib

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

def split(data, chunk_size):
	num_chunks = len(data)/chunk_size
	return [data[chunk_size*i: chunk_size*(i + 1)] for i in range(num_chunks)]

def int32(i):
	return 0xffffffff & i

def bigint_to_bytes(i):
	hex_string = '%x' % i
	#TODO: make this less hacky
	if len(hex_string) % 2:
		hex_string = '0' + hex_string
	return hex_string.decode('hex')

def bytes_to_bigint(b):
	return int(b.encode('hex'), 16)

def sha1sum(m):
	return hashlib.sha1(m).digest()
