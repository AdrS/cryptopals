import random

def pkcs1_pad(m, mod_len):
	'''pad m according to PKCS1 so that it's same length as modulus'''
	pad_len = mod_len - len(m) - 3
	assert(pad_len >= 8)

	#padding starts with 00 02
	parts = ['\x00\x02']

	#all remaining padding (except last byte) is random nonzero bytes
	rand = random.SystemRandom()
	parts.extend([chr(rand.randrange(1, 256)) for _ in range(pad_len)])

	#padding ends with 00
	parts.append('\x00')
	parts.append(m)

	padded = ''.join(parts)
	assert(len(padded) == mod_len)

	return padded

def pkcs1_unpad(m, mod_len):
	'''removes padding returns none if padding is invalid'''
	if len(m) != mod_len: return
	if m[0] != '\x00' or m[1] != '\x02': return

	#first nonzero byte (after 00 02) marks end of padding
	i = 2
	while i < len(m) and m[i] != '\x00':
		i += 1

	#check that 00 byte was actually found
	if i >= len(m): return

	pad_len = i - 2
	#must have at least 8 bytes of random padding
	if pad_len < 8: return

	return m[3 + pad_len:]

def test_pkcs1_unpad():
	#wrong length
	assert(not pkcs1_unpad('\x00\x0212345678\x00m', 13))

	#wrong prefix
	assert(not pkcs1_unpad('\x02\x0212345678\x00m', 12))

	# < 8 bytes of random padding
	assert(not pkcs1_unpad('\x00\x021234567\x00mm', 12))

	#no end of padding byte
	assert(not pkcs1_unpad('\x00\x0212345678pp', 12))

	#empty message
	assert(pkcs1_unpad('\x00\x0212345678p\x00', 12) == '')

	# > 8 bytes of random padding
	assert(pkcs1_unpad('\x00\x0212345678ppppppp\x00mm', 20) == 'mm')

def sanity_test():
	for m in ('we', 'all', 'live', 'yellow', 'beatles'):
		for mod_len in [18, 32, 64, 128]:
			assert(pkcs1_unpad(pkcs1_pad(m, mod_len), mod_len) == m)

if __name__ == '__main__':
	test_pkcs1_unpad()
	sanity_test()
