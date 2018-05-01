def xor(a, b):
	assert(len(a) == len(b))
	return ''.join([chr(ord(c) ^ ord(d)) for c, d in zip(a,b)])

if __name__ == '__main__':
	assert(xor('1c0111001f010100061a024b53535009181c'.decode('hex'),
		'686974207468652062756c6c277320657965'.decode('hex')).encode('hex') ==\
		'746865206b696420646f6e277420706c6179')
