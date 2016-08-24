def hexchar_to_int(c):
	if '0' <= c and c <= '9': return ord(c) - ord('0')
	if 'a' <= c and c <= 'f': return 10 + ord(c) - ord('a')
	if 'A' <= c and c <= 'F': return 10 + ord(c) - ord('A')
	raise ValueError("not a valid hex character")

def int_to_hexchar(n):
	if n < 0 or n > 15: raise ValueError("int must be in range 0-15")
	if n < 10: return chr(ord('0') + n)
	return chr(ord('A') + n - 10)

def byte_to_hex(b):
	b = ord(b)
	return int_to_hexchar(b >> 4) + int_to_hexchar(b & 0xF)

def str_to_hex(s):
	return ''.join([byte_to_hex(b) for b in s])

def hex_to_str(hs):
	if len(hs) % 2 != 0: raise ValueError("hex string must have even length")
	bs = []
	for i in range(0,len(hs),2):
		bs.append(chr((hexchar_to_int(hs[i]) << 4) + hexchar_to_int(hs[i + 1])))
	return ''.join(bs)

def b64char_to_int(b):
	if 'A' <= b <= 'Z': return ord(b) - ord('A')
	if 'a' <= b <= 'z': return ord(b) - ord('a') + 26
	if '0' <= b <= '9': return ord(b) - ord('0') + 52
	if b == '+': return 62
	if b == '/': return 63
	raise ValueError("invalid base64 character")

def int_to_b64char(b):
	if b < 0 or b > 63: raise ValueError("int must be in range 0-63")
	if b < 26: return chr(b + ord('A'))
	if b < 52: return chr(b - 26 + ord('a'))
	if b < 62: return chr(b - 52 + ord('0'))
	if b == 62: return '+'
	return '/'

def str_to_b64(s):
	#pad string with 0 bytes until length is multiple of 3
	pad = (3 - len(s) % 3) % 3
	s += '\x00'*pad
	bs = []
	bits = 0
	val = 0
	for b in s:
		val = (val << 8) + ord(b)
		bits += 8
		while bits >= 6:
			bits -= 6
			bs.append(int_to_b64char(val >> bits))
			val %= (2 ** bits)
	bs = bs[0: len(bs) - pad]
	bs.append('='*pad)
	return ''.join(bs)

def b64_to_str(bs):
	if len(bs) % 3: raise ValueError("base64 string must have length divisible by 3")
	if not bs: return ''
	#count padding amount
	pad = 0
	if bs[-1] == '=':
		ba[-1] = 'A'
		if bs[-2] == '=':
			pad = 2
			ba[-2] = 'A'
		else:
			pad = 1
	s = []
	cur = 0
	bits = 0
	for c in bs:
		cur = (cur << 6) + b64char_to_int(c)
		bits += 6
		if bits >= 8:
			bits -= 8
			s.append(chr(cur >> bits))
			cur %= (1 << bits)
	#remove pad
	s = s[0: len(s) - pad]
	return ''.join(s)
			
def hex_to_b64(hs):
	return str_to_b64(hex_to_str(hs))

def b64_to_hex(bs):
	return str_to_hex(b64_to_str(bs))

def test_hexchar_to_int():
	assert(hexchar_to_int('A') == 10)
	assert(hexchar_to_int('a') == 10)
	assert(hexchar_to_int('F') == 15)
	assert(hexchar_to_int('f') == 15)
	assert(hexchar_to_int('0') == 0)
	try:
		hexchar_to_int('g')
		assert(False)
	except ValueError: pass

def test_int_to_hexchar():
	assert(int_to_hexchar(0) == '0')
	assert(int_to_hexchar(15) == 'F')
	try:
		int_to_hexchar(16)
		assert(False)
	except ValueError: pass

def test_byte_to_hex():
	assert(byte_to_hex('\x02') == '02')
	assert(byte_to_hex('\xf2') == 'F2')

def test_str_to_hex():
	assert(str_to_hex('\x00\x01\xff\xfe') == '0001FFFE')

def test_hex_to_str():
	assert(hex_to_str('afbe901A') == '\xaf\xbe\x90\x1a')
	try:
		hex_to_str('FFF')
		assert(False)
	except ValueError: pass

def test_hex_str_sanity():
	for i in range(255):
		for j in range(255):
			s = chr(i) + chr(j)
			assert(hex_to_str(str_to_hex(s)) == s)

def test_b64_int_conversion():
	for i in range(64):
		assert(b64char_to_int(int_to_b64char(i)) == i)
	try:
		b64char_to_int('*')
		assert(False)
	except ValueError: pass
	try:
		int_to_b64char(64)
		assert(False)
	except ValueError: pass

def test_str_to_b64():
	assert(str_to_b64('') == '')
	#test vectors from wikipedia
	assert(str_to_b64('any carnal pleasure.') == 'YW55IGNhcm5hbCBwbGVhc3VyZS4=')
	assert(str_to_b64('any carnal pleasure') == 'YW55IGNhcm5hbCBwbGVhc3VyZQ==')
	assert(str_to_b64('any carnal pleasur') == 'YW55IGNhcm5hbCBwbGVhc3Vy')

def test_b64_to_str():
	assert(b64_to_str('YW55IGNhcm5hbCBwbGVhc3VyZS4=') == 'any carnal pleasure.')
	assert(b64_to_str('YW55IGNhcm5hbCBwbGVhc3VyZQ==') == 'any carnal pleasure')
	assert(b64_to_str('YW55IGNhcm5hbCBwbGVhc3Vy') == 'any carnal pleasur')
	assert(b64_to_str('') == '')

	try:
		b64_to_str('a')
		assert(False)
	except ValueError: pass
	try:
		b64_to_str('a+')
		assert(False)
	except ValueError: pass

	try:
		b64_to_str('a+Fhh^a==')
		assert(False)
	except ValueError: pass

if __name__ == "__main__":
	test_hexchar_to_int()
	test_int_to_hexchar()
	test_byte_to_hex()
	test_str_to_hex()
	test_hex_to_str()
	test_hex_str_sanity()
	test_b64_int_conversion()
	test_str_to_b64()
