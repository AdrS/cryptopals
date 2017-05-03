
#lookup tables from wikipedia, based off of FIPS pseudocode http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

def numRounds(key_len):
	'''returns number of rounds for given key length'''
	return 10 + ((key_len - 16) >> 2)

def subBytes(state):
	#TODO: make lookup tables consitant (either all bytes or all ints)
	lookup_table = [
		'\x63', '\x7c', '\x77', '\x7b', '\xf2', '\x6b', '\x6f', '\xc5', '\x30', '\x01', '\x67', '\x2b', '\xfe', '\xd7', '\xab', '\x76',
		'\xca', '\x82', '\xc9', '\x7d', '\xfa', '\x59', '\x47', '\xf0', '\xad', '\xd4', '\xa2', '\xaf', '\x9c', '\xa4', '\x72', '\xc0',
		'\xb7', '\xfd', '\x93', '\x26', '\x36', '\x3f', '\xf7', '\xcc', '\x34', '\xa5', '\xe5', '\xf1', '\x71', '\xd8', '\x31', '\x15',
		'\x04', '\xc7', '\x23', '\xc3', '\x18', '\x96', '\x05', '\x9a', '\x07', '\x12', '\x80', '\xe2', '\xeb', '\x27', '\xb2', '\x75',
		'\x09', '\x83', '\x2c', '\x1a', '\x1b', '\x6e', '\x5a', '\xa0', '\x52', '\x3b', '\xd6', '\xb3', '\x29', '\xe3', '\x2f', '\x84',
		'\x53', '\xd1', '\x00', '\xed', '\x20', '\xfc', '\xb1', '\x5b', '\x6a', '\xcb', '\xbe', '\x39', '\x4a', '\x4c', '\x58', '\xcf',
		'\xd0', '\xef', '\xaa', '\xfb', '\x43', '\x4d', '\x33', '\x85', '\x45', '\xf9', '\x02', '\x7f', '\x50', '\x3c', '\x9f', '\xa8',
		'\x51', '\xa3', '\x40', '\x8f', '\x92', '\x9d', '\x38', '\xf5', '\xbc', '\xb6', '\xda', '\x21', '\x10', '\xff', '\xf3', '\xd2',
		'\xcd', '\x0c', '\x13', '\xec', '\x5f', '\x97', '\x44', '\x17', '\xc4', '\xa7', '\x7e', '\x3d', '\x64', '\x5d', '\x19', '\x73',
		'\x60', '\x81', '\x4f', '\xdc', '\x22', '\x2a', '\x90', '\x88', '\x46', '\xee', '\xb8', '\x14', '\xde', '\x5e', '\x0b', '\xdb',
		'\xe0', '\x32', '\x3a', '\x0a', '\x49', '\x06', '\x24', '\x5c', '\xc2', '\xd3', '\xac', '\x62', '\x91', '\x95', '\xe4', '\x79',
		'\xe7', '\xc8', '\x37', '\x6d', '\x8d', '\xd5', '\x4e', '\xa9', '\x6c', '\x56', '\xf4', '\xea', '\x65', '\x7a', '\xae', '\x08',
		'\xba', '\x78', '\x25', '\x2e', '\x1c', '\xa6', '\xb4', '\xc6', '\xe8', '\xdd', '\x74', '\x1f', '\x4b', '\xbd', '\x8b', '\x8a',
		'\x70', '\x3e', '\xb5', '\x66', '\x48', '\x03', '\xf6', '\x0e', '\x61', '\x35', '\x57', '\xb9', '\x86', '\xc1', '\x1d', '\x9e',
		'\xe1', '\xf8', '\x98', '\x11', '\x69', '\xd9', '\x8e', '\x94', '\x9b', '\x1e', '\x87', '\xe9', '\xce', '\x55', '\x28', '\xdf',
		'\x8c', '\xa1', '\x89', '\x0d', '\xbf', '\xe6', '\x42', '\x68', '\x41', '\x99', '\x2d', '\x0f', '\xb0', '\x54', '\xbb', '\x16'
	]
	for i in range(len(state)):
		state[i] = lookup_table[ord(state[i])]

def shiftRows(state):
	s = state
	#s'_{i,j} --> s_{r, (c + r) mod 4}
	state = [s[0],s[1], s[2], s[3], s[5],s[6], s[7], s[4], s[10], s[11], s[8],s[9], s[15], s[12], s[13], s[14]]

def mixColumns(state):
	table2 = '\x00\x02\x04\x06\x08\x0a\x0c\x0e\x10\x12\x14\x16\x18\x1a\x1c\x1e\x20\x22\x24\x26\x28\x2a\x2c\x2e\x30\x32\x34\x36\x38\x3a\x3c\x3e\x40\x42\x44\x46\x48\x4a\x4c\x4e\x50\x52\x54\x56\x58\x5a\x5c\x5e\x60\x62\x64\x66\x68\x6a\x6c\x6e\x70\x72\x74\x76\x78\x7a\x7c\x7e\x80\x82\x84\x86\x88\x8a\x8c\x8e\x90\x92\x94\x96\x98\x9a\x9c\x9e\xa0\xa2\xa4\xa6\xa8\xaa\xac\xae\xb0\xb2\xb4\xb6\xb8\xba\xbc\xbe\xc0\xc2\xc4\xc6\xc8\xca\xcc\xce\xd0\xd2\xd4\xd6\xd8\xda\xdc\xde\xe0\xe2\xe4\xe6\xe8\xea\xec\xee\xf0\xf2\xf4\xf6\xf8\xfa\xfc\xfe\x1b\x19\x1f\x1d\x13\x11\x17\x15\x0b\x09\x0f\x0d\x03\x01\x07\x05\x3b\x39\x3f\x3d\x33\x31\x37\x35\x2b\x29\x2f\x2d\x23\x21\x27\x25\x5b\x59\x5f\x5d\x53\x51\x57\x55\x4b\x49\x4f\x4d\x43\x41\x47\x45\x7b\x79\x7f\x7d\x73\x71\x77\x75\x6b\x69\x6f\x6d\x63\x61\x67\x65\x9b\x99\x9f\x9d\x93\x91\x97\x95\x8b\x89\x8f\x8d\x83\x81\x87\x85\xbb\xb9\xbf\xbd\xb3\xb1\xb7\xb5\xab\xa9\xaf\xad\xa3\xa1\xa7\xa5\xdb\xd9\xdf\xdd\xd3\xd1\xd7\xd5\xcb\xc9\xcf\xcd\xc3\xc1\xc7\xc5\xfb\xf9\xff\xfd\xf3\xf1\xf7\xf5\xeb\xe9\xef\xed\xe3\xe1\xe7\xe5'
	table3 = '\x00\x03\x06\x05\x0c\x0f\x0a\x09\x18\x1b\x1e\x1d\x14\x17\x12\x11\x30\x33\x36\x35\x3c\x3f\x3a\x39\x28\x2b\x2e\x2d\x24\x27\x22\x21\x60\x63\x66\x65\x6c\x6f\x6a\x69\x78\x7b\x7e\x7d\x74\x77\x72\x71\x50\x53\x56\x55\x5c\x5f\x5a\x59\x48\x4b\x4e\x4d\x44\x47\x42\x41\xc0\xc3\xc6\xc5\xcc\xcf\xca\xc9\xd8\xdb\xde\xdd\xd4\xd7\xd2\xd1\xf0\xf3\xf6\xf5\xfc\xff\xfa\xf9\xe8\xeb\xee\xed\xe4\xe7\xe2\xe1\xa0\xa3\xa6\xa5\xac\xaf\xaa\xa9\xb8\xbb\xbe\xbd\xb4\xb7\xb2\xb1\x90\x93\x96\x95\x9c\x9f\x9a\x99\x88\x8b\x8e\x8d\x84\x87\x82\x81\x9b\x98\x9d\x9e\x97\x94\x91\x92\x83\x80\x85\x86\x8f\x8c\x89\x8a\xab\xa8\xad\xae\xa7\xa4\xa1\xa2\xb3\xb0\xb5\xb6\xbf\xbc\xb9\xba\xfb\xf8\xfd\xfe\xf7\xf4\xf1\xf2\xe3\xe0\xe5\xe6\xef\xec\xe9\xea\xcb\xc8\xcd\xce\xc7\xc4\xc1\xc2\xd3\xd0\xd5\xd6\xdf\xdc\xd9\xda\x5b\x58\x5d\x5e\x57\x54\x51\x52\x43\x40\x45\x46\x4f\x4c\x49\x4a\x6b\x68\x6d\x6e\x67\x64\x61\x62\x73\x70\x75\x76\x7f\x7c\x79\x7a\x3b\x38\x3d\x3e\x37\x34\x31\x32\x23\x20\x25\x26\x2f\x2c\x29\x2a\x0b\x08\x0d\x0e\x07\x04\x01\x02\x13\x10\x15\x16\x1f\x1c\x19\x1a'
	for c in range(4):
		s0, s1, s2, s3 = state[4*c:4*(c + 1)]
		state[4*c + 0] = table2[s0] ^ table3[s1] ^ s2         ^ s3
		state[4*c + 1] = s0         ^ table2[s1] ^ table3[s2] ^ s3
		state[4*c + 2] = s0         ^ s1         ^ table2[s2] ^ table3[s3]
		state[4*c + 3] = table3[s0] ^ s1         ^ s2         ^ table2[s3]

def addRoundKey(state, roundKey):
	for i in range(len(state)):
		state[i] ^= roundKey[i]

def subWord(word):
	subBytes(word)
	return word

def rotWord(word):
	return [word[1], word[2], word[3], word[0]]

def xor(s1, s2):
	return [chr(ord(b1) ^ ord(b2)) for b1, b2 in zip(s1, s2)]

def printHex(s):
	print (''.join(s)).encode('hex')

def keyExpansion(key):

	rcon = [['\x8d','\0','\0','\0'] , ['\x01','\0','\0','\0'] , ['\x02','\0','\0','\0'] , ['\x04','\0','\0','\0'] , ['\x08','\0','\0','\0'] , ['\x10','\0','\0','\0'] , ['\x20','\0','\0','\0'] , ['\x40','\0','\0','\0'] , ['\x80','\0','\0','\0'] , ['\x1b','\0','\0','\0'] , ['\x36','\0','\0','\0'] , ['\x6c','\0','\0','\0'] , ['\xd8','\0','\0','\0'] , ['\xab','\0','\0','\0'] , ['\x4d','\0','\0','\0'] , ['\x9a','\0','\0','\0'] , ['\x2f','\0','\0','\0'] , ['\x5e','\0','\0','\0'] , ['\xbc','\0','\0','\0'] , ['\x63','\0','\0','\0'] , ['\xc6','\0','\0','\0'] , ['\x97','\0','\0','\0'] , ['\x35','\0','\0','\0'] , ['\x6a','\0','\0','\0'] , ['\xd4','\0','\0','\0'] , ['\xb3','\0','\0','\0'] , ['\x7d','\0','\0','\0'] , ['\xfa','\0','\0','\0'] , ['\xef','\0','\0','\0'] , ['\xc5','\0','\0','\0']]
	nk = len(key)/4
	rounds = numRounds(len(key))
	w = key + ['\x00']*(16*(rounds + 1) - len(key))

	i = nk
	while i < 4*(rounds + 1):
		temp = w[4*(i - 1): 4*i]
		if i % nk == 0:
			temp = xor(subWord(rotWord(temp)), rcon[i/nk])
		elif nk > 6 and i % nk == 4:
			temp = subWord(temp)
		w[4*i:4*(i + 1)] = xor(w[4*(i - nk):4*(i - nk + 1)], temp)
		i += 1
	return w

def encrypt(pt_block, key):
	#TODO: check if this encrypts in place
	num_rounds = numRounds(len(key))
	state = pt_block
	w = keyExpansion(key)

	addRoundKey(state, w[:16])
	for i in range(1, num_rounds):
		subBytes(state)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, w[16*i:16*(i + 1)])

	subBytes(state)
	shiftRows(state)
	addRoundKey(state, w[-16:])
	return state

def testKeyExpansion():
	#128 bit key test
	key = ['\x2b', '\x7e', '\x15', '\x16', '\x28', '\xae', '\xd2', '\xa6', '\xab', '\xf7', '\x15', '\x88', '\x09', '\xcf', '\x4f', '\x3c']
	exp_key = '2b7e151628aed2a6abf7158809cf4f3ca0fafe1788542cb123a339392a6c7605f2c295f27a96b9435935807a7359f67f3d80477d4716fe3e1e237e446d7a883bef44a541a8525b7fb671253bdb0bad00d4d1c6f87c839d87caf2b8bc11f915bc6d88a37a110b3efddbf98641ca0093fd4e54f70e5f5fc9f384a64fb24ea6dc4fead27321b58dbad2312bf5607f8d292fac7766f319fadc2128d12941575c006ed014f9a8c9ee2589e13f0cc8b6630ca6'.decode('hex')
	assert(''.join(keyExpansion(key)) == exp_key)

	#192 bit key test
	key = ['\x8e', '\x73', '\xb0', '\xf7', '\xda', '\x0e', '\x64', '\x52', '\xc8', '\x10', '\xf3', '\x2b', '\x80', '\x90', '\x79', '\xe5', '\x62', '\xf8', '\xea', '\xd2', '\x52', '\x2c', '\x6b', '\x7b']
	exp_key = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7bfe0c91f72402f5a5ec12068e6c827f6b0e7a95b95c56fec24db7b4bd69b5411885a74796e92538fde75fad44bb095386485af05721efb14fa448f6d94d6dce24aa326360113b30e6a25e7ed583b1cf9a27f939436a94f767c0a69407d19da4e1ec1786eb6fa64971485f703222cb8755e26d135233f0b7b340beeb282f18a2596747d26b458c553ea7e1466c9411f1df821f750aad07d753ca4005388fcc5006282d166abc3ce7b5e98ba06f448c773c8ecc720401002202'.decode('hex')
	assert(''.join(keyExpansion(key)) == exp_key)

	#256 bit key test
	key = ['\x60', '\x3d', '\xeb', '\x10', '\x15', '\xca', '\x71', '\xbe', '\x2b', '\x73', '\xae', '\xf0', '\x85', '\x7d', '\x77', '\x81', '\x1f', '\x35', '\x2c', '\x07', '\x3b', '\x61', '\x08', '\xd7', '\x2d', '\x98', '\x10', '\xa3', '\x09', '\x14', '\xdf', '\xf4']
	exp_key = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff49ba354118e6925afa51a8b5f2067fcdea8b09c1a93d194cdbe49846eb75d5b9ad59aecb85bf3c917fee94248de8ebe96b5a9328a2678a647983122292f6c79b3812c81addadf48ba24360af2fab8b46498c5bfc9bebd198e268c3ba709e0421468007bacb2df331696e939e46c518d80c814e20476a9fb8a5025c02d59c58239de1369676ccc5a71fa2563959674ee155886ca5d2e2f31d77e0af1fa27cf73c3749c47ab18501ddae2757e4f7401905acafaaae3e4d59b349adf6acebd10190dfe4890d1e6188d0b046df344706c631e'.decode('hex')
	assert(''.join(keyExpansion(key)) == exp_key)

if __name__ == '__main__':
	assert(numRounds(128/8) == 10)
	assert(numRounds(192/8) == 12)
	assert(numRounds(256/8) == 14)
	testKeyExpansion()
