import aes, os, urllib, util

class NonAscii(ValueError): pass

key = os.urandom(16)

def oracle():
	#this value does not matter (as long as it's long enough)
	userdata = 'bs'*48
	ct = aes.encrypt_cbc(urllib.quote(userdata), key, key)
	#iv = key ==> don't send iv
	return ct[16:]

def consume_ct(ct):
	pt = aes.decrypt_cbc(key + ct, key)

	if not util.is_ascii(pt):
		raise NonAscii(pt)
	#do something with pt

def get_key():
	ct = oracle()
	blocks = aes.splitBlocks(ct)

	#send oracle c_0 || 00..0 || c_0
	#	= aes(iv ^ p_0) || 00..0 || aes(iv ^ p_0)
	#	= aes(key ^ p_0) || 00..0 || aes(key ^ p_0)
	#This decrypts to:
	#	p_0' || p_1' || p_2' = p_0 || aes_dec(00...) ^ c_0 || key ^ p_0
	#==> key = p_0' ^ p_2'

	parts = [blocks[0], '\0'*16, blocks[0]]
	parts.extend(blocks[3:])
	ctp = ''.join(parts)
	try:
		#p_1' = aes_dec(00...0) is non ascii with high probability
		#so we should get error with returned plaintext
		consume_ct(ctp)
	except NonAscii as e:
		blocks = aes.splitBlocks(e.args[0])
		return util.xor(blocks[0], blocks[2])

if __name__ == '__main__':
	assert(get_key() == key)
