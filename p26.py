import aes, os, urllib, util

class InvalidCookie(Exception): pass

key = os.urandom(16)
prefix = "comment1=cooking%20MCs;userdata="
sufix = ";comment2=%20like%20a%20pound%20of%20bacon"

def oracle(userdate):
	iv = os.urandom(16)
	nonce = util.randomUint64()
	return aes.encrypt_ctr(prefix + urllib.quote(userdate) + sufix, key, nonce), nonce

def is_admin(ct, nonce):
	pt = aes.decrypt_ctr(ct, key, nonce)
	cookies = []
	for i in pt.split(';'):
		parts = i.split('=')
		if len(parts) != 2:
			raise InvalidCookie()
		if parts[0] == 'admin' and parts[1] == 'true':
			return True
	return False

def gain_admin():
	desired = 'admin=true'
	actual = 'userdata='
	pad_len = len(desired) - len(actual)
	ct, nonce = oracle('a'*pad_len)
	#get enc(comment1= .... ;userdate=a;comment2=...)

	ct_diff = util.xor(desired, actual + 'a'*pad_len)
	prefix_pad_len = len(prefix) - len(actual)
	sufix_pad_len = len(ct) - len(ct_diff) - prefix_pad_len
	return util.xor('\0'*prefix_pad_len + ct_diff + '\0'*sufix_pad_len, ct), nonce

if __name__ == '__main__':
	assert(is_admin(*gain_admin()))
