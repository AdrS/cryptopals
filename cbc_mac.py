import aes

def cbc_mac_tag(m, k, iv):
	return aes.encrypt_cbc(m, k, iv)[-16:]

def cbc_mac_verify(m, k, iv, tag):
	return cbc_mac_tag(m, k, iv) == tag

def _test():
	from os import urandom
	iv = urandom(16)
	k = urandom(16)
	m = "message yo"

	tag = cbc_mac_tag(m, k, iv)
	assert(cbc_mac_verify(m, k, iv, tag))
	
	#wrong message
	assert(not cbc_mac_verify("different message", k, iv, tag))
	#wrong key
	assert(not cbc_mac_verify(m, urandom(16), iv, tag))
	#wrong iv
	assert(not cbc_mac_verify(m, k, urandom(16), tag))
	#wrong tag
	assert(not cbc_mac_verify(m, k, iv, urandom(16)))

if __name__ == '__main__':
	_test()
