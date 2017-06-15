import md4
from os import urandom

def mac_tac(key, message):
	return md4.md4(key + message)

def mac_verify(key, message, tag):
	return mac_tac(key, message) == tag



if __name__ == '__main__':
	key = urandom(16)
	m = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

	tag = mac_tac(key, m)

	padding = md4.get_padding(len(m) + 16)
	h = md4.MD4(tag, 16 + len(m) + len(padding))
	new_suffix = ';admin=true'
	h.add(new_suffix)
	forged_tag = h.digest()
	new_message = m + padding + new_suffix

	assert(mac_verify(key, new_message, forged_tag))
