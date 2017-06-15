from p28 import *
from os import urandom
from sha1 import Sha1, get_padding



if __name__ == '__main__':
	key = urandom(16)
	m = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

	t = tag(m, key)

	padding = get_padding(len(m) + 16)
	s = Sha1(t, 16 + len(m) + len(padding))
	new_suffix = ';admin=true'
	s.add(new_suffix)
	forged_tag = s.digest()
	new_message = m + padding + new_suffix

	assert(verify(new_message, forged_tag, key))
