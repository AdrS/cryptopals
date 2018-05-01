from hashlib import sha1
from os import urandom

def tag(m, k):
	return sha1(k+ m).digest()

def verify(m, t, k):
	real_tag = tag(m, k)
	return real_tag == t

if __name__ == '__main__':
	k = urandom(16)
	m = "some message"
	assert(verify(m, tag(m, k), k))
	assert(not verify("different message", tag(m, k), k))
	assert(not verify(m, tag(m, "wrong key"), k))
	#change tag
	t = tag(m, k)
	t = list(t)
	t[3] = chr((ord(t[3]) + 128) % 256)
	t = ''.join(t)
	assert(not verify(m, t, k))
