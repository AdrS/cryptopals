import number_theory, random, util

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1

q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

def gen_key_pair(p=p, q=q, g=g):
	'''return key pair 0 < x < q, y = g^x (mod p)'''
	#private key 0 < x < q
	x = random.SystemRandom().randrange(1, q - 1)

	#public key y = g^x (mod p)
	y = pow(g, x, p)
	return x, y

def dsa_sign(m, x, p=p, q=q, g=g, h=util.sha1sum):
	H_m = util.bytes_to_bigint(h(m))
	while True:
		#generate nonce 1 < k < q
		k = random.SystemRandom().randrange(1, q - 1)
		#r = (g^k mod p) mod q
		r = pow(g, k, p) % q
		#if r == 0, pick new k and try again
		if r == 0: continue

		#s = k^(-1)(H(m) + xr) mod q
		k_inv = number_theory.mod_inv(k, q)
		s = (k_inv * ((H_m + ((x*r) % q)) % q)) % q
		#if s == 0, pick new k and try again
		if s == 0: continue
		
		return (r, s)

def dsa_verify(r, s, m, y, p=p, q=q, g=g, h=util.sha1sum):
	#check that 0 < r < q and 0 < s < q
	if 0 >= r or r >= q or 0 >= s or r >= q:
		return False
	H_m = util.bytes_to_bigint(h(m))
	#w = s^(-1) mod q
	w = number_theory.mod_inv(s, q)
	u1 = (H_m * w) % q
	#u_2 = r*w = r*s^(-1)
	u2 = (r*w) % q
	v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
	return v == r

if __name__ == '__main__':
	x, y = gen_key_pair()
	msg = "Hello Alice"
	r, s = dsa_sign(msg, x)
	assert(dsa_verify(r, s, msg, y))
	assert(not dsa_verify(r, s, "Hello Mallory", y))
	assert(not dsa_verify(r + 1, s, "Hello Mallory", y))
	assert(not dsa_verify(r, s + 1, "Hello Mallory", y))
