import dsa, number_theory, util

def recover_private_key(m, r, s, k, q):
	'''recover dsa private key from k and signature'''
	#s = k^(-1)(H(m) + xr) mod q
	#==> sk - H(m) = xr (mod q)
	#==> x = r^(-1)(sk - H(m)) mod q
	H_m = util.bytes_to_bigint(util.sha1sum(m))
	r_inv = number_theory.mod_inv(r, q)
	x = ((((s*k) % q - H_m) % q) * r_inv) % q
	return x

def dsa_sign_with_k(H_m, x, k):
	g, p, q = dsa.g, dsa.p, dsa.q

	#r = (g^k mod p) mod q
	r = pow(g, k, p) % q
	#s = k^(-1)(H(m) + xr) mod q
	k_inv = number_theory.mod_inv(k, q)
	s = (k_inv * ((H_m + ((x*r) % q)) % q)) % q
	return (r, s)

if __name__ == '__main__':
	y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

	msg = '''For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n'''

	r = 548099063082341131477253921760299949438196259240
	s = 857042759984254168557880549501802188789837994940
	assert(util.sha1sum(msg).encode('hex') == 'd2d0714f014a9784047eaeccf956520045c45265')

	H_m = util.bytes_to_bigint(util.sha1sum(msg))
	r_inv = number_theory.mod_inv(r, dsa.q)

	for k in range(1, 1<<16):
		#x = ((((s*k) % dsa.q  + dsa.q - H_m) % dsa.q) * r_inv) % dsa.q
		x = ((s*k - H_m) * r_inv) % dsa.q
		if dsa_sign_with_k(H_m, x, k) == (r, s):
			#if x is actual privake key => y = g^x mod p
			assert(y == pow(dsa.g, x, dsa.p))
			print 'k =', k
			print 'Private key =', x
			key_hash = util.sha1sum('%x' % x).encode('hex')
			assert(key_hash == '0954edd5e0afe5542a4adf012611a91912a3ec16')
			break
