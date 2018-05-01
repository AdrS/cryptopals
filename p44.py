import dsa, number_theory, p43, util

p, g, q = dsa.p, dsa.g, dsa.q

y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

def load(path='44.txt'):
	'''reads list of messages and signatures in the format:
	\nmsg: <msg>\ns: <s>\nr: <r>\nm: <m>\n'''
	with open(path, 'r') as f:
		lines = f.read().split('\n')
	assert(len(lines) % 4 == 0)
	sigs = []
	for i in range(0, len(lines), 4):
		msg = lines[i][len('msg: '):]
		s = int(lines[i + 1][3:])
		r = int(lines[i + 2][3:])
		m = lines[i + 3][3:]
		if len(m) % 2:
			m = '0' + m
		m = util.bytes_to_bigint(m.decode('hex'))
		sigs.append((msg, s, r, m))
	return sigs

def find_key(sigs, q=q):
	'''takes list of triples (s, r, H(m) as bigint) looks for repeated
	nonces and recovers nonce and private key
	'''
	#s = k^(-1)(H(m) + xr) mod q
	#=> k = s^(-1)(H(m) + xr) mod q  (1)

	#r = g^k mod q
	#s = k^(-1)(H(m) + xr) mod q

	#r' = g^k' mod q
	#s' = k'^(-1)(H(m') + xr') mod q

	#Detecting Repeated Nonce
	#k == k' ==> r == r
	#r == r' ==> k probably equals k'
	#
	#r = (sk - H(m))/x mod q
	#r == r'=> (sk - H(m))/x == (s'k - H(m'))/x mod q
	#=> k(s - s') = H(m) - H(m') mod q
	#=> K = (H(m) - H(m'))/(s - s') mod q
	sigs_by_r = {}
	for s, r, m in sigs:
		if r not in sigs_by_r:
			sigs_by_r[r] = (s, m)
			continue
		#same r ==> same k?
		if r in sigs_by_r:
			sp, mp = sigs_by_r[r]
			#find nonce
			k = ((m - mp) * number_theory.mod_inv(s - sp, q)) % q
			#find private key from nonce
			x = p43.recover_private_key(None, r, s, k, q,  m)
			return x
if __name__ == '__main__':
	sigs = load()
	x = find_key([(s, r, m) for _, s, r, m in sigs])
	if x:
		print 'Private key =', x
		h_pk = util.sha1sum(util.bigint_to_bytes(x).encode('hex')).encode('hex')
		#print 'sha(x) =', h_pk
		assert(h_pk == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52')
	else:
		print 'No repeated nonces found :('
