import number_theory, rsa, time, util

class Oracle:
	def __init__(self):
		self._seen = set()
		self._d, self._e, self._n = rsa.gen_key_pair(256)

	def query(self, rsa_blob):
		'''Takes RSA ciphertext and returns plaintext.
		If the ciphertext has been queried, returns nothing'''
		#cannot submit same message to oracle twice
		if rsa_blob in self._seen:
			return
		return rsa.rsa_decrypt(rsa_blob, self._d, self._n)

	def get_ct(self):
		pt = "%d something" % int(time.time())
		ct = rsa.rsa_encrypt(pt, self._e, self._n)
		self._seen.add(ct)
		return ct

	def get_public_key(self):
		return self._e, self._n

if __name__ == '__main__':
	oracle = Oracle()
	ct = oracle.get_ct()

	#cannot query oracle on ciphertexts it has already seen
	assert(oracle.query(ct) == None)

	e, n = oracle.get_public_key()

	#c' = s^e*c ==> p' = (s^e*c)^d = s*p
	s = 2
	ctp = (pow(s, e, n) * ct) % n

	ptp = oracle.query(ctp)
	pt = (ptp * number_theory.mod_inv(s, n)) % n
	print util.bigint_to_bytes(pt)
