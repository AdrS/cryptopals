import number_theory
import util

def _find_rsa_prime(bit_length):
	#find prime p such that p - 1 is not divisible by 3
	#The reason for this is to ensure than e=3 has inverse mod (p - 1)(q - 1)
	while True:
		p = number_theory.find_safe_prime(bit_length)
		if (p - 1) % 3 != 0:
			return p

def gen_key_pair(bit_length=1024, verbose=False):
	'''generates an RSA public private key pair and returns
		d, e, n
	'''
	p = _find_rsa_prime(bit_length/2)
	if verbose:
		print 'p =', p
	q = _find_rsa_prime(bit_length/2)
	if verbose:
		print 'q =', q
	n = p*q
	if verbose:
		print 'n =', n
	phi_n = (p - 1)*(q - 1)
	if verbose:
		print 'phi(n) =', phi_n
	#this is not secure (duh!!!)
	e = 3
	d = number_theory.mod_inv(e, phi_n)
	if verbose:
		print 'e, d = %d, %d' % (e, d)
	return d, e, n

def rsa_encrypt(m, e, n):
	if isinstance(m, basestring):
		m = util.bytes_to_bigint(m)
	return pow(m, e, n)

def rsa_decrypt(c, d, n):
	if isinstance(c, basestring):
		c = util.bytes_to_bigint(c)
	return pow(c, d, n)

if __name__ == '__main__':
	d, e, n = gen_key_pair(128, verbose=True)
	m = 'hello' #message length must be < n
	c = rsa_encrypt(m, e, n)
	mp = rsa_decrypt(c, d, n)
	assert(util.bigint_to_bytes(mp) == m)
