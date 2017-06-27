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

#Don't wan't to wait for params to be generated? ==> use these
_sample_params = (111362286410211583669725041748624015357015789920103016229885764684530821371586941962831815326506479749001616409906800547275431285766694970292540991623633822700408019631094608796497093656659564366838349269038200838176792713390842709111079260436382859247229353043625367114615775993991276917586476130163934190371L, 3, 167043429615317375504587562622936023035523684880154524344828647026796232057380412944247722989759719623502424614860200820913146928650042455438811487435450759902502377024707831573474592372202008245491689999576946888508161524416942544195053500973486143761844643232694997008489565006093697359038427190720833724177L)

if __name__ == '__main__':
	d, e, n = gen_key_pair(128, verbose=True)
	m = 'hello' #message length must be < n
	c = rsa_encrypt(m, e, n)
	mp = rsa_decrypt(c, d, n)
	assert(util.bigint_to_bytes(mp) == m)
