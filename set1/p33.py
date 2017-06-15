import random

_nist_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

_nist_g = 2

def gen_key_pair(p=_nist_p, g=_nist_g):
	'''generates a public private dh key pair for the specified group'''
	a = random.randrange(p)
	A = pow(g, a, p)
	return (a, A)

def get_common_key(A, b, p=_nist_p):
	return pow(A, b, p)

def _simple_dh():
	p = 37
	g = 5
	a = random.randint(0, p - 1)
	A = pow(g, a, p)

	b = random.randint(0, p - 1)
	B = pow(g, b, p)

	s1 = pow(B, a, p)
	s2 = pow(A, b, p)
	assert(s1 == s2)

def _test_bignum_dh():
	a, A = gen_key_pair()
	b, B = gen_key_pair()

	s1 = get_common_key(A, b)
	s2 = get_common_key(B, a)
	assert(s1 == s2)

if __name__ == '__main__':
	_simple_dh()
	_test_bignum_dh()
