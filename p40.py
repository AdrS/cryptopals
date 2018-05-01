import number_theory
import rsa
import util

#see: https://people.freebsd.org/~lstewart/references/apple_tr_kt32_cuberoot.pdf
#for computing cube roots

if __name__ == '__main__':
	#get 3 RSA keys all with e = 3
	_, e1, n1 = rsa.gen_key_pair(64)
	_, e2, n2 = rsa.gen_key_pair(64)
	_, e3, n3 = rsa.gen_key_pair(64)
	assert({e1, e2, e3} == {3})

	#if same message is encrypted with all keys
	m = "hello"
	c1 = rsa.rsa_encrypt(m, 3, n1)
	c2 = rsa.rsa_encrypt(m, 3, n2)
	c3 = rsa.rsa_encrypt(m, 3, n3)

	#then
	#c_i = m^3 (mod n_i)
	#So by CTR we can find m^3  (mod n_1*n_2*n_3)
	m_cubed = number_theory.crt([c1, c2, c3], [n1, n2, n3])

	#m < n_i ==> m^3 < n_1*n_2*n_3
	#==> we can find m by taking a normal cube root
	mp = util.bigint_to_bytes(number_theory.ith_root(m_cubed, 3))
	assert(m == mp)
	print 'Recovered message:', mp
