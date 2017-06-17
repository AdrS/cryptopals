from p33 import nist_p, nist_g, gen_key_pair
from util import bytes_to_bigint, bigint_to_bytes, sha256sum
from os import urandom
from netutil import *
from socket import socket
from p31_server import hmac
import random, sys

k = 3

users = {}

def hmac_sha256(k, msg):
	return hmac(k, msg, sha256sum)

class AccountAlreadyExists(Exception): pass

def _compute_x(salt, password):
	#compute x = H(salt || password)
	return bytes_to_bigint(sha256sum(salt + password))

def _compute_u(A,B):
	#compute u = H(A | B)
	return bytes_to_bigint(sha256sum(bigint_to_bytes(A) + bigint_to_bytes(B)))

def create_srp_account(name, password):
	if name in users:
		raise AccountAlreadyExists()

	salt = urandom(16)
	x = _compute_x(salt, password)
	#compute verifier v = g^H(salt + password)
	v = pow(nist_g, x, nist_p)
	users[name] = (v, salt)

def handle_srp_client(con, addr):
	#C -> S name, A=g^a
	name = recv_len_payload(con)

	if name not in users:
		send_len_payload(con, 'error: non existant account')
		con.close()
		return
	v, salt = users[name]

	A = recv_bigint(con)

	#S -> C salt, B=kv + g^b
	b = random.SystemRandom().randrange(nist_p)
	#B = k*v + g^b = kg^H(salt + password) + g^b
	B = (k*v + pow(nist_g,b, nist_p)) % nist_p

	send_len_payload(con, salt)
	send_bigint(con, B)

	#compute u = H(A | B)
	u = _compute_u(A, B)

	#S = (A v^u)^b = (g^a g^(ux))^b = (g^(a + ux))^b = g^(b(a + ux))
	S = pow(A * pow(v, u, nist_p), b, nist_p)
	K = sha256sum(bigint_to_bytes(S))

	#C -> S mac(K, salt)
	tag = recv_len_payload(con)

	if hmac_sha256(K, salt) != tag:
		print 'Invalid mac'
		send_len_payload(con,'error: invalid mac')
		con.close()
		return

	send_len_payload(con,'ok')
	print 'Established shared key: ', K.encode('hex')
	send_len_payload(con, 'success!!!')
	con.close()

def srp_connect(addr, name, password):
	print 'Connecting to %s:%d...' % addr
	con = socket()
	con.connect(addr)

	#C -> S name, A=g^a
	a, A = gen_key_pair()
	send_len_payload(con, name)
	send_bigint(con, A)

	#S -> C salt, B = kv + g^b
	salt = recv_len_payload(con)
	B = recv_bigint(con)

	#compute u = H(A | B)
	u = _compute_u(A, B)
	x = _compute_x(salt, password)

	#S = (B - kg^x)^(a + ux) = (kv + g^b - kv)^(a + ux) = g^(b(a + ux))
	S = pow(B - k*pow(nist_g, x, nist_p), (a + u*x) % nist_p, nist_p)
	K = sha256sum(bigint_to_bytes(S))

	#C -> S
	send_len_payload(con, hmac_sha256(K, salt))

	ok = recv_len_payload(con)

	if ok != 'ok':
		print 'SRP failed. Server returned "%s"' % ok
		return None, None
	print 'Established shared key: ', K.encode('hex')
	return con, K

def usage(argv):
	print '''usage:
	%s <port>                      run server on port
	%s <host> <port> <user> <pass> connect to server at address
	''' % (argv[0], argv[0])
	sys.exit(1)

if __name__ == '__main__':
	create_srp_account('adrs', 'password')
	if len(sys.argv) == 2:
		serve_forever(int(sys.argv[1]), handle_srp_client)
	elif len(sys.argv) == 5:
		addr = (sys.argv[1], int(sys.argv[2]))
		name, password = sys.argv[3:]

		con, K = srp_connect(addr, name, password)

		if con:
			print 'Received: ', recv_len_payload(con)
			send_len_payload(con, 'this works!!!')
	else:
		usage(sys.argv)
