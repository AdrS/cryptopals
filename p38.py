from srp import hmac_sha256, users, create_srp_account, AccountAlreadyExists
from srp import _compute_x
from p33 import nist_p, nist_g, gen_key_pair
from netutil import *
from os import urandom
from util import *
from socket import socket
import sys

def handle_simplified_srp_client(con, addr):
	#C -> S name, A=g^a
	name = recv_len_payload(con)

	if name not in users:
		send_len_payload(con, 'error: non existant account')
		con.close()
		return
	v, salt = users[name]

	A = recv_bigint(con)

	#S -> C salt, B = g^b, u = random
	b, B = gen_key_pair()
	u = bytes_to_bigint(urandom(16))

	send_len_payload(con, salt)
	send_bigint(con, B)
	send_bigint(con, u)

	#get shared key
	#S = (A v^u)^b = (g^a g^(ux))^b = g^(ab + uxb)
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

def simplified_srp_connect(addr, name, password):
	print 'Connecting to %s:%d...' % addr
	con = socket()
	con.connect(addr)

	#C -> S name, A=g^a
	a, A = gen_key_pair()
	send_len_payload(con, name)
	send_bigint(con, A)

	#S -> C salt, B = g**b, u
	salt = recv_len_payload(con)
	B = recv_bigint(con)
	u = recv_bigint(con)

	#S = B^(a + ux) = g^(b*(a + ux))
	x = _compute_x(salt, password)
	S = pow(B, a + u*x, nist_p)
	K = sha256sum(bigint_to_bytes(S))

	#C -> S
	send_len_payload(con, hmac_sha256(K, salt))

	ok = recv_len_payload(con)

	if ok != 'ok':
		print 'SRP failed. Server returned "%s"' % ok
		return None, None
	print 'Established shared key: ', K.encode('hex')
	return con, K

def crack_password(p, g, salt, A, u, b, tag, pw_list='pw_list.txt'):
	with open(pw_list, 'r') as f:
		dictionary = f.read().split('\n')
	for pw in dictionary:
		x = bytes_to_bigint(sha256sum(salt + pw))
		v = pow(g, x, p)
		S = pow(A * pow(v, u, p), b, p)
		K = sha256sum(bigint_to_bytes(S))
		#check guess
		if hmac_sha256(K, salt) == tag:
			return pw
	return None

#TODO: convert to mitm that lets traffic through
def evil_handle_client(conC, addrC, addrS):
	#C -> M name, A = g^a
	name = recv_len_payload(conC)
	A = recv_bigint(conC)

	#connect to real server
	conS = socket()
	conS.connect(addrS)

	#M -> S name, A
	send_len_payload(conS, name)
	send_bigint(conS, A)

	#S -> M salt, B = g^b, u
	salt = recv_len_payload(conS)
	B_S = recv_bigint(conS)
	u = recv_bigint(conS)

	#don't need server anymore
	conS.close()

	#pick arbitrary value to send to client
	bM = 1234567890
	B_M = pow(nist_g, bM, nist_p)

	#M -> C salt, B_M = g^bM, u
	send_len_payload(conC, salt)
	send_bigint(conC, B_M)
	send_bigint(conC, u)

	#C -> M mac(K, salt)
	tag = recv_len_payload(conC)

	#don't need client anymore
	conC.close()

	#crack password from tag = mac(K, salt)

	#correct guess of password ==>
	#correct value of v = g^H(salt || password) ==>
	#correct value of S = (A * v ^ u)^bM ==>
	#correct value of K = sha256(S) ==>
	#matches tag = hmac_sha256(K, salt)
	pw = crack_password(nist_p, nist_g, salt, A, u, bM, tag)
	if pw:
		print 'Cracked password!'
		print 'Password is:', pw
	else:
		print 'Password not found'

def usage(argv):
	print '''usage:
	%s <port>                      run server on port
	%s <host> <port> <user> <pass> connect to server at address
	%s <portl> <host> <ports>      act as mitm to crack password
	''' % (argv[0], argv[0], argv[0])
	sys.exit(1)

if __name__ == '__main__':
	create_srp_account('adrs', 'secret')
	if len(sys.argv) == 2:
		serve_forever(int(sys.argv[1]), handle_simplified_srp_client)
	elif len(sys.argv) == 4:
		addrS = (sys.argv[2], int(sys.argv[3]))
		handler = lambda conC, addrC: evil_handle_client(conC, addrC, addrS)
		serve_forever(int(sys.argv[1]), handler)
	elif len(sys.argv) == 5:
		addr = (sys.argv[1], int(sys.argv[2]))
		name, password = sys.argv[3:]

		con, K = simplified_srp_connect(addr, name, password)

		if con:
			print 'Received: ', recv_len_payload(con)
			send_len_payload(con, 'this works!!!')
	else:
		usage(sys.argv)
