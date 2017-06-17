import sys
from socket import socket
from netutil import send_len_payload, send_bigint, recv_bigint, recv_len_payload
from srp import hmac_sha256
from util import sha256sum

#from p33 import nist_p

def break_srp(addr, name):
	print 'Connecting to %s:%d...' % addr
	con = socket()
	con.connect(addr)

	#C -> S name, A=g^a We will be evil send A = multiple of p
	send_len_payload(con, name)
	send_bigint(con, 0)
	#send_bigint(con, nist_p) attack works with any multiple of p

	#S -> C salt, B = kv + g^b
	salt = recv_len_payload(con)
	_ = recv_bigint(con)

	#Server computes:
	#u = H(A || B)
	#S = (A v^u)^b = (v^u)^b A^b (mod p) = 0 when A = multple of p
	#K = H(S) = H(0)
	#We can compute this without needing the password
	K = sha256sum('\0')

	#C -> S mac(K, salt)
	send_len_payload(con, hmac_sha256(K, salt))

	ok = recv_len_payload(con)

	if ok != 'ok':
		print 'SRP failed. Server returned "%s"' % ok
		return None, None
	print 'Established shared key: ', K.encode('hex')
	return con, K

def usage(argv):
	print '''usage:
	%s <host> <port> <user> connect to server at address
	''' % argv[0]
	sys.exit(1)

if __name__ == '__main__':
	if len(sys.argv) == 4:
		addr = (sys.argv[1], int(sys.argv[2]))
		name = sys.argv[3]

		con, K = break_srp(addr, name)

		if con:
			print 'Received: ', recv_len_payload(con)
			send_len_payload(con, 'this works!!!')
	else:
		usage(sys.argv)
