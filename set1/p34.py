from p33 import *
from socket import *
from util import *
from os import urandom
import aes
import struct
import sys

def connect(addr, p=nist_p, g=nist_g):
	'''sets up tcp connection to host and does dh key exchange'''
	a, A = gen_key_pair(p, g)
	con = socket()
	con.connect(addr)
	send_bigint(con, p)
	send_bigint(con, g)
	send_bigint(con, A)
	B = recv_bigint(con)
	s = get_common_key(B, a, p)
	key = sha1sum(bigint_to_bytes(s))[:16]
	return con, key

def send(con, msg, key):
	'''sends <len> <aes cbc encrypted msg>'''
	iv = urandom(16)
	return send_len_payload(con, aes.encrypt_cbc(msg, key, iv))

def recv(con, key):
	'''reads <len> <aes cbc encrypted msg>'''
	return aes.decrypt_cbc(recv_len_payload(con), key)

def run_echo_server(port):
	lfd = socket()
	lfd.bind(('', port))
	lfd.listen(5)
	while True:
		con, addr = lfd.accept()
		print 'Connection from %s:%d' % addr

		p = recv_bigint(con)
		g = recv_bigint(con)
		A = recv_bigint(con)
		if g >= p or A >= p:
			con.send('error: bad parameters')
			con.close()
		b, B = gen_key_pair(p, g)
		send_bigint(con, B)
		s = get_common_key(A, b, p)
		print 'Established shared key'

		key = sha1sum(bigint_to_bytes(s))[:16]
		msg = recv(con, key)

		print 'Received: ', msg

		#echo message back
		send(con, msg, key)
		con.close()

def ping_server(addr):
	con, key = connect(addr)
	send(con, 'Ping from Alice', key)
	print 'Received', recv(con, key)
	con.close()

def run_mitm_server(port, addrB):
	lfd = socket()
	lfd.bind(('', port))
	lfd.listen(5)
	while True:
		conA, addrA = lfd.accept()
		print 'Connection from Alice %s:%d' % addrA

		#set do DH with Alice
		p = recv_bigint(conA)
		g = recv_bigint(conA)
		A = recv_bigint(conA)
		if g >= p or A >= p:
			conA.send('error: bad parameters')
			conA.close()
			continue
		c, C = gen_key_pair(p, g)
		send_bigint(conA, C)
		sA = get_common_key(A, c, p)
		print 'Established shared key with Alice'

		keyA = sha1sum(bigint_to_bytes(sA))[:16]

		#establish connection with Bob
		conB, keyB = connect(addrB)
		print 'Established connection with Bob'

		#read ping from Alice
		msgA = recv(conA, keyA)

		print 'Received ping from Alice: ', msgA

		#forward ping to Bob
		send(conB, msgA, keyB)

		#read pong from Bob
		msgB = recv(conB, keyB)
		conB.close()

		print 'Received pong from Bob: ', msgB

		#forward pong to Alice
		send(conA, msgB, keyA)
		conA.close()

def usage(argv):
	print ''''usage:
	%s <port>                   run echo server on port
	%s <host> <port>            ping echo server at address
	%s <portl> <host> <ports>   act as mitm listening on <portl> and
	                            forwarding traffic to server at <host> <ports>
	''' % (argv[0], argv[0], argv[0])
	sys.exit(1)

if __name__ == '__main__':
	if len(sys.argv) == 2:
		run_echo_server(int(sys.argv[1]))
	elif len(sys.argv) == 3:
		ping_server((sys.argv[1], int(sys.argv[2])))
	elif len(sys.argv) == 4:
		run_mitm_server(int(sys.argv[1]), (sys.argv[2], int(sys.argv[3])))
	else:
		usage(sys.argv)
