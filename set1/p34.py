from p33 import *
from util import *
from os import urandom
import socket
import aes
import struct
import sys
from netutil import *

def dh_connect(addr, p=nist_p, g=nist_g):
	'''sets up tcp connection to host and does dh key exchange'''
	a, A = gen_key_pair(p, g)
	con = socket.socket()
	con.connect(addr)
	print 'Connecting to %s:%d' % addr
	send_bigint(con, p)
	send_bigint(con, g)
	send_bigint(con, A)
	B = recv_bigint(con)
	s = get_common_key(B, a, p)
	key = sha1sum(bigint_to_bytes(s))[:16]
	print 'Shared key: ', key.encode('hex')
	return con, key

def send_ct(con, msg, key):
	'''sends <len> <aes cbc encrypted msg>'''
	iv = urandom(16)
	return send_len_payload(con, aes.encrypt_cbc(msg, key, iv))

def recv_ct(con, key):
	'''reads <len> <aes cbc encrypted msg>'''
	return aes.decrypt_cbc(recv_len_payload(con), key)

def echo_server_handler(con, addr):
	p = recv_bigint(con)
	g = recv_bigint(con)
	A = recv_bigint(con)
	if g >= p or A > p:
		print 'received bad parameters'
		con.send('error: bad parameters')
		con.close()
		return
	b, B = gen_key_pair(p, g)
	send_bigint(con, B)
	s = get_common_key(A, b, p)
	key = sha1sum(bigint_to_bytes(s))[:16]
	print 'Established shared key:', key.encode('hex')

	msg = recv_ct(con, key)

	print 'Received: ', msg

	#echo message back
	send_ct(con, msg, key)
	con.close()

def ping_server(addr):
	con, key = dh_connect(addr)
	send_ct(con, 'Ping from Alice', key)
	print 'Received', recv_ct(con, key)
	con.close()

def mitm_server_handler(conA, addrA, addrB):
	#start DH with Alice
	#A -> M p, g, A
	p = recv_bigint(conA)
	g = recv_bigint(conA)
	A = recv_bigint(conA)
	if g >= p or A >= p:
		print 'received bad parameters'
		conA.send('error: bad parameters')
		conA.close()
		return

	#do DH with Bob
	#M -> B p, g, p
	conB = socket.socket()
	conB.connect(addrB)
	send_bigint(conB, p)
	send_bigint(conB, g)
	send_bigint(conB, p)

	#B -> M B
	B = recv_bigint(conB)

	#sB = p^b = 0 (mod p)
	key = sha1sum(bigint_to_bytes(0))[:16]

	print 'Finished DH with Bob'

	#finish DH with Alice
	#M -> A p
	send_bigint(conA, p)

	#sA = p^a = 0 (mod p)

	print 'Finished DH with Alice'

	#NOTE: Alice and Bob always end up with the same predictable
	#	session key because of the MITM

	#read ping from Alice
	msgA = recv_ct(conA, key)

	print 'Received ping from Alice: ', msgA

	#forward ping to Bob
	send_ct(conB, msgA, key)

	#read pong from Bob
	msgB = recv_ct(conB, key)
	conB.close()

	print 'Received pong from Bob: ', msgB

	#forward pong to Alice
	send_ct(conA, msgB, key)
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
		serve_forever(int(sys.argv[1]), echo_server_handler)
	elif len(sys.argv) == 3:
		ping_server((sys.argv[1], int(sys.argv[2])))
	elif len(sys.argv) == 4:
		addrB = (sys.argv[2], int(sys.argv[3]))
		handler = lambda conA, addrA: mitm_server_handler(conA, addrA, addrB)
		serve_forever(int(sys.argv[1]), handler)
	else:
		usage(sys.argv)
