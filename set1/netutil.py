import socket
import struct
import threading
import util

def read_exactly(con, n):
	'''reads exactly n bytes form con or raises exception'''
	data = con.recv(n)
	if len(data) != n:
		raise Exception('expected more bytes')
	return data

def send_len_payload(con, data):
	'''sends <length of data> <data>'''
	return con.send(struct.pack('!I', len(data)) + data)

def recv_len_payload(con):
	'''reads <length of data> <data> and returns data'''
	length = struct.unpack('!I', read_exactly(con, 4))[0]
	data = read_exactly(con, length)
	return data

def send_bigint(con, i):
	'''sends <length> <bigint>'''
	return send_len_payload(con, util.bigint_to_bytes(i))

def recv_bigint(con):
	'''reads <length> <bigint>'''
	return util.bytes_to_bigint(recv_len_payload(con))

def serve_forever(port, handler):
	lfd = socket.socket()
	lfd.bind(('', port))
	lfd.listen(5)
	print 'Listening on port %d...' % port
	while True:
		con, addr = lfd.accept()
		print 'Connection from %s:%d' % addr
		threading.Thread(target=handler, args=(con, addr)).run()
