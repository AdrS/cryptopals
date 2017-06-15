import aes
import base64
import os
import util


key = os.urandom(16)
nonce = util.randomUint64()

def load():
	with open('25.txt', 'r') as f:
		ct = base64.b64decode(''.join(f.read().split()))
	return aes.decrypt_ecb(ct, 'YELLOW SUBMARINE')

def get_ct():
	return aes.encrypt_ctr(load(), key, nonce)

def edit(ct, offset, newtext):
	assert(offset + len(newtext) <= len(ct))
	#the lazy way
	pt = aes.decrypt_ctr(ct, key, nonce)
	newpt = pt[:offset] + newtext + pt[offset + len(newtext):]
	return aes.encrypt_ctr(newpt, key, nonce)

def recover(ct):
	keystream = edit(ct, 0, '\0'*len(ct))
	return util.xor(ct, keystream)

if __name__ == '__main__':
	print recover(get_ct())
