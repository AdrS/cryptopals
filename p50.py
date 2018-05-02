import aes
import base64
import cbc_mac
import os
import util

m = "alert('MZA who was that?');\n"
k = "YELLOW SUBMARINE"
iv = '\0'*16
tag = cbc_mac.cbc_mac_tag(m, k, iv)

assert(tag.encode('hex') == "296b8d7cb78a243dda4d0a61d33bbdd1")

target = "alert('Ayo, the Wu is back!');"

def collide_hash(target):
	# Put comment after target to hide everything after
	while True:
		base = target + '//' + os.urandom(4)
		t1 = cbc_mac.cbc_mac_tag(base, k, iv)
		preimage = aes.add_pkcs7_padding(base) + util.xor(t1, m[:16]) + m[16:]
		assert(cbc_mac.cbc_mac_tag(preimage, k, iv) == tag)
		if "\n" not in preimage[:-(len(m) - 16)]:
			return preimage
		print("newline in padding :(")

if __name__ == "__main__":
	print(base64.b64encode(collide_hash(target)))
	'''
	// example javascript
	let m = "YWxlcnQoJ0F5bywgdGhlIFd1IGlzIGJhY2shJyk7Ly+SYtRRDAwMDAwMDAwMDAwMZrPKKd6E1lIZ7AuEnoG3vGFzIHRoYXQ/Jyk7Cg=="
	eval(atob(m))
	'''
