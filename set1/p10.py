import aes
import base64

with open('10.txt', 'r') as f:
	ct = base64.b64decode(''.join(f.read().split()))

key = "YELLOW SUBMARINE"

print aes.decrypt_cbc('\x00'*16 + ct, key)
