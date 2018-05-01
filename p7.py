import aes
import base64

with open('7.txt', 'r') as f:
	ct = base64.b64decode(''.join(f.read().split()))

key = "YELLOW SUBMARINE"

print aes.decrypt_ecb(ct, key)
