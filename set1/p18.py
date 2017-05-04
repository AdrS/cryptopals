import aes, base64

ct = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
nonce = 0
key = 'YELLOW SUBMARINE'

print aes.decrypt_ctr(ct, key, nonce)
