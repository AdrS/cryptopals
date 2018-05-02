import aes
import os
import string
import util
import zlib

key = os.urandom(16)
sessionId = 'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='

def oracle(p):
	nonce = util.randomUint64()
	def format_request(p):
		return '''POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=%s
Content-Length: %d

%s''' % (sessionId, len(p), p)
	return len(aes.encrypt_ctr(zlib.compress(format_request(p)), key, nonce))

def argmin_strict(lens):
	'Returns index of smallest length or None if there is a tie'
	mi = 0
	tie = False
	for i in range(1, len(lens)):
		if lens[i] < lens[mi]:
			mi = i
			tie = False
		elif lens[i] == lens[mi]:
			tie = True
	if not tie:
		return mi
	
def guessSessionId():
	base = "Cookie: sessionid="

	charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + '+/=' + '\n'

	# While not at end of cookie:
	while base[-1] != '\n':
		print(base)
		best = argmin_strict([oracle(base + guess) for guess in charset])
		if not best:
			print('tie :(')
			break
		base += charset[best]
	return base

if __name__ == "__main__":
	guessSessionId()
