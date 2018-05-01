import aes, os, urllib

class InvalidCookie(Exception): pass

key = os.urandom(16)
prefix = "comment1=cooking%20MCs;userdata="
sufix = ";comment2=%20like%20a%20pound%20of%20bacon"

def oracle(userdate):
	iv = os.urandom(16)
	return aes.encrypt_cbc(prefix + urllib.quote(userdate) + sufix, key, iv)

def is_admin(ct):
	pt = aes.decrypt_cbc(ct, key)
	cookies = []
	for i in pt.split(';'):
		parts = i.split('=')
		if len(parts) != 2:
			raise InvalidCookie()
		if parts[0] == 'admin' and parts[1] == 'true':
			return True
	return False

def gain_admin():
	while True:
		#Notes:
		#	'=' ^ 4 --> '9'
		#	';' ^ 2 --> '9'
		lenPad1 = 16 - (len(prefix) % 16)
		tail = '9admin9true'
		lenPad2 = 16 - (len(tail) % 16)
		#AES-CBC('comment1=....;userdata=aaaaaa <block boundary>
		#		<block of all as>	<block boundary>
		#		a...aaaa9admin9true <block boundary>;commend2=....
		c = oracle('a'*(lenPad1 + 16 + lenPad2) + tail)
		lenP1 = len(prefix) + lenPad1 + 16


		#get iv + AES-CBC('comment1=....userdate=aaaa..')

		c1 = c[:lenP1]
		c2 = c[lenP1 : lenP1 + 16]
		c2 = aes.xor(c2,'\x00'*lenPad2 + '\x02' + '\x00'*5 + '\x04' + '\x00'*4)
		c2 = ''.join(c2)
		c3 = c[lenP1 + 16:]
		cprime = c1 + c2 + c3
		
		#block with fliped bits does not contain ';' or '=' with probability
		#(127/128)^16 = 88%
		#Because IV is different for each query, just try again until success
		try:
			is_admin(cprime)
		except InvalidCookie:
			pass
		else:
			return cprime
