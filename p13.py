import aes, os, string
from collections import defaultdict

class InvalidQueryString(Exception): pass
class IllegalCharacter(Exception): pass
class InvalidEmail(Exception): pass

def parse_query_string(s):
	'''parses string of form 'k1=v1&k2=v2&...&kn=vn' and returns dictionary'''
	items = s.split('&')
	d = defaultdict(list)
	for i in items:
		parts = i.split('=')
		if len(parts) != 2 or not parts[0]:
			raise InvalidQueryString()
		d[parts[0]].append(parts[1])
	return d

def only_valid_chars(s, valid_characters = string.ascii_letters + string.digits + '.-'):
	for c in s:
		if c not in valid_characters:
			return False
	return True

def parse_email(email):
	if email.count('@') != 1: raise InvalidEmail()
	name, host = email.split('@')

	if not name or not host:
		raise InvalidEmail()
	if not only_valid_chars(name) or not only_valid_chars(host):
		raise IllegalCharacter()
	return name, host

def profile_for(email):
	parse_email(email)
	return 'email=' + email + '&uid=10&role=user'

key = os.urandom(16)

def oracle(email):
	return aes.encrypt_ecb(profile_for(email), key)

def is_admin(encrypted_profile):
	profile = parse_query_string(aes.decrypt_ecb(encrypted_profile, key))
	return 'admin' in profile['role']

def gain_admin():
	block_size = 16

	#get AES-ECB("email=" + userame + "@" + host + &uid=10&role=")
	host = 'adrianstoll.com'
	len1 = len('email=' + '@' + host + '&uid=10&role=')
	pad_len = block_size - (len1 % block_size)
	#pick username so that string is multiple of block length
	username = 'a'*pad_len

	c1 = oracle(username + '@' + host)[: len1 + pad_len]

	#get AES-ECB("admin&uid=10&role=...")
	#determine length of username so that "admin&..." is at start of block
	#when the following is encrypted:
	#email=aaaaa.....aa@b.|admin&uid=10&role=...

	len2 = len('email=' + '@b.')
	pad_len = block_size - (len2 % block_size)
	c2 = oracle('a'*pad_len + '@b.admin')[len2 + pad_len:]
	ct = c1 + c2
	print username + '@' + host
	print ct.encode('hex')
	return ct

def test_profile_for():
	assert(profile_for('hi@bye.com') == 'email=hi@bye.com&uid=10&role=user')

def test_parse_email():
	try:
		parse_email('hi@b@c.com')
		assert(False)
	except InvalidEmail:
		pass
	else:
		assert(False)
	assert(parse_email('a@b.com') == ('a', 'b.com'))
	try:
		parse_email('foo@bar.com&role=admin')
		assert(False)
	except IllegalCharacter:
		pass
	else:
		assert(False)

def testParseQueryString():
	assert(parse_query_string("a=1&b=2&c=3") == {'a':['1'],'b':['2'],'c':['3']})
	assert(parse_query_string("key=value") == {'key':['value']})
	assert(parse_query_string("a=1&a=2&b=1") =={'a':['1','2'],'b':['1']})
	try:
		parse_query_string("hi=hi&yo=car&sf&s=t")
	except InvalidQueryString:
		pass
	else:
		assert(False)
	try:
		parse_query_string("hi=hi=7&yo=car")
	except InvalidQueryString:
		pass
	else:
		assert(False)

if __name__ == '__main__':
	testParseQueryString()
	test_parse_email()
	test_profile_for()
