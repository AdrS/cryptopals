import number_theory, rsa, util

pkcs_magic_bytes = '\x00ASN.1'
prefix = '\x00\x01\xff'

def check_signature(msg, sig, e, n, bit_length=1024):
	p = util.bigint_to_bytes(rsa.rsa_encrypt(sig, e, n))
	if len(p) > bit_length/8: return False

	#pad to bit_length with leading 0 bytes
	if len(p) < bit_length/8:
		p = '\x00'*(bit_length/8 - len(p)) + p

	#check that s^e (mod n) starts with
	#00 01 FF FF ... FF 00  ASN.1  HASH
	#check for 00 01 FF
	if not p.startswith(prefix): return False
	pos = len(prefix)
	#move past the rest of the FFs
	while pos < len(p) and p[pos] == '\xff':
		pos += 1
	#check that there is enough space for 00 ASN.1 HASH
	if pos + len(pkcs_magic_bytes) + 20 > len(p): return False
	#check for 00 ASN.1
	if p[pos : pos + len(pkcs_magic_bytes)] != pkcs_magic_bytes:
		return False
	pos += len(pkcs_magic_bytes)
	#check that hash matches message
	return p[pos: pos + 20] == util.sha1sum(msg)

def pkcs1_pad(msg, bit_length=1024):
	h = util.sha1sum(msg)
	bit_length /= 8
	bit_length -= len(prefix)
	bit_length -= len(h)
	bit_length -= len(pkcs_magic_bytes)
	#check that there is enought space
	if bit_length < 0: return None
	return ''.join([prefix, '\xff'*bit_length, pkcs_magic_bytes, h])

def test_check_signature(d,e,n):
	msg = "hello Bob"
	padded = pkcs1_pad(msg)
	sig = rsa.rsa_decrypt(padded, d, n)
	assert(check_signature(msg, sig, e, n))
	assert(not check_signature("hello Alice", sig, e, n))

def forge(msg, bit_length=1024):
	#find x such that x^3 ~= 00 01 FF 00 ASN.1 HASH garbage padding
	evil = prefix + pkcs_magic_bytes + util.sha1sum(msg)
	pad = '\x01' * (bit_length/8 - len(evil))
	target = util.bytes_to_bigint(evil + pad)
	return number_theory.ith_root(target, 3)

def test_forge(e, n):
	msg = "Hello Mallory"
	sig = forge(msg)
	assert(check_signature(msg, sig, e, n))

if __name__ == '__main__':
	#d, e, n = rsa.gen_key_pair(1024)
	#don't want to wait to generate key pair
	d, e, n = (111362286410211583669725041748624015357015789920103016229885764684530821371586941962831815326506479749001616409906800547275431285766694970292540991623633822700408019631094608796497093656659564366838349269038200838176792713390842709111079260436382859247229353043625367114615775993991276917586476130163934190371L, 3, 167043429615317375504587562622936023035523684880154524344828647026796232057380412944247722989759719623502424614860200820913146928650042455438811487435450759902502377024707831573474592372202008245491689999576946888508161524416942544195053500973486143761844643232694997008489565006093697359038427190720833724177L)

	#d, e, n = (5421820438447543415409225204884933201685568232841740855404513529747835743693594542794970589795992409782893463228056435073394561591889192636642698529174963L, 3, 8132730657671315123113837807327399802528352349262611283106770294621753615540574477715853894899095018766021907794867796639189149519133201569564120308610069L)
	test_check_signature(d,e,n)
	test_forge(e,n)
