import base64, rsa, util

def oracle(ct, d, n):
	'''checks if parity of plaintext is even'''
	return rsa.rsa_decrypt(ct, d, n) % 2 == 0

def decrypt(ct, e, n, parity_oracle):
	high = n
	low = 0

	#TODO: does not get last byte
	i = 1
	while low < high:
		#(2^i)^e * c = (2^i * m)^e (mod n)
		#            = (m << i)^e (mod n)
		cur = (pow((1<<i), e, n) * ct) % n

		mid = (high + low)/2

		#low <= m <= high <= n
		#==>
		#(low << i) <= (m << i) <= (high << i) <= (n << i)

		if parity_oracle(cur):
			high = mid
		else:
			low = mid

		print util.bigint_to_bytes(high)
		i += 1

		#if 2m > n ==> 2n > 2m > n
		#==> 2m mod n = 2m - n
		#==> 2m is odd (mod n)

		#if 2m < n ==> 2m mod n = 2m ==> 2m is even mod n
		#n is odd => don't have to consider case 2m = n

		#find enc(2m mod n)
		#2^e*c = 2^e*m^e = (2m)^e (mod n)
	return util.bigint_to_bytes(high)

if __name__ == '__main__':
	pt = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
	d, e, n = rsa._sample_params
	ct = rsa.rsa_encrypt(pt, e, n)
	
	print decrypt(ct, e, n, lambda ct: oracle(ct, d, n))
