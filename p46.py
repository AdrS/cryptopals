import base64, rsa, util

def oracle(ct, d, n):
	'''checks if parity of plaintext is even'''
	return rsa.rsa_decrypt(ct, d, n) % 2 == 0

def decrypt(c, e, n, parity_oracle):
	'''compute c^d (mod n) given access to parity oracle
	Note: this can be used for decryption AND signing
	'''
	lower = 0
	# upper = lower + 1
	i = 0

	#invariants:
	# 1) 0 <= lower < upper <= 2^i
	# 2) upper - lower = 1
	# 3) m in [n*lower/2^i, n*upper/2^i]

	pow2i = 1 #2^i
	while pow2i < n:
		# 3) ==> 2^i*m in [n*lower, n*upper]
		# 2) ==> 2^i*m in [n*lower, n*(lower + 1)]
		#    ==> 2^i*m - n*lower in [0, n]

		# 2^(i + 1)*m in [2n*lower, 2n*upper]
		# 2^(i + 1)*m in [2n*lower, 2n*lower + 2n]

		#case I: 2^(i + 1)*m in [2n*lower, 2n*lower + n]
		# ==> 2^(i + 1)*m  - 2n*lower in [0, n]
		# ==> 2*2^i*m is even mod n

		#case II: 2^(i + 1)*m in [2n*lower + n, 2n*lower + 2n]
		# ==> 2^(i + 1)*m  - 2n*lower in [n, 2n]
		# ==> 2^(i + 1)*m  - 2n*lower - n in [0, n]
		# ==>     " " mod n = even - odd = odd mod n
		# ==> 2*2^i*m is odd mod n

		#(2^i * m)^e = (2^i)^e * c (mod n)
		pow2i <<= 1
		cur = (pow(pow2i, e, n) * c) % n

		#case I
		if parity_oracle(cur):
			# 2^(i + 1)*m  - 2n*lower in [0, n]
			# ==> 2^(i + 1)*m in [n*(2*lower), n*(2*lower) + n]
			# lower_{i + 1} = 2*lower
			# upper_{i + 1} = 2*lower + 1
			# Note: invariant 2 still holds
			# 
			# ==> 2^(i + 1)*m in [n*lower_{i + 1}, n*(lower_{i + 1} + 1)]
			# ==> m in [n*lower_{i + 1}/2^(i + 1), n*upper_{i + 1}/2^(i + 1)]
			# Note: invariant 3 still holds
			lower <<= 1
		else:
			# 2^(i + 1)*m  - 2n*lower in [n, 2n]
			# ==> 2^(i + 1)*m in [n*(2*lower + 1), n*(2*lower + 2)]
			# ==> 2^(i + 1)*m in [n*(2*lower + 1), n*2*upper]
			# upper_{i + 1} = 2*upper
			# lower_{i + 1} = 2*upper - 1
			# Note: invariant 2 still holds
			# 
			# ==> 2^(i + 1)*m in [n*lower_{i + 1}, n*upper_{i + 1}]
			# ==> m in [n*lower_{i + 1}/2^(i + 1), n*upper_{i + 1}/2^(i + 1)]
			# Note: invariant 3 still holds
			#(lower + 1) * 2 - 1 = 2*lower + 1
			lower = (lower << 1) + 1
		i = i + 1
	# 2^i >= n ==>
	#The interval [n*lower/2^i, n*upper/2^i] has width <= 1
	#integer division by 2^i rounds down ==> use upper bound to find m
	return ((lower + 1)*n) >> i

if __name__ == '__main__':
	pt = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
	d, e, n = rsa._sample_params
	ct = rsa.rsa_encrypt(pt, e, n)
	
	print util.bigint_to_bytes(decrypt(ct, e, n, lambda ct: oracle(ct, d, n)))
