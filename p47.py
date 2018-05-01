import pkcs1, rsa, util

def union_of_intervals(intervals):
	'''takes list of overlapping closed intervals [(a_i, b_i)] where a_i <= b_i 
	returns the union of of the intervals in sorted by a_i'''
	union = []
	#sort by left end of interval
	intervals.sort()
	i = 0
	while i < len(intervals):
		a_i, b_i = intervals[i]
		j = i + 1
		while j < len(intervals) and intervals[j][0] <= b_i:
			b_j = intervals[j][1]
			if b_j > b_i:
				b_i = b_j
			j += 1
		union.append((a_i, b_i))
		i = j
	return union

def test_union_of_intervals():
	#union of disjoint intervals is same set of intervals
	assert(union_of_intervals([(0,1), (2, 3), (4, 4)]) == [(0,1), (2, 3), (4, 4)])

	#each overlaps with previous
	assert(union_of_intervals([(0,1), (1, 2), (2, 3)]) == [(0,3)])

	#one interval contained in another
	s = [(0, 6), (1, 2), (3, 5), (7,9)]
	assert(union_of_intervals(s) == [(0,6), (7,9)])

def padding_oracle(c, d, n, mod_len):
	'''checks if PKCS #1v1.5 padding is of decryption is correct'''
	p = util.bigint_to_bytes(rsa.rsa_decrypt(c, d, n))
	#pad start with 0s so it has same length as modulus
	p = '\x00' * (mod_len - len(p)) + p
	return pkcs1.pkcs1_unpad(p, mod_len) != None

def fast_oracle(c, d, n, l, u):
	p = rsa.rsa_decrypt(c, d, n)
	return l <= p and p < u
	if p[0] != '\x02': return False

def _next_s(c, e, n, si, padding_oracle):
	'''find smallest s_{i+1} > s_i such that 2B <= sc^d (mod n) < 3B'''
	si += 1
	while not padding_oracle((pow(si, e, n) * c) % n):
		si += 1
	return si

def _step2a(c, e, n, B, padding_oracle):
	'''find smallest s_1 >= n/(3B) such that 2B <= sc^d (mod n) < 3B'''
	return _next_s(c, e, n, n/(3*B), padding_oracle)

#for testing
def assert_intervals_valid(intervals):
	has_m = False
	for a, b in intervals:
		assert(a <= b)
		if a <= M and M <= b:
			has_m = True
	assert(has_m)

#narrow set of intervals
def _step3(intervals, B, n, s):
	narrowed_intervals = []

	for a, b in intervals:
		#if m in [a, b] and 2B <= sm - rn < 3B for some r
		#
		#(sa - 3B + 1)/n <= r <= (sb - 2B)/n

		r_min = (s*a - 3*B + 1)/n + 1
		r_max = (s*b - 2*B)/n

		#TODO: does rounding matter?
		#(2B + rn)/s <= m <= (3B - 1 + rn)/s
		ap = max(a, (2*B + r_max*n)/s)
		bp = min(b, (3*B - 1 + r_min*n)/s)

		#if new interval is non empty, keep it
		if ap <= bp:
			narrowed_intervals.append((ap, bp))
	return union_of_intervals(narrowed_intervals)

def decrypt(c, e, n, padding_oracle, verbose=False):
	#plain old ciphertext should be valid
	assert(padding_oracle(c))

	mod_len = pkcs1.num_bytes(n)
	#B = 2^8(mod_len - 2)
	B = 1 << (8*mod_len - 16)

	#messages with valid padding are in range [2B, 3B)
	#Keep track of intervals c^d (mod n) could be in
	intervals = [(2*B, 3*B - 1)]

	if verbose: print 'Starting 2.a...'
	#2.a
	# Find smallest s_1 such that s_1 >= n/(3B)
	s = _step2a(c, e, n, B, padding_oracle)

	intervals = _step3(intervals, B, n, s)


	#2.b
	if verbose: print 'Starting 2.b...'
	while len(intervals) > 1:
		s = _next_s(c, e, n, s, padding_oracle)
		intervals = _step3(intervals, B, n, s)

	if verbose: print 'Only interval left', intervals

	assert(intervals)
	#only one interval left
	a, b = intervals[0]

	#2.c
	#while interval contains multiple values
	while a < b - 1:
		if verbose: print b - a
		sprev = s
		#try small values of r_i, s_i such that
		# r_i >= 2(b*s_{i - 1} - 2B)/n
		#
		#(2B + r_i*n)/b <= s_i < (3B + r_i*n)/a
		r = 2*(b*sprev - 2*B)/n

		found = False
		while not found:
			tmp = 2*B + r*n
			s = tmp/b #(2B + r_i*n)/b
			ub = (tmp + B)/a #(3B + r_i*n)/a
			while s <= ub and not found:
				#until a valid one is found
				if padding_oracle((pow(s, e, n) * c) % n):
					found = True
					break
				s += 1
			r += 1
		a, b = _step3([(a,b)], B, n, s)[0]
	return b


if __name__ == '__main__':
	#don't want to have to wait for key generation each time
	#256 bit key
	#d, e, n = (37255313119928308596958693738000904270148055374803475499902820648455212368979L, 3, 55882969679892462895438040607001356405695530651745489982532299779733176320093L)
	d, e, n = rsa._sample_params

	m = 'Hello Adrian.'
	mod_len = pkcs1.num_bytes(n)
	B = 1 << (8*mod_len - 16)

	M = util.bytes_to_bigint(pkcs1.pkcs1_pad(m, mod_len))

	c = rsa.rsa_encrypt(M, e, n)

	p = decrypt(c, e, n, lambda c: fast_oracle(c, d, n, 2*B, 3*B))
	p = util.bigint_to_bytes(p)
	#pad start with 0s so it has same length as modulus
	p = '\x00' * (mod_len - len(p)) + p
	p = pkcs1.pkcs1_unpad(p, mod_len)
	print p
	assert(p == m)
