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

def fast_oracle(c, d, n, mod_len):
	p = util.bigint_to_bytes(rsa.rsa_decrypt(c, d, n))
	if p[0] != '\x02': return False

	#do full check
	#pad start with 0s so it has same length as modulus
	p = '\x00' * (mod_len - len(p)) + p
	return pkcs1.pkcs1_unpad(p, mod_len) != None

def _next_s(c, e, n, si, padding_oracle):
	'''find smallest s_{i+1} > s_i such that 2B <= sc^d (mod n) < 3B'''
	si += 1
	cp = (pow(si, e, n) * c) % n
	while not padding_oracle(cp):
		si += 1
		cp = (pow(si, e, n) * c) % n
	return si

def _step2a(c, e, n, B, padding_oracle):
	'''find smallest s_1 >= n/(3B) such that 2B <= sc^d (mod n) < 3B'''
	return _next_s(c, e, n, n/(3*B), padding_oracle)

#narrow set of intervals
def _step3(intervals, B, n, s):
	narrowed_intervals = []
	for a, b in intervals:
		#if m in [a, b] and 2B <= sm - rn < 3B for some r
		#
		#(sa - 3B + 1)/n <= r <= (sb - 2B)/n
		r_min = (s*a - 3*B + 1)/n
		r_max = (s*b - 2*B)/n

		#TODO: does rounding matter?
		#(2B + rn)/s <= m <= (3B - 1 + rn)/s
		ap = max(a, (2*B + r_min*n)/s) #TODO: should be ceil
		bp = min(b, (3*B + 1 + r_max*n)/s)

		#if new interval is non empty, keep it
		if ap <= bp:
			narrowed_intervals.append((ap, bp))
	return union_of_intervals(narrowed_intervals)
	
def decrypt(c, e, n, padding_oracle):
	#plain old ciphertext should be valid
	assert(padding_oracle(c))

	mod_len = pkcs1.num_bytes(n)
	#B = 2^8(mod_len - 2)
	B = 1 << (8*mod_len - 16)

	#messages with valid padding are in range [2B, 3B)
	#Keep track of intervals c^d (mod n) could be in
	intervals = [(2*B, 3*B - 1)]

	print 'Starting 2.a...'
	#2.a
	# Find smallest s_1 such that s_1 >= n/(3B)
	s = _step2a(c, e, n, B, padding_oracle)
	intervals = _step3(intervals, B, n, s)

	print 'Found first s', s

	#2.b
	print 'Starting 2.b...'
	while len(intervals) > 1:
		s = _next_s(c, e, n, s, padding_oracle)
		intervals = _step3(intervals, B, n, s)
	print 'Only interval left', intervals

	#2.c

if __name__ == '__main__':
	#don't want to have to wait for key generation each time
	d, e, n = (37255313119928308596958693738000904270148055374803475499902820648455212368979L, 3, 55882969679892462895438040607001356405695530651745489982532299779733176320093L)

	m = 'Hello Adrian.'
	mod_len = pkcs1.num_bytes(n)
	c = rsa.rsa_encrypt(pkcs1.pkcs1_pad(m, mod_len), e, n)
	o = lambda c: padding_oracle(c, d, n, mod_len)

	print decrypt(c, e, n, lambda c: padding_oracle(c, d, n, mod_len))
