import random
import math

def gcd(a,b):
	#TODO: write non recursive version
	if b == 0: return a
	return gcd(b, a % b)

def extended_euclid(a,b):
	#return g, s, t such that g = sa + tb
	#see: https://www.csee.umbc.edu/~chang/cs203.s09/exteuclid.shtml
	#see: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
	#	for non recursive version

	#gcd(a, 0) = a = 1*a + 0*b
	if b == 0:
		return a, 1, 0

	#write a = qb + r where  r = (a mod b)
	#==> r = a - qb
	q = a/b
	#gcd(a, b) = gcd(b, a mod b) = xb  + y(a mod b)
	g, x, y = extended_euclid(b, a % b)
	#==>
	#gcd(a, b) = xb + y(a - qb) = ya + (x - yq)b
	return g, y, (x - y*q)

def mod_inv(a, n):
	'''computes a^(-1) mod n if gcd(a,n) = 1 otherwise returns None
	returns inverse in range (0, n)
	'''
	g, x, y = extended_euclid(a, n)
	#gcd(a,n) = g = xa + yn 
	#a only has modular inverse if it is relatively prime with n
	if g != 1:
		return None
	#1 = gcd(a,n) = g = xa + yn  ==> xa = 1 (mod n)
	#ensure 0 < x < n
	while x < 0:
		x += n
	while x >= n:
		x -= n
	return x

def crt(a, n):
	'''Use the Chinese Remainder Theorem to find a solution to the series
	of congruences x_i = a_i (mod n_i) where gcd(n_i, n_j) = 1 for i != j
	Solution X is in range [0, Pi_{i} n_i)
	'''
	#Let N = product of n_is
	N = 1
	for n_i in n:
		N *= n_i
	#Let N_i = N/n_i
	Ni = [N/n_i for n_i in n]

	#Let b_i = N_i^(-1) (mod n_i) [existence of inverses guaranteed by fact that
	#the n_is are pairwise relatively prime
	b = [mod_inv(N_i, n_i) for N_i, n_i in zip(Ni, n)]

	#X = sum a_i*b_i*N_i is unique solution (modulo N) to system of congruences
	X = sum((a_i*b_i*N_i for a_i, b_i, N_i in zip(a, b, Ni))) % N
	return X

def ith_root(x, n):
	#find nth root of x using binary search
	#see: https://en.wikipedia.org/wiki/Talk%3ANth_root_algorithm
	#for other methods
	#TODO: test this more
	low, high = 1, x

	while low < high - 1:
		mid = (low + high)/2
		mid_cubed = mid ** n
		if mid_cubed < x:
			low = mid
		elif mid_cubed > x:
			high = mid
		else:
			return mid
	return low

def _test_gcd():
	assert(gcd(123, 123) == 123)
	assert(gcd(0, 123) == 123)
	assert(gcd(5*123, 123) == 123)
	assert(gcd(127, 33) == 1)
	assert(gcd(81, 33) == 3)
	assert(gcd(81, 512) == 1)

def _test_extended_euclid():
	assert(extended_euclid(123, 0) == (123, 1, 0))
	assert(extended_euclid(0, 123) == (123, 0, 1))
	assert(extended_euclid(99, 78) == (3, -11, 14))
	assert(extended_euclid(99, 78) == (3, -11, 14))

def _test_mod_inv():
	assert(mod_inv(78, 99) == None)
	assert(mod_inv(13, 60) == -23 + 60)

############ Primarily testing ######################## 
def fermat_test(n, trials=128):
	'''
	probabilistic test to see if n is prime
	for prime n, always returns True
	for random composite n, returns False with probability
	>= 1 - 1/2^trials
	'''
	#Fermat's little theorem:
	#if p is prime then a^n = a (mod n) for 0 < a < n

	#if n is odd then (n - 1)^n = (-1)^n = n - 1 (mod n)
	#if a = 1 then a^n = 1^n = 1 no matter the value of n
	#==> should only text for a in [2, n - 1)

	for _ in range(trials):
		a = random.SystemRandom().randrange(2, n - 1)
		if pow(a, n, n) != a:
			return False
	return True

def is_small_prime(n):
	'''primarily test for small integers'''
	if n % 2 == 0:
		return n == 2
	i = 3
	while i <= math.sqrt(n):
		if n % i == 0:
			return False
		i += 2
	return True

def sieve_of_eratosthenese(n):
	'''find all odd prime numbers <= n'''
	#only keep track of odd numbers
	l = int(math.ceil(n/2.0)) + 1

	#to check if i is prime, look at index (i - 1)/2
	nums = [True]*l
	primes = [2]
	upper_limit =  int(math.ceil(math.sqrt(n))) + 1
	#skip evens
	for i in range(3, upper_limit, 2):
		if nums[(i - 1)/2]:
			primes.append(i)
			#Start at i^2:
			#all composite numbers < i^2 have prime factor < i
			#==> they have already been marked as composite
			#
			#Count in increments of 2*i because every other multiple #is even
			for j in range(i*i, n + 1, 2*i):
				nums[(j - 1)/2] = False

	start_of_rest = upper_limit
	#ensure start of rest is odd
	if start_of_rest % 2 == 0:
		start_of_rest += 1
	for i in range(upper_limit, n + 1, 2):
		if nums[(i - 1)/2]:
			primes.append(i)
	return primes

#cache list of small primes to speed up search
_small_primes = []

def _ensure_small_primes_loaded():
	global _small_primes
	if not _small_primes:
		#loads first ~82k primes
		_small_primes = sieve_of_eratosthenese((1<<20))

def is_prime(n):
	'''tests if n is a prime'''
	global _small_primes
	_ensure_small_primes_loaded()
	#check divisibility by small primes to filter out most composites
	for p in _small_primes:
		if n % p == 0:
			return n == p
	if n <= _small_primes[-1]**2:
		return True
	
	#use Fermat's primarily test
	return fermat_test(n)

def find_prime(bit_length):
	'''finds a prime with given bit length'''
	upper_bound = (1<<bit_length)
	#lower bound is to prevent small primes from being found
	lower_bound = (1<<(bit_length - 1))
	rand = random.SystemRandom()
	while True:
		n = rand.randrange(lower_bound, upper_bound)
		#convert even to odd
		if n % 2 == 0:
			n += 1
		if is_prime(n):
			return n

def find_strong_prime(bit_length):
	'''finds a prime of the form p = aq + 1 for prim q and small a
	Note: this guarantees that p - 1 will have no small factors besides a'''
	#see: https://people.csail.mit.edu/rivest/pubs/RS01.version-1999-11-22.pdf
	#Rivest Are Strong Primes Need for RSA? Section 5
	q = find_prime(bit_length - 1)
	p = 2*q + 1
	two_q = 2*q
	while not is_prime(p):
		p += two_q
	return p
	#Timing from a laptop i5
	#$ time python -c "import number_theory as nt; nt.find_strong_prime(1024)"
	#real    0m27.405s
	#user    0m27.016s
	#sys     0m0.266s

def find_safe_prime(bit_length):
	'''find prime of the form p = 2q + 1 where q is prime'''
	while True:
		q = find_prime(bit_length - 1)
		n = 2*q + 1
		if is_prime(n):
			return n

def _test_is_small_prime():
	assert(is_small_prime(2))
	assert(is_small_prime(3))
	assert(not is_small_prime(4))
	assert(is_small_prime(5))
	assert(not is_small_prime(6))
	assert(is_small_prime(7))
	assert(not is_small_prime(8))
	assert(not is_small_prime(7*13))
	assert(is_small_prime(127))

def _test_sieve_of_eratosthenese():
	assert(sieve_of_eratosthenese(31) == [2,3,5,7,11,13,17,19,23,29,31])

def _test_is_prime():
	assert(is_prime(3))
	assert(not is_prime(4))
	assert(is_prime(5))
	assert(not is_prime(6))
	assert(is_prime(7))
	assert(not is_prime(8))
	assert(not is_prime(7*13))
	assert(is_prime(127))
	#source: http://www.bigprimes.net/archive/prime/101/
	assert(is_prime(104743))
	assert(is_prime(105023))
	assert(is_prime(105359))
	assert(is_prime(105613))
	assert(is_prime(179424691))
	assert(is_prime(179425033))
	assert(is_prime(179425601))
	assert(is_prime(179426083))

	#test on large composites
	assert(not is_prime(104743 * 105023))
	assert(not is_prime(179425601 * 179426083))

	#test on 512 bit prime
	#from http://jensign.com/JavaScience/dotnet/CSPPrimes/index.html
	assert(is_prime(13144131834269512219260941993714669605006625743172006030529504645527800951523697620149903055663251854220067020503783524785523675819158836547734770656069477))

if __name__ == '__main__':
	_test_gcd()
	_test_extended_euclid()
	_test_mod_inv()
	_test_is_small_prime()
	_test_sieve_of_eratosthenese()
	_test_is_prime()
