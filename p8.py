
def load_cts(path='8.txt'):
	with open(path,'r') as f:
		return [l.strip().decode('hex') for l in f]

def get_blocks(ct):
	assert(len(ct) % 16 == 0)
	return [ct[i: i + 16] for i in range(0, len(ct), 16)]

def num_repeat_blocks(ct):
	'''returns number of blocks in cipher text that have appeared before'''
	return len(ct)/16 - len(set(get_blocks(ct)))

def detect_ecb(cts):
	res = [(num_repeat_blocks(ct)*16.0/len(ct), ct) for ct in cts]
	#use number of repeated blocks as metric of likelyhood of ecb use
	res.sort(key=lambda x: x[0], reverse=True)
	return res

def test_get_blocks():
	assert(get_blocks('') == [])
	assert(get_blocks('a'*16) == ['a'*16])
	assert(get_blocks('a'*16 + 'b'*16) == ['a'*16, 'b'*16])

def test_num_repeat_blocks():
	assert(num_repeat_blocks('a'*16 + 'b'*16 + 'c'*16) == 0)
	assert(num_repeat_blocks('a'*16 + 'b'*16 + 'a'*16) == 1)
	assert(num_repeat_blocks('a'*16 + 'b'*16 + 'a'*16 + 'b'*16) == 2)
	assert(num_repeat_blocks('a'*16 + 'a'*16 + 'a'*16 + 'b'*16) == 2)

if __name__ == '__main__':
	test_get_blocks()
	test_num_repeat_blocks()
