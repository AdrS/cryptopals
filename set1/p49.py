from cbc_mac import cbc_mac_tag, cbc_mac_verify
from os import urandom
from urlparse import parse_qs
from util import xor


name_to_id = {
	'Alice' : 0,
	'Bob' : 1,
	'Malice': 2
}

balances = [1000, 250, 666]

key = urandom(16)

def handle_transaction(message, iv, mac):
	if len(iv) != 16 or len(mac) != 16: return

	#check mac tag
	if not cbc_mac_verify(message, key, iv, mac): return

	args = parse_qs(message)

	#check that message is of the form:
	#	from=#{from_id}&to=#{to_id}&amount=#{amount}
	expected_args = {'to', 'from', 'amount'}
	if set(args.keys()) != expected_args: return
	if not all((len(args[k]) == 1 for k in expected_args)): return

	from_id = int(args['from'][0])
	to_id = int(args['to'][0])
	amount = int(args['amount'][0])

	#check that to and from are for actual accounts
	if from_id < 0 or from_id > len(balances): return
	if to_id < 0 or to_id > len(balances): return

	#check that there is sufficient funds
	if balances[from_id] < amount: return

	#finally carry out transaction
	balances[from_id] -= amount
	balances[to_id] += amount

def generate_transaction(from_id, to_id, amount):
	m = 'from=%d&to=%d&amount=%d' % (from_id, to_id, amount)
	iv = urandom(16)
	return m, iv, cbc_mac_tag(m, key, iv)

def print_balances(heading='Balances:'):
	print heading
	for n, i in sorted(name_to_id.items()):
		print '%s: $%d' % (n, balances[i])
	print ''

if __name__ == '__main__':
	print_balances('Initial balances:')

	#Alice carries out legitimate transaction
	m, iv, tag  = generate_transaction(0, 1, 250)
	handle_transaction(m, iv, tag)

	print_balances()
	
	#Malice takes Alice's transaction and changes the to field to Malice
	m_mal = m.replace('to=1', 'to=2')
	iv_mal = xor(iv, xor(m[:16], m_mal[:16]))
	
	handle_transaction(m_mal, iv_mal, tag)

	print_balances('After Malice is evil')
