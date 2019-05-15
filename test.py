from tools import COINBASE, Miner, Validator, Block, Wallet, TARGET, MEMPOOL, FullNode, CANDIDATE_BLOCKS
from Crypto.Hash import SHA256
import pickle
import jsonpickle

block = Block()

block.transactions = [b't1', b't2', b'DAN::PaysKev::300.00']

m = Miner()

m.merkle_tree(block)

# print(block.merkle_tree)
print('Merkle root :: {}'.format(block.merkle_root))

print('Mining block :: Target difficulty {}'.format(TARGET))
m.mine(block)
print('Nonce  :: {}'.format(block.nonce))
print('validating block :: {}'.format(block.hash))
v = Validator()
print(v.validate(block))

print('==========')

# w = Wallet('Dan')
f = open('dans_wallet.pk', 'rb')
w = pickle.load(f)

print('Public key :: {}'.format(w.pub_key))
print('Private key :: {}'.format(w.priv_key))
print('Wallet address :: {}'.format(w.wallet_address))
print('Checking to confirm wallet address')

h = SHA256.new()
h.update(w.pub_key)
print(h.hexdigest())
print('==========')

print('signing transactions')
sig = w.sign_transaction('TEST')
print(sig)
print('==========')

print('Verifying transactions')
verify = w.verify_sig('TEST', sig, w.pub_key)
print(verify)
print('==========')

f = open('dans_wallet.pk', 'wb')
pickle.dump(w, f)

print('Encrypting message')
digest = w.encrypt_message('TESTicles')
print(digest.hex())
print('==========')

print('Decrypting message')
message = w.decrypt_message(digest)
print(message)


print('==========')
print('making transaction')
t = w.send_transaction('Shiv', '100')
print(t)

print('==========')
print('validating transaction block')
print(v.validate_transaction(t))


print('==========')
print('generating some test transactions')
w.send_transaction('Kev', '1')
w.send_transaction('Kat', '2')
w.send_transaction('Shv', '3')
w.send_transaction('Bec', '4')
w.send_transaction('Rob', '5')
w.send_transaction('And', '6')

print(MEMPOOL)

full_node = FullNode()

full_node.gen_candidate_block()

for item in CANDIDATE_BLOCKS:
    print(item.merkle_root)

#print(v.validate(CANDIDATE_BLOCKS[0]))
jp = jsonpickle.encode(CANDIDATE_BLOCKS)

print(jp)

import json

f = open('candidate_blocks.json', 'w')
json.dump(jp, f, indent=4)

print(w.priv_key.hex())

w.print_wallet()

print(COINBASE)

print('end')

