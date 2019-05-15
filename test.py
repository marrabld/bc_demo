from tools import Miner, Validator, Block, Wallet, TARGET
from Crypto.Hash import SHA256
import pickle

block = Block()

block.transactions = [b't1', b't2', b'DAN::PaysKev::300.00']

m = Miner()

m.merkle_tree(block)

# print(block.merkle_tree)
print('Merkle root :: {}'.format(block.merkle_root))

print('Mining block :: Target difficulty {}'.format(TARGET))
m.mine(block)
print('None  :: {}'.format(block.nonce))
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
