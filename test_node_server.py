from tools import COINBASE, Miner, Validator, Block, Wallet, TARGET, MEMPOOL, FullNode, CANDIDATE_BLOCKS
import pickle

f = open('dans_wallet.pk', 'rb')
w = pickle.load(f)

ks = Wallet('Randomseedpharse')

print('==========')
print('generating some test transactions')
w.send_transaction(ks.wallet_address, '21')
ks.send_transaction(w.wallet_address, '0.002')
ks.send_transaction(w.wallet_address, '0.02')

