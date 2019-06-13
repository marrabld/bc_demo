import hashlib
import copy
import os

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
import pyqrcode
import socket
import json

TARGET = 3
DEBUG = 2

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

MEMPOOL = []
CANDIDATE_BLOCKS = []
COINBASE = 20000
BLOCK_LIMIT = 3


class Validator:
    @staticmethod
    def validate(block):
        """
        Checks that the nonce is less than our target and the equal to the block hash

        :param block:
        :return:
        """
        m = hashlib.sha256()
        m.update(str(block.merkle_root).encode('utf-8'))
        m.update(str(block.nonce).encode('utf-8'))

        candidate_hash = m.hexdigest()
        return candidate_hash == block.hash

    @staticmethod
    def validate_transaction(transaction):
        """

        :return:
        """

        '''
        transaction = {}

        transaction['to'] = to
        transaction['coins'] = coins
        sig = self.sign_transaction(transaction)
        transaction['pub_key'] = self.pub_key
        transaction['from'] = self.wallet_address
        transaction['sig'] = sig
        '''

        valid_wallet = False
        h = SHA256.new()
        h.update(transaction['pub_key'])
        h.hexdigest()
        wallet_address = h.hexdigest()

        valid_wallet = (wallet_address == transaction['from'])

        candidate_t = {}
        candidate_t['to'] = transaction['to']
        candidate_t['coins'] = transaction['coins']

        digest = SHA256.new()
        digest.update(str(candidate_t).encode())

        # Load public key and verify message
        verifier = PKCS1_v1_5.new(RSA.importKey(transaction['pub_key']))
        verified = verifier.verify(digest, transaction['sig'])

        return verified and valid_wallet


class Miner:
    def __init__(self):
        """

        """

        self._merkle_tree = []
        self._merkle_root = None
        self.ledger = Ledger()

    def merkle_tree(self, block):
        """

        This is strictly a merkle chain ATM

        :param block:
        :return:
        """

        m = hashlib.sha256()

        for ii, item in enumerate(block.transactions):
            m.update(str(item).encode())
            self._merkle_tree.append(m.hexdigest())

        merkle_root = m.hexdigest()
        block.merkle_root = merkle_root
        return merkle_root

    def mine(self, block, last_hash):
        """

        :param block:
        :param last_hash:
        :return:
        """

        target_nonce = 0

        while target_nonce >= 0:
            if DEBUG > 1:
                print('=====================================')
                print(' Mining :: Target Nonce :: {}'.format(target_nonce))
                print('=====================================')
                # print(chr(27) + "[2J")
                # os.system('cls' if os.name == 'nt' else 'clear')
            m = hashlib.sha256()
            m.update(str(last_hash).encode('utf-8'))
            m.update(str(block.merkle_root).encode('utf-8'))
            m.update(str(target_nonce).encode('utf-8'))
            hsh = m.hexdigest()

            if '0' * TARGET in hsh[0:TARGET]:
                block.nonce = target_nonce
                block.hash = hsh
                target_nonce = -1  # escape condition

            else:
                target_nonce += 1

            if target_nonce >= 100000000:  # stop race condition
                target_nonce = -1

        # COINBASE -= 10


class Block:

    def __init__(self):
        """
        A structure for holding the block data
        """
        self.hash = None
        self.transactions = []
        self.prev_hash = None
        self.blk_num = None
        self.nonce = 0
        self.merkle_root = None

    def __str__(self):
        return "HASH {}".format(self.hash)


class Ledger:
    """
    This is essentially the blockchain and utilities for interacting with it.
    """

    def __init__(self):
        """

        """
        self.block_chain = []

    def __str__(self):
        """
        print out the entire blockchain
        :return:
        """

        str = ''
        for item in self.block_chain:
            str += ' Hash {} \n\t'.format(item.hash)
            str += ' Block Number {} \n\t'.format(item.blk_num)
            str += ' Transactions \n\t\t'
            for tt_item in item.transactions:
                str += (' {} \n\t\t'.format(tt_item))
            str += '\b Prev_hash {} \n\t'.format(item.prev_hash)
            str += ' Merkle root {} \n\t'.format(item.merkle_root)
            str += ' Nonce {} \n\t'.format(item.nonce)
            str += '\n'

        return str

    def add_block(self, block):
        """

        :return:
        """
        if block.prev_hash == 0:  # Genesis block
            self.block_chain = []
            block.blk_num = 0
            self.block_chain.append(block)  ##  Danger.  could spoof this to whipe itself

        elif block.prev_hash == self.block_chain[-1].hash:
            block.blk_num = self.block_chain[-1].blk_num + 1
            self.block_chain.append(block)

        else:
            print('Not a valid block omitting')

    def last_block(self):
        """

        :return:
        """
        try:
            return self.block_chain[-1].hash
        except:
            return 0  # must be the genesis block

    def export(self):
        """
        Pickle the ledger
        :return:
        """
        #f = open('ledger.pk', 'wb')
        #pickle.dumps(Le, f )


class FullNode:
    def __init__(self):
        """

        :return:
        """
        self.v = Validator()
        self.m = Miner()
        self.l = Ledger()

    def gen_candidate_block(self):
        """
        A full node will mine and validate
        """
        b = Block()

        while len(MEMPOOL) > 0:
            t = MEMPOOL.pop()
            # MEMPOOL.remove(t)
            if self.v.validate_transaction(t):
                b.transactions.append(t)
            else:
                print('Validation failed on {}'.format(t))

        if len(self.l.block_chain) == 0:  # genesis block
            b.prev_hash = 0
        else:
            b.prev_hash = self.l.last_block()

        b.merkle_root = self.m.merkle_tree(b)

        self.m.mine(b, self.l.last_block())

        CANDIDATE_BLOCKS.append(b)

    def ledger_to_balance(self):
        """
        This takes in the full ledger and only returns the balance of all wallets

        :return:
        """
        balance = {}

        for item in self.l.block_chain:
            #  Check if the address exists
            for t in item.transactions:
                if not balance[t['to']]:
                    balance[t['to']] = t['coins']
                elif balance[t['to']]:
                    balance[t['to']] += t['coins']

        return balance


class Wallet:
    """
    A class for generating keys
    """

    def __init__(self, seed=None):
        """
        If we pass a seed then generate a new wallet, else make an empty wallet we can import the keys

        """

        if seed is None:
            self.seed = seed
            self.priv_key = None
            self.pub_key = None
            self.wallet_address = None
        else:
            key = RSA.generate(2048)
            self.priv_key = key.exportKey()
            self.pub_key = key.publickey().exportKey()

            h = SHA256.new()
            h.update(self.pub_key)
            h.hexdigest()
            self.wallet_address = h.hexdigest()

    def sign_transaction(self, transaction):
        """

        :param transaction:
        :return:
        """

        digest = SHA256.new()
        digest.update(str(transaction).encode('UTF-8'))

        signer = PKCS1_v1_5.new(RSA.importKey(self.priv_key))
        sig = signer.sign(digest)
        return sig

    def encrypt_message(self, message, pub_key):
        """

        :param message:
        :return:
        """

        message = pad(message)
        message = b64encode(message.encode())

        rsakey = RSA.importKey(self.pub_key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.encrypt(message)

        return encrypted

    def decrypt_message(self, digest):
        """

        :param digest:
        :return:
        """

        from base64 import b64decode
        key = self.priv_key
        rsakey = RSA.importKey(key)
        rsakey = PKCS1_OAEP.new(rsakey)
        decrypted = rsakey.decrypt(digest)

        return unpad(b64decode(decrypted))

    def send_transaction(self, to, coins):
        """

        :param to:
        :param coins:
        :return:
        """

        import pickle as pickle

        # data_string = pickle.dumps(data, -1)

        transaction = {}

        transaction['to'] = to
        transaction['coins'] = coins
        sig = self.sign_transaction(transaction)
        transaction['pub_key'] = self.pub_key
        transaction['from'] = self.wallet_address
        transaction['sig'] = sig

        HOST = '127.0.0.1'  # The server's hostname or IP address
        PORT = 65432  # The port used by the server

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.sendall(pickle.dumps(transaction))
                # s.sendall(b'TEST')
                data = s.recv(1024)
                print(repr(data))
        except:
            s.close()

        MEMPOOL.append(transaction)

        return transaction

    @staticmethod
    def verify_sig(transaction, sig, pub_key):

        digest = SHA256.new()
        digest.update(str(transaction).encode())

        # Load public key and verify message
        verifier = PKCS1_v1_5.new(RSA.importKey(pub_key))
        verified = verifier.verify(digest, sig)
        return verified

    def print_wallet(self):
        """

        :return:
        """
        wallet_address = pyqrcode.create(self.wallet_address)
        wallet_address.png('address.png', scale=6, module_color=[0, 0, 0, 128], background=[0xff, 0xff, 0xcc])

        private_key = pyqrcode.create(self.priv_key.hex()[0:60])  ## pk is too long for qrcode.
        private_key.png('{}_pivate_key.png'.format(self.wallet_address[0:6]), scale=600, module_color=[0, 0, 0, 128],
                        background=[0xff, 0xff, 0xcc])


class Crypto:
    @staticmethod
    def make_hash(self, o):

        """
        Makes a hash from a dictionary, list, tuple or set to any level, that contains
        only other hashable types (including any lists, tuples, sets, and
        dictionaries).
        """

        if isinstance(o, (set, tuple, list)):

            return tuple([self.make_hash(e) for e in o])

        elif not isinstance(o, dict):

            return hash(o)

        new_o = copy.deepcopy(o)
        for k, v in new_o.items():
            new_o[k] = self.make_hash(v)

        return hash(tuple(frozenset(sorted(new_o.items()))))
