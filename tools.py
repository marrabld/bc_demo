import hashlib
import copy
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

TARGET = 2
DEBUG = 2

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class Block:

    def __init__(self):
        """
        A structure for holding the block data
        """
        self.hash = None
        self.transactions = {}
        self.prev_hash = None
        self.blk_num = None
        self.nonce = 0
        self.merkle_root = None
        self.transactions_signatures = {}


class Miner:
    def __init__(self):
        """

        """

        self._merkle_tree = []
        self._merkle_root = None

    def merkle_tree(self, block):
        """

        This is strictly a merkle chain ATM

        :param block:
        :return:
        """

        m = hashlib.sha256()

        for ii, item in enumerate(block.transactions):
            m.update(item)
            self._merkle_tree.append(m.hexdigest())

        block.merkle_root = m.hexdigest()

    def mine(self, block):
        """

        :param block:
        :return:
        """

        target_nonce = 0

        while target_nonce >= 0:
            if DEBUG > 1:
                print(target_nonce)
            m = hashlib.sha256()
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

        candidate_t = {}
        candidate_t['to'] = transaction['to']
        candidate_t['coins'] = transaction['coins']

        digest = SHA256.new()
        digest.update(str(candidate_t).encode())

        # Load public key and verify message
        verifier = PKCS1_v1_5.new(RSA.importKey(transaction['pub_key']))
        verified = verifier.verify(digest, transaction['sig'])
        return verified




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

    def encrypt_message(self, message):
        """

        :param message:
        :return:
        """

        message = pad(message)
        message = b64encode(message.encode())

        rsakey = RSA.importKey(self.priv_key)
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

        transaction = {}

        transaction['to'] = to
        transaction['coins'] = coins
        sig = self.sign_transaction(transaction)
        transaction['pub_key'] = self.pub_key
        transaction['from'] = self.wallet_address
        transaction['sig'] = sig

        return transaction

    @staticmethod
    def verify_sig(transaction, sig, pub_key):

        digest = SHA256.new()
        digest.update(str(transaction).encode())

        # Load public key and verify message
        verifier = PKCS1_v1_5.new(RSA.importKey(pub_key))
        verified = verifier.verify(digest, sig)
        return verified


class Ledger:
    """
    This is essentially the blockchain and utilities for interacting with it.
    """

    def __init__(self):
        """

        """
        pass
