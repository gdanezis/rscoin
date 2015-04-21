from base64 import b64encode, b64decode
from binascii import hexlify

from bisect import bisect_left
import bsddb
from traceback import print_stack, print_exc
from hashlib import sha256


from twisted.internet import protocol
from twisted.protocols.basic import LineReceiver

import rscoin

class RSCProtocol(LineReceiver):
    def __init__(self, factory):
        self.factory = factory

    def parse_Tx_bundle(self , bundle_items, items):
        assert len(items) == bundle_items
        H = sha256(" ".join(items)).digest()

        items = map(b64decode, items)
        mainTx = rscoin.Tx.parse(items.pop(0))

        otherTx, keys, sigs = [], [], []
        if len(mainTx.inTx) > 0:
                    size = len(mainTx.inTx)
                    for _ in range(size):
                        otherTx += [items.pop(0)]
                    for _ in range(size):
                        keys += [items.pop(0)]
                    for _ in range(size):
                        sigs += [items.pop(0)]
        elif len(mainTx.inTx) == 0:
                    keys += [items.pop(0)]
                    sigs += [items.pop(0)]

        assert len(items) == 0
        
        return H, (mainTx, otherTx, keys, sigs)


    def handle_Query(self, items):
        bundle_size = int(items[1])

        try:
            items = items[2:2+bundle_size]
            H, data = self.parse_Tx_bundle( bundle_size, items)
            (mainTx, otherTx, keys, sigs) = data

            # Specific checks
            assert len(otherTx) > 0
            assert len(items[2+bundle_size:]) == 0

        except Exception as e:
            print_exc()
            self.return_Err("ParsingError")
            return 

        try:            
            # Check the Tx Query
            res = self.factory.process_TxQuery(data)
        except Exception as e:
            print_exc()
            self.return_Err("QueryError")
            return 

        # If Query failed
        if not res:
            self.sendLine("NOTOK" )

        self.sendLine("OK %s" % self.sign(H))
        return

    def handle_Commit(self, items):
        bundle_size = int(items[1])

        try:
            extras = items[2+bundle_size:] 
            items = items[2:2+bundle_size]
            H, data = self.parse_Tx_bundle( bundle_size, items)
            (mainTx, otherTx, keys, sigs) = data

            # Specific checks
            assert len(items[2+bundle_size:]) == 0

            auth_keys, auth_sigs = [], []
            while len(extras) > 0:
                auth_keys += [ b64decode(extras.pop(0)) ]
                auth_sigs += [ b64decode(extras.pop(0)) ]

            assert len(extras) == 0            
        except:
            print_exc()
            self.return_Err("ParsingError")
            return

        data = (H, mainTx, otherTx, keys, sigs, auth_keys, auth_sigs)
        res = self.factory.process_TxCommit(data)

        if not res:
            self.sendLine("NOTOK")

        h = mainTx.id()
        ret = self.sign(h)
        self.sendLine("OK %s" % ret)


    def lineReceived(self, line):
        items = line.split(" ")
        if items[0] == "Query":
            return self.handle_Query(items) # Get signatures           

        if items[0] == "Commit":
            return self.handle_Commit(items) # Seal a transaction

        self.return_Err("UnknownCommand")
        return

    def sign(self, H):
        k = self.factory.key
        pub = k.pub.export()
        sig = k.sign(H)
        return " ".join(map(b64encode, [pub, sig]))


    def return_Err(self, Err):
        self.sendLine("Error %s" % Err)


class RSCFactory(protocol.Factory):
    def __init__(self, secret, directory, special_key):
        self.special_key = special_key
        self.key = rscoin.Key(secret, public=False)
        self.directory = sorted(directory)
        keyID = self.key.pub.export()[:10]

        # Open the databases
        self.dbname = 'keys-%s.db' % hexlify(keyID)
        self.db = bsddb.btopen(self.dbname, 'c')
        self.logname = 'log-%s.db' % hexlify(keyID)
        self.log = bsddb.btopen(self.logname, 'c')

    
    def buildProtocol(self, addr):
        cli = RSCProtocol(self)
        return cli


    def process_TxQuery(self, data):
        """ Queries a full transaction and gets a signed response if it is valid. 

            When I get a query:
            * Check that the signatures check.
            * Check the input addresses are in the utxo.
            * Check that they are not used, or used for same.
            * Add to spent transactions.
            * Remove from utxo.

        """
        mainTx, otherTx, keys, sigs = data
        mid = mainTx.id()
        inTxo = mainTx.get_utxo_in_keys()


        # Check the transaction is well formed
        all_good = mainTx.check_transaction(otherTx, keys, sigs)
        if not all_good:
            return False

        ## Check all inputs are in
        for ik in inTxo:
            ## We are OK if this is already in the log with the same mid
            if ik in self.log and self.log[ik] == mid:
                continue
            ## Otherwise it should not have been used yet
            elif ik not in self.db:
                return False

        # Once we know all is good we proceed to remove them
        # but write the decision to a log
        for ik in inTxo:
            if ik in self.db:
                del self.db[ik]
            self.log[ik] = mid

        # Save before signing
        self.db.sync() 
        self.log.sync()       
        return True

    def process_TxCommit(self, data):
        """ Provides a Tx and a list of responses, and commits the transaction. """
        H, mainTx, otherTx, keys, sigs, auth_pub, auth_sig = data
        
        # First check all signatures
        all_good = True
        for pub, sig in zip(auth_pub, auth_sig):
            key = rscoin.Key(pub)
            all_good &= key.verify(H, sig)

        if not all_good:
            return False

        # Check the transaction is well formed
        all_good = mainTx.check_transaction(otherTx, keys, sigs)
        if not all_good:
            return False

        pub_set = set(auth_pub)

        # Now check all authorities are involved
        mid = mainTx.id()
        inTxo = mainTx.get_utxo_in_keys()
        for itx in inTxo:
            ## Ensure we have a Quorum for each input
            aut = set(x for x, _ , _ in self.get_authorities(itx))
            all_good &= (len(aut & pub_set) > len(aut) / 2) 
            
        if not all_good:
            return False

        ## TODO: Log all information about the transaction

        # Update the outTx entries
        for k, v in mainTx.get_utxo_out_entries():
            self.db[k] = v
        self.db.sync()

        return all_good


    def get_authorities(self, xID, N = 5):
        """ Returns the keys of the authorities for a certain xID """
        d = self.directory
        if len(d) <= N:
            return d

        i = bisect_left(d, (xID, None, None))

        return [d[(i + j - 1) % len(d)][0] for j in range(N)]



### ------------ TESTS ---------------

from twisted.test.proto_helpers import StringTransport
import os.path
from os import urandom

import pytest

@pytest.fixture
def sometx():
    secret = "A" * 32
    public = rscoin.Key(secret, public=False).pub.export()
    directory = [(public, "127.0.0.1", 8080)]

    factory = RSCFactory(secret, directory, None)
    
    # Build one transaction
    k1 = rscoin.Key(urandom(32), public=False)
    k2 = rscoin.Key(urandom(32), public=False)

    tx1 = rscoin.Tx([], [rscoin.OutputTx(k1.id(), 100)])
    tx2 = rscoin.Tx([], [rscoin.OutputTx(k2.id(), 150)])

    tx3 = rscoin.Tx([rscoin.InputTx(tx1.id(), 0), rscoin.InputTx(tx2.id(), 0)], [rscoin.OutputTx(k1.id(), 250)])
    
    for kv, vv in tx1.get_utxo_out_entries() + tx2.get_utxo_out_entries():
        factory.db[kv] = vv

    # Run the protocol
    instance = factory.buildProtocol(None)
    tr = StringTransport()
    instance.makeConnection(tr)

    return (factory, instance, tr), (k1, k2, tx1, tx2, tx3)

def test_factory():
    secret = "A" * 32
    public = rscoin.Key(secret, public=False).pub.export()
    directory = [(public, "127.0.0.1", 8080)]

    factory = RSCFactory(secret, directory, None)
    assert os.path.exists(factory.dbname)

def test_authorities():
    chars = ["A", "B", "C", "D", "E", "F"]
    directory = [(c* 32, "127.0.0.1", 8080) for c in chars]

    secret = "X"*32
    factory = RSCFactory(secret, directory, None)

    assert factory.get_authorities("AXX")[-1][0] == "E"
    assert factory.get_authorities("FXX")[-1][0] == "D"


def test_TxQuery(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx


    tx4 = rscoin.Tx([rscoin.InputTx(tx1.id(), 0)], [rscoin.OutputTx(k1.id(), 100)])


    for kv, vv in tx1.get_utxo_out_entries() + tx2.get_utxo_out_entries():
        factory.db[kv] = vv

    # Check the list is up to date
    for ik in tx3.get_utxo_in_keys():
        assert ik in factory.db

    data = (tx3, [tx1.serialize(), tx2.serialize()], 
                            [k1.export()[0], k2.export()[0]], 
                            [k1.sign(tx3.id()), k2.sign(tx3.id())])

    # Put the transaction through
    assert factory.process_TxQuery(data)

    for ik in tx3.get_utxo_in_keys():
        assert ik not in factory.db

    ## A transaction should be indepotent
    assert factory.process_TxQuery(data)
    data2 = (tx4, [tx1.serialize()], 
                            [k1.export()[0]], 
                            [k1.sign(tx3.id())])

    assert not factory.process_TxQuery(data2)

def test_TxQuery_serialize(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    # Check the list is up to date
    for ik in tx3.get_utxo_in_keys():
        assert ik in factory.db

    data = map(b64encode, [tx3.serialize(), tx1.serialize(), tx2.serialize(), 
                k1.export()[0], k2.export()[0], k1.sign(tx3.id()), k2.sign(tx3.id())])

    H = sha256(" ".join(data)).digest()

    data = " ".join(["Query", str(len(data))] + data)

    instance.lineReceived(data)
    response = tr.value()
    
    k, s = map(b64decode, response.split(" ")[1:])
    assert factory.key.verify(H, s)

def test_TxCommit(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    # Check the list is up to date
    for ik in tx3.get_utxo_in_keys():
        assert ik in factory.db

    data1 = map(b64encode, [tx3.serialize(), tx1.serialize(), tx2.serialize(), 
                k1.export()[0], k2.export()[0], k1.sign(tx3.id()), k2.sign(tx3.id())])

    H = sha256(" ".join(data1)).digest()

    data = " ".join(["Query", str(len(data1))] + data1)

    instance.lineReceived(data)
    response = tr.value()
    
    k, s = map(b64decode, response.split(" ")[1:])
    k2 = rscoin.Key(k)
    assert factory.key.verify(H, s)
    assert k2.verify(H, s)

    ## Now we test the Commit
    tr.clear()
    data = " ".join(["Commit", str(len(data1))] + data1 + map(b64encode, [k, s]))
    instance.lineReceived(data)
    
    flag, pub, sig = tr.value().split(" ")
    assert factory.key.verify(tx3.id(), b64decode(sig))

    k3 = rscoin.Key(b64decode(pub))
    assert k3.verify(tx3.id(), b64decode(sig))
    