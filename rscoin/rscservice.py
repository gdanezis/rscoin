from base64 import b64encode, b64decode
from binascii import hexlify

from json import loads
from bisect import bisect_left
import bsddb
from traceback import print_stack, print_exc
from hashlib import sha256
from os.path import join

from petlib.ec import EcPt

from twisted.internet import protocol
from twisted.protocols.basic import LineReceiver

import rscoin

def load_setup(setup_data):
    structure = loads(setup_data)
    structure["special"] = b64decode(structure["special"])
    structure["directory"] = [(b64decode(a), b, c) for a,b,c in structure["directory"]]

    return structure


class RSCProtocol(LineReceiver):

    def __init__(self, factory):
        self.factory = factory

    def parse_Tx_bundle(self , bundle_items, items):
        """ Common parsing code for the Tx bundle """

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
        """ Process the query message and respond """
        bundle_size = int(items[1])

        try:
            items = items[2:2+bundle_size]
            H, data = self.parse_Tx_bundle( bundle_size, items)
            (mainTx, otherTx, keys, sigs) = data

            # Specific checks
            assert len(otherTx) > 0
            assert len(items[2+bundle_size:]) == 0

            # TODO: checkhere this Tx falls within our remit

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
        """ Process the commit message and respond """
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
        """ Simple de-multiplexer """
        items = line.split(" ")
        if items[0] == "Query":
            return self.handle_Query(items) # Get signatures           

        if items[0] == "Commit":
            return self.handle_Commit(items) # Seal a transaction

        if items[0] == "Ping":
            self.sendLine("Pong %s" % b64encode(self.factory.key.id()))
            return # self.handle_Commit(items) # Seal a transaction


        self.return_Err("UnknownCommand")
        return

    def sign(self, H):
        """ Generic signature """
        k = self.factory.key
        pub = k.pub.export(EcPt.POINT_CONVERSION_UNCOMPRESSED)
        sig = k.sign(H)
        return " ".join(map(b64encode, [pub, sig]))


    def return_Err(self, Err):
        self.sendLine("Error %s" % Err)


class RSCFactory(protocol.Factory):

    _sync = False

    def __init__(self, secret, directory, special_key, conf_dir=None):
        """ Initialize the RSCoin server"""
        self.special_key = special_key
        self.key = rscoin.Key(secret, public=False)
        self.directory = sorted(directory)
        keyID = self.key.id()[:10]

        # Open the databases
        self.dbname = 'keys-%s.db' % hexlify(keyID)
        self.logname = 'log-%s.db' % hexlify(keyID)
        
        if conf_dir:
            self.dbname = join(conf_dir, self.dbname)
            self.logname = join(conf_dir, self.logname)

        self.db = bsddb.btopen(self.dbname, 'c')
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

        # Check that at least one Input is handled by this server
        should_handle = False
        for ik in inTxo:
            lst = self.get_authorities(ik)
            should_handle |= (self.key.id() in lst)

        if not should_handle:
            #print("Not in ID range.")
            return False

        # Check the transaction is well formed
        all_good = mainTx.check_transaction(otherTx, keys, sigs)
        if not all_good:
            print("Failed TX check")
            return False

        ## Check all inputs are in
        for ik in inTxo:
            ## We are OK if this is already in the log with the same mid
            if ik in self.log and self.log[ik] == mid:
                continue
            ## Otherwise it should not have been used yet
            elif ik not in self.db:
                print b64encode(ik)[:8]
                print("Failed utxo check")
                return False

        # Once we know all is good we proceed to remove them
        # but write the decision to a log
        for ik in inTxo:
            if ik in self.db:
                del self.db[ik]
            self.log[ik] = mid

        # Save before signing
        if RSCFactory._sync:
            self.db.sync() 
            self.log.sync()       
        return True

    def process_TxCommit(self, data):
        """ Provides a Tx and a list of responses, and commits the transaction. """
        H, mainTx, otherTx, keys, sigs, auth_pub, auth_sig = data
        
        # First check all signatures
        all_good = True
        pub_set = []
        for pub, sig in zip(auth_pub, auth_sig):
            key = rscoin.Key(pub)
            pub_set += [ key.id() ]
            all_good &= key.verify(H, sig)

        if not all_good:
            return False

        # Check the transaction is well formed
        all_good = mainTx.check_transaction(otherTx, keys, sigs, masterkey=self.special_key)
        if not all_good:
            return False

        pub_set = set(pub_set)

        # Now check all authorities are involved
        mid = mainTx.id()
        inTxo = mainTx.get_utxo_in_keys()
        for itx in inTxo:
            ## Ensure we have a Quorum for each input
            aut = set(self.get_authorities(itx))
            all_good &= (len(aut & pub_set) > len(aut) / 2) 

        # Now check we have not already spent the transaction
        all_good &= (mid not in self.log)
            
        if not all_good:
            return False

        ## TODO: Log all information about the transaction

        # Update the outTx entries
        for k, v in mainTx.get_utxo_out_entries():
            self.db[k] = v
        
        if RSCFactory._sync:
            self.db.sync()

        return all_good


    def get_authorities(self, xID, N = 5):
        """ Returns the keys of the authorities for a certain xID """
        return get_authorities(self.directory, xID, N)


def get_authorities(directory, xID, N = 5):
    """ Returns the keys of the authorities for a certain xID """
    d = sorted(directory)
    
    if __debug__:
        for di, _, _ in d:
            assert isinstance(di, str) and len(di) == 32

    if len(d) <= N:
        return [di[0] for di in d]

    i = bisect_left(d, (xID, None, None))
    return [d[(i + j - 1) % len(d)][0] for j in range(N)]
