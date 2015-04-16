from collections import namedtuple
from struct import pack, unpack

from hashlib import sha256

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify


# Named structures
InputTx = namedtuple('InputTx', ['tx_id', 'pos'])
OutputTx = namedtuple('OutputTx', ['key_id', 'value'])


class Key:
    """ A class representing a key pair """

    def __init__(self, key_bytes, public=True):
        self.G = EcGroup()
        if public:
            self.sec = None
            self.pub = EcPt.from_binary(key_bytes, self.G)
        else:
            self.sec = Bn.from_binary(key_bytes)
            self.pub = self.sec * self.G.generator()

    def sign(self, message):
        """ Sign a 32-byte message using the key pair """

        assert len(message) == 32
        assert self.sec is not None
        r, s = do_ecdsa_sign(self.G, self.sec, message)
        r0, s0 = r.binary(), s.binary()
        assert len(r0) <= 32 and len(s0) <= 32
        sig = pack("H32sH32s", len(r0), r0, len(s0), s0)
        return sig

    def verify(self, message, sig):
        """ Verify the message and the signature """

        assert len(message) == 32
        lr, r, ls, s = unpack("H32sH32s", sig)
        sig = Bn.from_binary(r[:lr]), Bn.from_binary(s[:ls])
        return do_ecdsa_verify(self.G, self.pub, sig, message)

    def id(self):
        """ The fingerprint of the public key """

        return sha256(self.pub.export()).digest()

    def export(self):
        """ Export the public and secret keys as strings """

        sec = None
        if self.sec is not None:
            sec = self.sec.binary()
        return (self.pub.export(), sec)


class Tx:
    """ Represents a transaction """

    def __init__(self, inTx=[], outTx=[]):
        """ Initialize a transaction """
        self.inTx = inTx
        self.outTx = outTx

    def serialize(self):
        """ Turn this transaction into a cannonical byte string """

        ser = pack("HH", len(self.inTx), len(self.outTx))

        # Serialize the In transations
        for intx in self.inTx:
            ser += pack("32sL", intx.tx_id, intx.pos)

        # Serialize the Out transactions
        for outtx in self.outTx:
            ser += pack("32sQ", outtx.key_id, outtx.value)

        return ser

    def __eq__(self, other):
        return isinstance(other, Tx) and self.id() == other.id()

    def __ne__(self, other):
        return not (self == other)

    @staticmethod
    def parse(data):
        Lin, Lout = unpack("HH", data[:4])
        data = data[4:]

        inTx = []
        for _ in range(Lin):
            idx, posx = unpack("32sL", data[:32+4])
            inTx += [InputTx(idx, posx)]
            data = data[32+4:]

        outTx = []
        for _ in range(Lout):
            kidx, valx = unpack("32sQ", data[:32+8])
            outTx += [OutputTx(kidx, valx)]
            data = data[32+8:]

        return Tx(inTx, outTx)

    def id(self):
        """ Return the fingerprint of the tranaction """
        return sha256(self.serialize()).digest()

    def get_utxo_entries(self):
        """ Returns the entries for the utxo for valid transactions """

        tid = self.id()
        return [(tid, i) for i in range(len(self.outTx))]

    def check_transaction(self, past_tx, keys, sigs):
        """ Checks that a transaction is valid given evidence """

        all_good = True
        all_good &= (len(past_tx) == len(keys) == len(sigs) == len(self.inTx))
        if not all_good:
            return False

        val = 0
        for (otx, okey, osig, txin) in zip(past_tx, keys, sigs, self.inTx):
            # Check the transaction ID matches
            oTx = Tx.parse(otx)
            all_good &= (txin.tx_id == oTx.id())

            all_good &= (0 <= txin.pos < len(oTx.outTx))

            # Check the key matches
            k = Key(okey)
            all_good &= (oTx.outTx[txin.pos].key_id == k.id())
            val += oTx.outTx[txin.pos].value

            # Check the signature matches
            all_good &= k.verify(self.id(), osig)

        # Check the value matches
        total_value = sum([o.value for o in self.outTx])
        all_good &= (val == total_value)

        return all_good


# ---------------- TESTS -------------------

from binascii import hexlify
from os import urandom


def test_test():
    assert True


def test_Tx():
    # Empty string
    x = Tx([], [])
    assert hexlify(x.serialize())[:8] == "0" * 8

    y = Tx([InputTx(urandom(32), 0)], [OutputTx(urandom(32), 100)])
    ser = y.serialize()
    assert len(ser) == 4 + 32 + 4 + 32 + 8
    z = Tx.parse(ser)
    assert y == z
    assert hexlify(y.serialize())[:8] == "01000100"
    assert len(x.id()) == len(y.id()) == 32

def test_checks1():

    k1 = Key(urandom(32), public=False)
    k2 = Key(urandom(32), public=False)

    tx1 = Tx([], [OutputTx(k1.id(), 100)])
    tx2 = Tx([], [OutputTx(k2.id(), 150)])

    tx3 = Tx([InputTx(tx1.id(), 0), InputTx(tx2.id(), 0)], [OutputTx(k1.id(), 250)])

    assert tx3.check_transaction([tx1.serialize(), tx2.serialize()], 
                            [k1.export()[0], k2.export()[0]], 
                            [k1.sign(tx3.id()), k2.sign(tx3.id())])

def test_checks_timing():

    params = []

    for _ in range(100):
        k1 = Key(urandom(32), public=False)
        k2 = Key(urandom(32), public=False)

        tx2 = Tx([], [OutputTx(k1.id(), 150)])

        tx3 = Tx([InputTx(tx2.id(), 0)], [OutputTx(k1.id(), 100), OutputTx(k1.id(), 50)])

        params += [(tx3.serialize(), ([tx2.serialize()], 
                                [k1.export()[0]], 
                                [k1.sign(tx3.id())]))]

    t0 = timer()
    for (tx3, par) in params:
        assert Tx.parse(tx3).check_transaction(*par)
    t1 = timer()
    print "\nTx check rate: %2.2f / sec" % (1.0 / ((t1-t0)/100.0)) 

def test_checks2():

    k1 = Key(urandom(32), public=False)
    k2 = Key(urandom(32), public=False)

    tx1 = Tx([], [OutputTx(k1.id(), 100), OutputTx(k2.id(), 150)])

    tx3 = Tx([InputTx(tx1.id(), 0), InputTx(tx1.id(), 1)], [OutputTx(k1.id(), 250)])

    assert tx3.check_transaction([tx1.serialize(), tx1.serialize()], 
                            [k1.export()[0], k2.export()[0]], 
                            [k1.sign(tx3.id()), k2.sign(tx3.id())])

def test_checks_failures():

    k1 = Key(urandom(32), public=False)
    k2 = Key(urandom(32), public=False)

    tx1 = Tx([], [OutputTx(k1.id(), 100)])
    tx2 = Tx([], [OutputTx(k2.id(), 150)])

    tx3 = Tx([InputTx(tx1.id(), 0), InputTx(tx2.id(), 0)], [OutputTx(k1.id(), 251)])

    # Wrong value
    assert not tx3.check_transaction([tx1.serialize(), tx2.serialize()], 
                            [k1.export()[0], k2.export()[0]], 
                            [k1.sign(tx3.id()), k2.sign(tx3.id())])

    # Wrong signature
    assert not tx3.check_transaction([tx1.serialize(), tx2.serialize()], 
                            [k1.export()[0], k2.export()[0]], 
                            [k2.sign(tx3.id()), k1.sign(tx3.id())])


def test_key():
    G = EcGroup()
    sec = G.order().random()
    k = Key(sec.binary(), False)
    bpub, bsec = k.export()

    k2 = Key(bpub)
    assert k2.sec is None
    assert k2.pub == k.pub
    assert k2.id() == k.id()

    m = urandom(32)
    sig = k.sign(m)
    assert k2.verify(m, sig)
    assert not k2.verify(urandom(32), sig)


from timeit import default_timer as timer


def test_timings():
    # Make 100 keys
    G = EcGroup()

    keys = []
    for _ in range(100):
        sec = G.order().random()
        k = Key(sec.binary(), False)
        # bpub, bsec = k.export()
        keys += [k]

    msg = urandom(32)

    # time sign
    t0 = timer()
    sigs = []
    for i in range(1000):
        sigs += [(keys[i % 100], keys[i % 100].sign(msg))]
    t1 = timer()
    print "\nSign rate: %2.2f / sec" % (1.0 / ((t1-t0)/1000.0))

    # time verify
    t0 = timer()
    for k, sig in sigs:
        assert k.verify(msg, sig)
    t1 = timer()
    print "Verify rate: %2.2f / sec" % (1.0 / ((t1-t0)/1000.0))

    # time hash
    t0 = timer()
    for _ in range(10000):
        sha256(msg).digest()
    t1 = timer()
    print "Hash rate: %2.2f / sec" % (1.0 / ((t1-t0)/10000.0))
