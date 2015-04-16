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

    def __init__(self, inTx, outTx):
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

    def id(self):
        """ Return the fingerprint of the tranaction """
        return sha256(self.serialize()).digest()

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
    assert hexlify(y.serialize())[:8] == "01000100"
    assert len(x.id()) == len(y.id()) == 32


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
