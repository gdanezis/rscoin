from collections import namedtuple
from struct import pack, unpack

from hashlib import sha256

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify


# Named structures
InputTx = namedtuple('InputTx', ['tx_id', 'pos'])
OutputTx = namedtuple('OutputTx', ['key_id', 'value'])
UtxoDiff = namedtuple('UtxoDIff', ['to_add', 'to_del'])


class Key:
    """ A class representing a key pair """

    def __init__(self, key_bytes, public=True):
        """ Make a key given a public or private key in bytes """
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
        """ Parse a serliazed transaction """
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
        adde = [(tid, i) for i in range(len(self.outTx))]
        dele = [(xid, xpos) for xid, xpos in range(len(self.inTx))]
        return UtxoDiff(to_add=adde, to_del=dele)

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
            if not all_good:
                return False

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
