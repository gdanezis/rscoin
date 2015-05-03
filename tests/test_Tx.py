# from line_profiler import profile

from hashlib import sha256
from binascii import hexlify
from os import urandom

from petlib.ec import EcGroup

from rscoin import Key, Tx, InputTx, OutputTx



def test_test():
    assert True
    # D = EcGroup.list_curves()
    # for x in D:
    #    print "%s\t%s" % (x, D[x])


def test_Tx():
    # Empty string
    x = Tx([], [], R="A"*32)
    assert hexlify(x.serialize())[:8] == "0" * 8

    y = Tx([InputTx(urandom(32), 0)], [OutputTx(urandom(32), 100)], R="B"*32)
    ser = y.serialize()
    assert len(ser) == 4 + 32 + 4 + 32 + 8 + 32
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

def test_utxo_checks():

    k1 = Key(urandom(32), public=False)
    k2 = Key(urandom(32), public=False)

    tx1 = Tx([], [OutputTx(k1.id(), 100)])
    tx2 = Tx([], [OutputTx(k2.id(), 150)])

    tx3 = Tx([InputTx(tx1.id(), 0), InputTx(tx2.id(), 0)], [OutputTx(k1.id(), 250)])

    assert tx3.check_transaction_utxo(
                            [(tx1.id(), 0, k1.id(), 100), (tx2.id(), 0, k2.id(), 150)], 
                            [k1.export()[0], k2.export()[0]], 
                            [k1.sign(tx3.id()), k2.sign(tx3.id())])

def test_utxo_check_issuing():

    kIssue = Key(urandom(32), public=False)
    pubIssue = kIssue.pub.export()

    k1 = Key(urandom(32), public=False)
    k1pub = k1.pub.export()

    tx3 = Tx([], [OutputTx(k1.id(), 250)])

    assert tx3.check_transaction_utxo([], [ pubIssue ], 
                            [kIssue.sign(tx3.id())], masterkey = kIssue.id())


def test_utxo_entries():

    k1 = Key(urandom(32), public=False)
    k2 = Key(urandom(32), public=False)

    tx1 = Tx([], [OutputTx(k1.id(), 100)])
    tx2 = Tx([], [OutputTx(k2.id(), 150)])

    tx3 = Tx([InputTx(tx1.id(), 0), InputTx(tx2.id(), 0)], [OutputTx(k1.id(), 250)])

    assert len(tx3.get_utxo_in_keys()) == 2 # 2 inputs
    assert len(tx3.get_utxo_out_entries()) == 1 # 1 outputs


# @profile
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
