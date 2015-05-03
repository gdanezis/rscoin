if __name__ == "__main__":

    import sys
    sys.path += [ "." ]

from base64 import b64encode, b64decode
from hashlib import sha256
import os.path
from os import urandom
from timeit import default_timer as timer


from twisted.test.proto_helpers import StringTransport

import rscoin
from rscoin.rscservice import RSCFactory, load_setup, get_authorities
from rscoin.rscservice import package_query, unpackage_query_response


import pytest


@pytest.fixture
def sometx():
    secret = "A" * 32
    public = rscoin.Key(secret, public=False).id()
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
    public = rscoin.Key(secret, public=False).id()
    directory = [(public, "127.0.0.1", 8080)]

    factory = RSCFactory(secret, directory, None)
    assert os.path.exists(factory.dbname + ".db") or os.path.exists(factory.dbname)

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
    print "Number of Authorities: %s" % len(factory.get_authorities(tx1.id()))
    assert factory.key.id() in factory.get_authorities(tx1.id())
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

    H, data, _ = package_query(tx3, [tx1, tx2], [k1, k2])

    instance.lineReceived(data)
    response = tr.value()

    _, k, s = unpackage_query_response(response)    
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

def test_TxCommit_Issued(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    kIssue = rscoin.Key(urandom(32), public=False)
    pubIssue = kIssue.pub.export()
    factory.special_key = kIssue.id() # Asssign this as the special key

    k1 = rscoin.Key(urandom(32), public=False)
    k1pub = k1.pub.export()

    tx3 = rscoin.Tx([], [rscoin.OutputTx(k1.id(), 250)])

    sig1 = kIssue.sign(tx3.id())
    assert tx3.check_transaction_utxo([], [pubIssue], [sig1], kIssue.id())

    ## Now we test the Commit
    data1 = map(b64encode, [tx3.serialize(), pubIssue, sig1])

    # Ensure the entries are not in before sending message
    for k, v in tx3.get_utxo_out_entries():
        assert k not in factory.db

    # Send message
    tr.clear()
    data = " ".join(["Commit", str(len(data1))] + data1)
    instance.lineReceived(data)

    # Ensure the returned signatures check
    ret, pub, sig = tr.value().split(" ")
    assert ret == "OK"
    kx = rscoin.Key(b64decode(pub))
    assert kx.verify(tx3.id(), b64decode(sig))

    # Ensure the entries are now in
    for k, v in tx3.get_utxo_out_entries():
        assert factory.db[k] == v

def test_Ping(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    instance.lineReceived("Ping")

    assert unpackage_query_response(tr.value()) == ["Pong", factory.key.id()]
    assert tr.value().strip() == "Pong %s" % b64encode(factory.key.id())


def test_setup():
    data = """{
        "special": "AmodBjXyo2bVqyi1h0e5Kf8hSbGCmalnbF8YwJ0=",
        "directory": [ ["A/Sw7CRkoXzB2O0A3WfPMSDIbv/pOxd5Co3u9kM=", "127.0.0.1", 8080] ] 
    }"""

    stuff = load_setup(data)
    
    secret = "hello1"
    special = "special"
    directory = stuff["directory"]

    public = rscoin.Key(secret, public=False).pub.export()
    print("\nPublic: %s" % b64encode(public)) # , b64decode

    public_special = rscoin.Key(special, public=False).pub.export()
    print("Public (special): %s" % b64encode(public_special)) # , b64decode

    assert public == directory[0][0]
    assert public_special == stuff["special"]

def test_multiple():

    # Make special keys for making coins
    secret_special = "KEYSPECIAL"
    public_special = rscoin.Key(secret_special, public=False).pub.export()
    
    # Define a number of keys
    all_keys = []
    for x in range(100):
        secret = "KEY%s" % x
        public = rscoin.Key(secret, public=False).id()
        all_keys += [(public, secret)]

    # Make up the directory
    directory = []
    for x, (pub, _) in enumerate(all_keys):
        directory += [(pub, "127.0.0.1", 8080 + x)]

    # Build the factories
    factories = {}
    for pub, sec in all_keys:
        factory = RSCFactory(sec, directory, public_special, conf_dir="scratch")
        factories[pub] = factory

    # Make a mass of transactions
    k1 = rscoin.Key(urandom(32), public=False)
    k2 = rscoin.Key(urandom(32), public=False)

    all_tx_in = []
    all_tx_out = []

    for _ in range(10):

        tx1 = rscoin.Tx([], [rscoin.OutputTx(k1.id(), 100)]) 
        tx2 = rscoin.Tx([], [rscoin.OutputTx(k2.id(), 150)])

        tx3 = rscoin.Tx( [rscoin.InputTx(tx1.id(), 0), 
                         rscoin.InputTx(tx2.id(), 0)], 
                         [rscoin.OutputTx(k1.id(), 250)] )

        all_tx_in += [ tx1, tx2 ]
        all_tx_out += [ tx3 ]

    print "Lens: all_tx_in: %s all_tx_out: %s" % (len(all_tx_in), len(all_tx_out))
    
    for tx in all_tx_in:
        for kv, vv in tx.get_utxo_out_entries():
            for f in factories.values():
                f.db[kv] = vv


    data = (tx3, [tx1.serialize(), tx2.serialize()], 
                            [k1.export()[0], k2.export()[0]], 
                            [k1.sign(tx3.id()), k2.sign(tx3.id())])

    # Put the transaction through
    total = 0

    [ kid1, kid2 ] = tx3.get_utxo_in_keys()
    au1 = get_authorities(directory, kid1)
    au2 = get_authorities(directory, kid2)
    
    auxes = set(au1 + au2)

    assert len(auxes) == 10
    for aid in auxes:
        assert isinstance(aid, str) and len(aid) == 32
        assert aid in factories

    xset = []
    for kid, f in factories.iteritems():
        resp = f.process_TxQuery(data)
        # print(resp)
        assert kid == f.key.id()
        if resp:
            total += 1
            xset += [ f.key.id() ]
            #assert f.key.id() in auxes
        else:
            pass
            #assert f.key.id() not in auxes
    assert 5 <= total <= 10
    assert set(auxes) == set(xset)

@pytest.fixture
def msg_mass():

    secret = "A" * 32
    public = rscoin.Key(secret, public=False).id()
    directory = [(public, "127.0.0.1", 8080)]

    factory = RSCFactory(secret, directory, None)
    
    # Run the protocol
    instance = factory.buildProtocol(None)
    tr = StringTransport()
    instance.makeConnection(tr)

    sometx = (factory, instance, tr)


    # Make special keys for making coins
    secret_special = "KEYSPECIAL"
    public_special = rscoin.Key(secret_special, public=False).pub.export()
    
    # Define a number of keys
    all_keys = []
    secret = "KEYX"
    public = rscoin.Key(secret, public=False).id()
    
    directory = [(public, "127.0.0.1", 8080 )]

    # Make a mass of transactions
    k1 = rscoin.Key(urandom(32), public=False)
    k2 = rscoin.Key(urandom(32), public=False)

    all_tx = []

    for _ in range(1000):

        tx1 = rscoin.Tx([], [rscoin.OutputTx(k1.id(), 100)]) 
        tx2 = rscoin.Tx([], [rscoin.OutputTx(k2.id(), 150)])

        tx3 = rscoin.Tx( [rscoin.InputTx(tx1.id(), 0), 
                         rscoin.InputTx(tx2.id(), 0)], 
                         [rscoin.OutputTx(k1.id(), 250)] )

        all_tx += [ ([tx1, tx2], tx3) ]

    for intx, _ in all_tx:
        for tx in intx:
            for kv, vv in tx.get_utxo_out_entries():
                factory.db[kv] = vv

    mesages_q = []

    for ([tx1, tx2], tx3) in all_tx:
        H, data, core = package_query(tx3, [tx1, tx2], [k1, k2])
        mesages_q += [ (tx3, data, core) ]

    return (sometx, mesages_q)

def test_full_client(msg_mass):
    ## Run a single client on single CPU and test-stress it.
    
    (sometx, mesages_q) = msg_mass
    #print len(msg_mass), msg_mass
    (factory, instance, tr) = sometx

    responses = []
    t0 = timer()
    for (tx, data, core) in mesages_q:
        tr.clear()
        instance.lineReceived(data)
        response = tr.value()
        responses += [(tx, data, core, response)]
    t1 = timer()
    print "\nQuery message rate: %2.2f / sec" % (1.0 / ((t1-t0)/(len(mesages_q))))

    # k, s = map(b64decode, response.split(" ")[1:])
    # k2 = rscoin.Key(k)
    # assert factory.key.verify(H, s)
    # assert k2.verify(H, s)

    ## Now we test the Commit
    #tr.clear()
    t0 = timer()
    for (tx, data, core, response) in responses:
        resp = response.split(" ")
        k, s = map(b64decode, resp[1:])
        assert resp[0] == "OK"
        tr.clear()
        data = " ".join(["Commit", str(len(core))] + core + map(b64encode, [k, s]))
        instance.lineReceived(data)
        flag, pub, sig = tr.value().split(" ")
        assert flag == "OK"
    t1 = timer()
    print "\nCommit message rate: %2.2f / sec" % (1.0 / ((t1-t0)/(len(responses))))

    
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Test and time the Tor median statistics.')
    parser.add_argument('--time', action='store_true', help='Run timing tests')
    parser.add_argument('--lprof', action='store_true', help='Run the line profiler')
    parser.add_argument('--cprof', action='store_true', help='Run the c profiler')
    parser.add_argument('--plot', action='store_true', help='Upload time plot to plotly')


    args = parser.parse_args()

    if args.time:
        xxx = msg_mass()
        test_full_client(xxx)


    if args.cprof:
        import cProfile
        
        xxx = msg_mass()
        cProfile.run("test_full_client(xxx)", sort="tottime")

    if args.lprof:
        from line_profiler import LineProfiler
        #import rscoin.rscservice

        profile = LineProfiler(rscoin.rscservice.RSCProtocol.handle_Query, 
                                rscoin.rscservice.RSCFactory.process_TxQuery,
                                rscoin.Tx.check_transaction,
                                rscoin.Tx.parse)
        xxx = msg_mass()
        profile.run("test_full_client(xxx)")
        profile.print_stats()

@pytest.mark.online
def test_online_ping(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    import socket

    HOST = '52.16.247.68'    # The remote host
    PORT = 8080              # The same port as used by the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.sendall('Ping\r\n')
    data = s.recv(5000)
    s.close()
    
    assert unpackage_query_response(data)[0] == "Pong"
    
