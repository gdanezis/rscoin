if __name__ == "__main__":
    import sys
    sys.path += [ "." ]

from base64 import b64encode, b64decode
from binascii import hexlify

from hashlib import sha256
import os.path
from os import urandom
from timeit import default_timer as timer
from collections import defaultdict

from twisted.test.proto_helpers import StringTransport

import rscoin
from rscoin.rscservice import RSCFactory, load_setup, get_authorities
from rscoin.rscservice import package_query, unpackage_query_response, \
                        package_commit, package_issue, unpackage_commit_response



import pytest

master_ip = "52.17.228.102"


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
    factory = RSCFactory(secret, directory, None, N=3)

    print
    print factory.get_authorities("AXXX")[-1]
    print factory.get_authorities("FXXX")[-1]
    assert factory.get_authorities("AXXX")[-1][0] == "A"
    assert factory.get_authorities("FXXX")[-1][0] == "F"


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

    #data1 = map(b64encode, [tx3.serialize(), tx1.serialize(), tx2.serialize(), 
    #            k1.export()[0], k2.export()[0], k1.sign(tx3.id()), k2.sign(tx3.id())])

    #H = sha256(" ".join(data1)).digest()

    #data = " ".join(["Query", str(len(data1))] + data1)
    H, data, dataCore = package_query(tx3, [tx1, tx2], [k1, k2])

    instance.lineReceived(data)
    response = tr.value()
    
    k, s = map(b64decode, response.split(" ")[1:])
    k2 = rscoin.Key(k)
    assert factory.key.verify(H, s)
    assert k2.verify(H, s)

    ## Now we test the Commit
    tr.clear()
    # data = " ".join(["Commit", str(len(dataCore))] + dataCore + map(b64encode, [k, s]))

    data = package_commit(dataCore, [(k, s)])
    instance.lineReceived(data)
    
    flag, pub, sig = tr.value().split(" ")
    assert factory.key.verify(tx3.id(), b64decode(sig))

    k3 = rscoin.Key(b64decode(pub))
    assert k3.verify(tx3.id(), b64decode(sig))

def test_TxCommit_Issued(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    kIssue = rscoin.Key(urandom(32), public=False)
    pubIssue = kIssue.export()[0]

    factory.special_key = kIssue.id() # Asssign this as the special key

    tx3 = rscoin.Tx([], [rscoin.OutputTx(k1.id(), 250)])

    sig1 = kIssue.sign(tx3.id())
    assert tx3.check_transaction_utxo([], [pubIssue], [sig1], kIssue.id())
    assert tx3.check_transaction([], [pubIssue], [sig1], kIssue.id())

    ## Now we test the Commit

    # Ensure the entries are not in before sending message
    for k, v in tx3.get_utxo_out_entries():
        assert k not in factory.db

    # Send message
    tr.clear()

    data = package_issue(tx3, [kIssue, sig1])

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

def test_load_balance():
    try:
        dir_data = load_setup(file("directory.conf").read())
        directory = dir_data["directory"]
    except:
        chars = ["A", "B", "C", "D", "E", "F"]
        directory = [(c* 32, "127.0.0.1", 8080) for c in chars]

    hist = defaultdict(int)
    for _ in range(10000):
        x = get_authorities(directory, urandom(32), N = 3)
        for xi in x:
            hist[xi] += 1

    for ki, ni in sorted(hist.iteritems()):
        print hexlify(ki)[:8], ni



def test_multiple():

    import os
    try:
        os.mkdir("testscratch")
    except:
        pass

    # Make special keys for making coins
    secret_special = "KEYSPECIAL"
    public_special = rscoin.Key(secret_special, public=False).id()
    
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
        factory = RSCFactory(sec, directory, public_special, conf_dir="testscratch", N=5)
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
    au1 = get_authorities(directory, kid1, N = 5)
    au2 = get_authorities(directory, kid2, N = 5)
    
    auxes = set(au1 + au2)

    assert len(auxes) == 10
    for aid in auxes:
        assert isinstance(aid, str) and len(aid) == 32
        assert aid in factories

    H, msg, dataCore = package_query(tx3, [tx1, tx2], [k1, k2])

    xset = []
    rss = []
    for kid, f in factories.iteritems():
        # resp = f.process_TxQuery(data)

        instance = f.buildProtocol(None)
        tr = StringTransport()
        instance.makeConnection(tr)
        instance.lineReceived(msg)

        resp_msg = unpackage_query_response(tr.value().strip())

        assert kid == f.key.id()
        if resp_msg[0] == "OK":
            [r, s] = resp_msg[1:]

            total += 1
            xset += [ f.key.id() ]
            rss += [(r,s)]
        else:
            pass
            
    assert 5 <= total <= 10
    assert set(auxes) == set(xset)

    ## Now test the commit phase
    assert 5 <= len(rss) <= 10 
    msg_commit = package_commit(dataCore, rss)

    #from twisted.python import log
    #import sys
    #log.startLogging(sys.stdout)

    total = 0
    for kid, f in factories.iteritems():
    
        instance = f.buildProtocol(None)
        tr = StringTransport()
        instance.makeConnection(tr)
        instance.lineReceived(msg_commit)

        resp_commit = tr.value().strip()
        resp_l = unpackage_commit_response(resp_commit)
        if resp_l[0] == "OK":
            total += 1
    assert total == 5

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

    ## Now we test the Commit
    t0 = timer()
    for (tx, data, core, response) in responses:
        resp = response.split(" ")
        k, s = map(b64decode, resp[1:])
        assert resp[0] == "OK"
        tr.clear()
        data = package_commit(core, [(k, s)])
        instance.lineReceived(data)
        flag, pub, sig = tr.value().split(" ")
        assert flag == "OK"
    t1 = timer()
    print "\nCommit message rate: %2.2f / sec" % (1.0 / ((t1-t0)/(len(responses))))
        


# @pytest.mark.online
def test_commit_error(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    instance.lineReceived("xCommit X Y Z")
    assert tr.value().strip() == "Error ParsingError"

@pytest.mark.online
def test_online_ping(sometx):
    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx

    import socket

    ## Read live directory


    HOST = master_ip    # The remote host
    PORT = 8080              # The same port as used by the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.sendall('Ping\r\n')
    data = s.recv(5000)
    s.close()
    
    assert unpackage_query_response(data)[0] == "Pong"


@pytest.mark.online
def test_online_issue(sometx):

    (factory, instance, tr), (k1, k2, tx1, tx2, tx3) = sometx
    
    kIssue = rscoin.Key(file("secret.key").read(), False) # rscoin.Key(urandom(32), public=False)
    pubIssue = kIssue.pub.export()
    factory.special_key = kIssue.id()
    print "Public ID: %s" % b64encode(factory.special_key)
    
    # Build a new coin
    k1 = rscoin.Key(urandom(32), public=False)
    k1pub = k1.pub.export()
    tx3 = rscoin.Tx([], [rscoin.OutputTx(k1.id(), 250)])
    sig1 = kIssue.sign(tx3.id())

    ## Now we test the Commit
    #data1 = map(b64encode, [tx3.serialize(), pubIssue, sig1])
    #data = " ".join(["Commit", str(len(data1))] + data1)

    data = package_issue(tx3, [kIssue, sig1])

    # test on fake
    tr.clear()
    instance.lineReceived(data)

    # Ensure the returned signatures check
    ret, pub, sig = tr.value().split(" ")
    assert ret == "OK"
    kx = rscoin.Key(b64decode(pub))
    assert kx.verify(tx3.id(), b64decode(sig))

    # Second time:
    tr.clear()
    instance.lineReceived(data)
    ret2, pub2, sig2 = tr.value().split(" ")
    assert ret2 == ret
    assert pub2 == pub
    assert sig != sig2
    assert kx.verify(tx3.id(), b64decode(sig2))


    import socket
    HOST = master_ip    # The remote host
    PORT = 8080              # The same port as used by the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.sendall(data + '\r\n')

    data_rec = ''
    data_rec += s.recv(4096)
    print "Data: '%s'" % data_rec
    s.close()    

    # Ensure the returned signatures check
    ret, pub, sig = data_rec.split(" ")
    assert ret == "OK"
    kx = rscoin.Key(b64decode(pub))
    assert kx.verify(tx3.id(), b64decode(sig))


    
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
                                rscoin.Tx.check_transaction_utxo,
                                rscoin.Tx.parse)
        xxx = msg_mass()
        profile.run("test_full_client(xxx)")
        profile.print_stats()


