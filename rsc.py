#!/usr/bin/python
from rscoin.rscservice import RSCProtocol, RSCFactory, load_setup, unpackage_commit_response, get_authorities, \
                    package_query, unpackage_query_response, package_commit, package_issue, unpackage_commit_response

import rscoin
from base64 import b64encode, b64decode
import argparse
from os import urandom
from timeit import default_timer

from twisted.internet import reactor, defer
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.protocols.basic import LineReceiver

class RSCconnection(LineReceiver):

    def __init__(self, f):
        self.factory = f

    def lineReceived(self, line):
        self.factory.add_to_buffer(line)

        self.factory.should_close = True
        self.transport.loseConnection()

    def connectionLost(self, reason):
        if not self.factory.should_close:
            self.factory.d.errback(reason)

class RSCfactory(Factory):
    def __init__(self):
        self.should_close = False
        self.d = defer.Deferred()

    def add_to_buffer(self, line):
        if not self.d.called:
            self.d.callback(line)

    def buildProtocol(self, addr):
        return RSCconnection(self)

    def clientConnectionLost(self, connector, reason):
        # pass # self.add_to_buffer(None)
        if not self.should_close:
            self.d.errback(reason)

    def clientConnectionFailed(self, connector, reason):
        if not self.should_close:
            self.d.errback(reason)
        # pass # self.add_to_buffer(None)

def load_keys():
    keys = {}
    for l in file("keychain.txt"):
        items = l.strip().split()
        keys[items[0]] = items
        if items[1] == "sec":
            keys[b64decode(items[2])] = items
    return keys


from cPickle import dump, load
from collections import defaultdict

_stats = defaultdict(int)

class ActiveTx():
    def __init__(self, fname, keys):
        self.fname = fname
        self.keys = keys
        
        try:
            self.Tx = load(file(self.fname, "rb"))
        except:
            self.Tx = {}

        self.saving_lock = False

    def add(self, Tx):
        ptx = rscoin.Tx.parse(Tx)
        for i, (key_id, value) in enumerate(ptx.outTx):
            if key_id in self.keys:
                self.Tx[(ptx.id(), i, key_id, value)] = Tx

    def remove(self, desc):
        del self.Tx[desc]

    def save(self, reactor):
        if not self.saving_lock:
            self.saving_lock = True
            reactor.callInThread(self._save)

    def _save(self):
        dump(self.Tx, file(self.fname, "wb"))
        self.saving_lock = False

    def balances(self):
        balances = defaultdict(int)
        for (_, _, key_id, value) in self.Tx:
            balances[keys[key_id][0]] += value
        return balances

    def get_value(self, value):
        v = 0
        tx = []
        for k in self.Tx:
            (tx_id, i, key_id, cv) = k
            v += cv
            tx += [ k ]
            if v >= value:
                break

        # print v, tx
        return v, tx

def broadcast(small_dir, data):
    d_list = []
    responses = []
    # d = defer.Deferred()

    def gotProtocol(p):
        p.sendLine(data)

    for (kid, ip, port) in small_dir:
        _stats[ip] += 1
        point = TCP4ClientEndpoint(reactor, ip, int(port), timeout=10)
        f = RSCfactory()

        d = point.connect(f)
        d.addCallback(gotProtocol)
        d.addErrback(f.d.errback)
        # f.d.errback

        d_list += [ f.d ]

    d_all = defer.gatherResults(d_list)
    return d_all

def r_stop(results):
    if results is not None and isinstance(results, Exception):
        print "Error", results
    reactor.stop()

def play(core, directory):

    tx = rscoin.Tx.parse(b64decode(core[0]))

    t0 = default_timer()

    inTxo = tx.get_utxo_in_keys()
    # Check that at least one Input is handled by this server
    Qauths = []
    for ik in inTxo:
        Qauths += get_authorities(directory, ik, 3)
    Qauths = set(Qauths)
    Qsmall_dir = [(kid, ip, port) for (kid, ip, port) in directory if kid in Qauths]
    # print len(Qsmall_dir)

    Cauths_L = get_authorities(directory, tx.id(), N=3)
    Cauths = set(Cauths_L)
    
    assert len(Cauths) == len(Cauths_L)
    assert len(Cauths) <= 3

    Csmall_dir = [(kid, ip, port) for (kid, ip, port) in directory if kid in Cauths]
    
    assert len(Csmall_dir) <= 3
    
    d_end = defer.Deferred()

    def get_commit_responses(resp):
        try:
            assert len(resp) <= 3
            for r in resp:
                res = unpackage_commit_response(r)
                if res[0] != "OK":
                    print resp
                    d_end.errback(Exception("Commit failed."))
                    return
            t1 = default_timer()
            # print 
            print "Commit OK", t1 - t0, t0, t1
            d_end.callback(t1 - t0)
        except Exception as e:
            d_end.errback(e)
            return

    if len(tx.inTx) == 0:
        # We are dealing with an issue message
        c_msg = " ".join(["xCommit", str(len(core))] + core)

        d = broadcast(Csmall_dir, c_msg)
        d.addCallback(get_commit_responses)
        d.addErrback(d_end.errback)

    else:
        q_msg = " ".join(["xQuery", str(len(core))] + core)

        d = broadcast(Qsmall_dir, q_msg)

        def process_query_response(resp):
            try:
                kss = []
                for r in resp:
                    res = unpackage_query_response(r)
                    if res[0] != "OK":
                        print resp
                        d_end.errback(Exception("Query failed."))
                        return

                    _, k, s = res
                    kss += [(k, s)]


                commit_message = package_commit(core, kss)

                dx = broadcast(Csmall_dir, commit_message)
                dx.addCallback(get_commit_responses)
                dx.addErrback(d_end.errback)

            except Exception as e:
                d_end.errback(e)

        d.addCallback(process_query_response)
        d.addErrback(d_end.errback)

    return d_end

import socket

def main():    
    dir_data = load_setup(file("directory.conf").read())
    # directory = dir_data["directory"]

    directory = [(kid, socket.gethostbyname(ip), port) for (kid, ip, port) in dir_data["directory"] ]

    special_id = dir_data["special"]

    # Options
    parser = argparse.ArgumentParser(description='RSCoin client.')
    parser.add_argument('--dir', action='store_true', help='List mintettes.')
    parser.add_argument('--mock', action='store_true', help='Do not connect to the network.')
    parser.add_argument('--balances', action='store_true', help='List balances of all addresses.')
    

    parser.add_argument('--issue', nargs=2, metavar=("VALUE", "ADDRESS"), help='Issue a coin to an address.')
    parser.add_argument('--pay', nargs=3, metavar=("VALUE", "ADDRESS", "CHANGEADDRESS"),  help='Pay and address some amount, and return change')

    parser.add_argument('--newaddress', nargs=1, metavar="NAME", help='Make a new address with a specific name.')
    parser.add_argument('--storeaddress', nargs=2, metavar=("NAME", "KEYID"), help='Load an address ID with a specific name.')
    parser.add_argument('--listaddress',action='store_true', help='List all known addresses.')

    parser.add_argument('--play', nargs=1, metavar="FILE", help='Play a set of transaction cores.')

    parser.add_argument('--conn', default=20, type=int, metavar="CONNECTIONS", help='Number of simultaneaous connections.')
    
    
    args = parser.parse_args()

    if args.dir:
        for (kid, ip, port) in directory:
            print "%s\t%s\t%s" % (ip, port, b64encode(kid))

    elif args.balances:
        keys = load_keys()
        active = ActiveTx("activetx.log", keys)
        for (k, v) in active.balances().iteritems():
            print "%s\t%s RSC" % (k, v)
        
    elif args.listaddress:
        keys = load_keys()
        
        for k in keys:
            if k[0] == "#":
                print "%s\t%s (%s)" % (k, keys[k][2], keys[k][1])

    elif args.newaddress:
        sec_str = urandom(32)
        k_sec = rscoin.Key(sec_str, public=False)
        k_pub = k_sec.pub.export()
        k_id = k_sec.id()
        
        f = file("keychain.txt", "a")
        data = "#%s sec %s %s" % (args.newaddress[0], b64encode(k_id), b64encode(sec_str))
        print data
        f.write(data+"\n")
        f.close()

    elif args.storeaddress:
        f = file("keychain.txt", "a")
        data = "#%s pub %s" % (args.storeaddress[0], args.storeaddress[1])
        f.write(data+"\n")
        f.close()

    elif args.play:

        threads = [ None ] * args.conn
        cores = []

        for core in file(args.play[0]):
            c = core.strip().split()
            cores += [ c ]

        def play_another_song(var):
            if var is not None and (not isinstance(var, float) or not isinstance(var, float)):
                print "ERROR", var                

            if cores != []:
                c = cores.pop()
                d = play(c, directory)
                d.addCallback(play_another_song)

                def replay():
                    cores += [ c ]

                d.addErrback(replay)
                d.addErrback(play_another_song)

            else:
                threads.pop()
                if threads == []:
                    reactor.stop()
        
        for _ in threads:
            play_another_song(None)

        t0 = default_timer()
        reactor.run()
        t1 = default_timer()
        
        print "Overall time: %s" % (t1 - t0)
        for (ip, v) in sorted(_stats.iteritems()):
            print "Stats: %s %s" % (ip, v)

    elif args.pay:

        (val, dest_addr, change_addr) = args.pay
        val = int(val)
        assert isinstance(val, int) and 0 < val 

        keys = load_keys()
        dest_addr = b64decode(keys["#"+dest_addr][2])
        change_addr = b64decode(keys["#"+change_addr][2])

        active = ActiveTx("activetx.log", keys)
        
        print val
        xval, txs = active.get_value(int(val))
        assert len(txs) > 0

        if val <= xval:
            # build the transactions
            inTx = []
            outTx = [ rscoin.OutputTx(dest_addr, val) ] 
            if xval - val > 0:
                outTx += [ rscoin.OutputTx(change_addr, xval - val) ]

            inTx_list = []
            keys_list = []
            for (tx_id, i, key_id, value) in txs:
                inTx_list += [ rscoin.Tx.parse(active.Tx[(tx_id, i, key_id, value)]) ]
                keys_list += [ rscoin.Key(b64decode(keys[key_id][3]), False) ]
                inTx += [ rscoin.InputTx(tx_id, i) ]
            
            newtx = rscoin.Tx(inTx, outTx)
            newtx_ser = newtx.serialize()
            
            ## Now we sign and remove from the list
            active.add(newtx_ser)
            for k in txs:
                active.remove(k)

            active.save(reactor)

            ## Now run the on-line checking
            sechash, query_string, core = package_query(newtx, inTx_list, keys_list)
            print " ".join(core)

            d = play(core, directory)
            d.addBoth(r_stop)
            
            reactor.run()

        else:
            print "Insufficient balance: %s ( < %s)" % (val, xval)


    elif args.issue:
    
        # Parse the basic files.
        secret = file("secret.key").read()
        mykey = rscoin.Key(secret, public=False)

        # Ensure the secret key corresponds to the special public key.
        assert special_id == mykey.id()

        [value_str, key_name] = args.issue
        
        keys = load_keys()
        key_id = b64decode(keys["#"+key_name][2])

        tx = rscoin.Tx([], [rscoin.OutputTx(key_id, int(value_str))])
        sig = mykey.sign(tx.id())

        ## Now we test the Commit
        #tx_ser = tx.serialize()
        #core = map(b64encode, [tx_ser, mykey.pub.export(), sig])
        #data = " ".join(["Commit", str(len(core))] + core)

        data = package_issue(tx, [mykey, sig])

        if args.mock:
            print data
        else:

            auths = set(get_authorities(directory, tx.id()))
            small_dir = [(kid, ip, port) for (kid, ip, port) in directory if kid in auths]

            d = broadcast(small_dir, data)

            def r_process(results):
                for msg in results:
                    parsed = unpackage_commit_response(msg) 
                    if parsed[0] != "OK":
                        raise Exception("Response not OK.")

                    pub, sig = parsed[1:]
                    kx = rscoin.Key(pub)
                        
                    if not (kx.verify(tx.id(), sig) and kx.id() in auths):
                        raise Exception("Invalid Signature.")

                    auths.remove( kx.id() )         

                active = ActiveTx("activetx.log", keys)
                active.add(tx_ser)
                active.save(reactor)

                print " ".join(core)

            d.addCallback(r_process)
            d.addBoth(r_stop)
            reactor.run()

if __name__ == "__main__":
    main()