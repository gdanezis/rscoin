from rscoin.rscservice import RSCFactory, load_setup, unpackage_commit_response, get_authorities

import rscoin
from base64 import b64encode, b64decode
import argparse


from twisted.internet import reactor, defer
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.protocols.basic import LineReceiver

class RSCconnection(LineReceiver):

    def __init__(self, f):
        self.factory = f

    def lineReceived(self, line):
        self.factory.add_to_buffer(line)

class RSCfactory(Factory):
    def __init__(self):
        self.d = defer.Deferred()

    def add_to_buffer(self, line):
        if not self.d.called:
            self.d.callback(line)

    def buildProtocol(self, addr):
        return RSCconnection(self)

    def clientConnectionLost(self, connector, reason):
        self.add_to_buffer(None)

    def clientConnectionFailed(self, connector, reason):
        self.add_to_buffer(None)



if __name__ == "__main__":
    # Parse the basic files
    secret = file("secret.key").read()
    mykey = rscoin.Key(secret, public=False)
    
    dir_data = load_setup(file("directory.conf").read())
    directory = dir_data["directory"]

    # Options
    parser = argparse.ArgumentParser(description='RSCoin client.')
    parser.add_argument('--dir', action='store_true', help='List mintettes.')
    parser.add_argument('--pub', action='store_true', help='Print keys.')
    parser.add_argument('--issue', nargs=2, help='Issue a coin to an address.')
    
    args = parser.parse_args()

    if args.pub:
        print "My public key ID: %s" % b64encode(mykey.id())

    elif args.dir:
        for (kid, ip, port) in directory:
            print "%s\t%s\t%s" % (ip, port, b64encode(kid))

    elif args.issue:
        [value_str, key_str] = args.issue

        tx = rscoin.Tx([], [rscoin.OutputTx(key_str, int(value_str))])
        sig = mykey.sign(tx.id())

        ## Now we test the Commit
        core = map(b64encode, [tx.serialize(), mykey.pub.export(), sig])
        data = " ".join(["Commit", str(len(core))] + core)

        responses = []
        d = defer.Deferred()

        def gotProtocol(p):
            p.sendLine(data)

        d_list = []
        auths = set(get_authorities(directory,tx.id()))
        for (kid, ip, port) in directory:
            if kid not in auths:
                continue

            point = TCP4ClientEndpoint(reactor, ip, int(port))
            f = RSCfactory()
            d = point.connect(f)
            d.addCallback(gotProtocol)

            d_list += [ f.d ]

        d = defer.gatherResults(d_list)

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

            print " ".join(core)

        def r_stop(results):
            if results is not None:
                print "Error", results
            reactor.stop()

        d.addCallback(r_process)
        d.addBoth(r_stop)
        reactor.run()
