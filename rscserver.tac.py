from twisted.application import internet, service
from rscoin.rscservice import RSCFactory

import rscoin
from base64 import b64encode, b64decode



secret = b64decode(file("secret.key").read())
public = rscoin.Key(secret, public=False)
print "Public keys: %s" % b64encode(public).pub.export())

directory = [(public.id(), "127.0.0.1", 8080)]

application = service.Application("rscoin")
echoService = internet.TCPServer(8080, RSCFactory(secret, directory, public))
echoService.setServiceParent(application)

