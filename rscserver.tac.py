from twisted.application import internet, service
from rscoin.rscservice import RSCFactory, load_setup

import rscoin
from base64 import b64encode, b64decode


secret = file("secret.key").read()
public = rscoin.Key(secret, public=False)
print "Public keys: %s" % b64encode(public.pub.export())

dir_data = file("directory.conf").read()
directory = load_setup(dir_data) # [(public.id(), "127.0.0.1", 8080)]

application = service.Application("rscoin")
echoService = internet.TCPServer(8080, RSCFactory(secret, directory["directory"], directory["special"], N=3))
echoService.setServiceParent(application)

