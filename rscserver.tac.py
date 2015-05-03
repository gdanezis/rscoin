from twisted.application import internet, service
from rscoin.rscservice import RSCFactory

import rscoin


secret = "A" * 32
public = rscoin.Key(secret, public=False).pub.export()
directory = [(public, "127.0.0.1", 8080)]

application = service.Application("echo")
echoService = internet.TCPServer(8080, RSCFactory(secret, directory, public))
echoService.setServiceParent(application)

