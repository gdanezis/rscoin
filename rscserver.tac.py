from twisted.application import internet, service
from rscservice import RSCFactory

import rscoin

secret = "A" * 32
public = rscoin.Key(secret, public=False).pub.export()
directory = [("127.0.0.1", 8080, public)]

application = service.Application("echo")
echoService = internet.TCPServer(8080, RSCFactory(secret, directory))
echoService.setServiceParent(application)

