import rscoin
from base64 import b64encode, b64decode


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Derive the public key from a secret password.')
    parser.add_argument('--password', type=str, help='The password that acts as a private key.')    
    parser.add_argument('--store', action='store_true', help='Make up a password and store it.')    

    args = parser.parse_args()

    if args.password:
        secret = args.password
        public = rscoin.Key(secret, public=False).pub.export()
        print("Public: %s" % b64encode(public)) # , b64decode

    if args.store:
        import os

        if not os.path.exists("secret.key"):
            key = os.urandom(32)
            f = file("secret.key", "w")
            f.write(key)
            f.close()
        else:
            key = file("secret.key", "r").read()

        public = rscoin.Key(key, public = False).pub.export()
        print("Public: %s" % b64encode(public)) # , b64decode