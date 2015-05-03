import rscoin
from base64 import b64encode, b64decode


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Derive the public key from a secret password.')
    parser.add_argument('--password', type=str, required=True, help='The password that acts as a private key.')
    

    args = parser.parse_args()

    if args.password:
        secret = args.password
        public = rscoin.Key(secret, public=False).pub.export()
        print("Public: %s" % b64encode(public)) # , b64decode

