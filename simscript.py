from rscoin import Key, Tx, InputTx, OutputTx
from rscoin.rscservice import package_query, RSCProtocol

from os import urandom
from random import randint, shuffle
from base64 import b64encode

import sys
fi = file(sys.argv[2]+"-issue", "w")
f1 = file(sys.argv[2]+"-r1", "w")
f2 = file(sys.argv[2]+"-r2", "w")


# Build a set of "addresses"
num_addresses = 100
keys = []

for _ in range(num_addresses):
    k = Key(urandom(32), False)
    keys += [ (k.id(), k.pub.export(), k) ]

# Read the special issuing key
secret_special = file("secret.key").read()
key_special = Key(secret_special, public=False)
id_special = key_special.id()
pub_special = key_special.pub.export()


# Make a stash of initial money to issue
num_coins = int(sys.argv[1])

active_addrs = [ ]

for _ in range(num_coins):
    all_keys = keys[randint(0, num_addresses - 1)]
    key_id, key_pub, key = all_keys

    tx = Tx([], [OutputTx(key_id, 1)])
    sig = key_special.sign(tx.id())

    tx_ser = tx.serialize()
    core = map(b64encode, [tx_ser, pub_special, sig])

    #H, (mainTx, otherTx, keys, sigs) = RSCProtocol.parse_Tx_bundle(len(core), core)
    #assert tx.check_transaction( otherTx, keys, sigs, id_special)

    data = " ".join(core)
    print >>fi, data

    active_addrs += [ ((tx.id(), 0, all_keys, 1), tx) ]

shuffle(active_addrs)
active_addrs2 = []

while active_addrs != []:
    (tx1_id, pos1, (k1id, k1pub, k1), val1), txin1 = active_addrs.pop()
    (tx2_id, pos2, (k2id, k2pub, k2), val2), txin2 = active_addrs.pop()

    tx = Tx([InputTx(tx1_id, pos1), InputTx(tx2_id, pos2)], 
                    [OutputTx(k1id, 1), OutputTx(k2id, 1)])
    
    _, _, core = package_query(tx, [txin1, txin2], [k1, k2])

    _, (_, xxotherTx, xxkeys, xxsigs) = RSCProtocol.parse_Tx_bundle(len(core), core)
    assert tx.check_transaction( xxotherTx, xxkeys, xxsigs)

    active_addrs2 += [ ((tx.id(), 0, (k1id, k1pub, k1), 1), tx) ]
    active_addrs2 += [ ((tx.id(), 1, (k2id, k2pub, k2), 1), tx) ]

    data = " ".join(core)
    print >>f1, data

shuffle(active_addrs2)
active_addrs3 = []

while active_addrs2 != []:
    (tx1_id, pos1, (k1id, k1pub, k1), val1), txin1 = active_addrs2.pop()
    (tx2_id, pos2, (k2id, k2pub, k2), val2), txin2 = active_addrs2.pop()

    tx = Tx([InputTx(tx1_id, pos1), InputTx(tx2_id, pos2)], 
                    [OutputTx(k1id, 1), OutputTx(k2id, 1)])
    
    _, _, core = package_query(tx, [txin1, txin2], [k1, k2])

    _, (_, xxotherTx, xxkeys, xxsigs) = RSCProtocol.parse_Tx_bundle(len(core), core)
    assert tx.check_transaction( xxotherTx, xxkeys, xxsigs)

    active_addrs3 += [ ((tx.id(), 0, (k1id, k1pub, k1), 1), tx) ]
    active_addrs3 += [ ((tx.id(), 1, (k2id, k2pub, k2), 1), tx) ]

    data = " ".join(core)
    print >>f2, data

fi.close()
f1.close()
f2.close()