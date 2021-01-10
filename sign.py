#!/bin/python

from nacl.hash import sha256
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

from sys import argv

assert(len(argv) > 1)

seed = "abcdefghijklmnopqrstuvwxyz012345".encode()
key = SigningKey(seed)

with open(argv[1], "rb") as f:
	sign = key.sign(sha256(f.read(), RawEncoder), RawEncoder).signature
	print("Signature =", "".join("%02X" %a for a in sign))