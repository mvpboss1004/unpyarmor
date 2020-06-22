# SPDX-License-Identifier: GPL-3.0+

import sys
import marshal

from .unpack import *
from .pyarmor import *

PYC_HEADER = bytes.fromhex("550d0d0a000000000000000000000000")

def unpack(enc, key):
    pubkey = parse_key(key)
    armor = parse_armored(enc)
    co = restore_codeobj(armor.code, pubkey)
    co = deobfusc_codeobj(co, pubkey)
    pyc_data = PYC_HEADER + marshal.dumps(co)
    return pyc_data

def main():
    if len(sys.argv) != 4:
        print("usage: {} [enc] [key] [pyc-out]".format(sys.argv[0]))
        return
    with open(sys.argv[1], "rb") as fd:
        enc = fd.read()
    with open(sys.argv[2], "rb") as fd:
        key = fd.read()
    dec = unpack(enc, key)
    with open(sys.argv[3], "wb") as fd:
        fd.write(dec)
