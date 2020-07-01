# SPDX-License-Identifier: GPL-3.0+

import sys
import marshal

from .unpack import *
from .pyarmor import *

def unpack(enc, key):
    pubkey = parse_key(key)
    armor = parse_armored(enc)
    # Make sure the python version matches
    python_ver = (sys.version_info.major, sys.version_info.minor)
    if armor.py_ver != python_ver:
        print("You are using python {}, but this script was packed with {}, expect errors!".format(python_ver, armor.py_ver))
    co = restore_codeobj(armor.code, pubkey)
    co = deobfusc_codeobj(co, pubkey)
    pyc_data = armor.import_magic.ljust(16, b"\x00") + marshal.dumps(co)
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
