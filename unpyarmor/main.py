import sys
import marshal
from unpack import *
from pyarmor import *

def do_unpack(enc_data, key_data):
    pubkey = parse_key(key_data)
    armor = parse_armored(enc_data)
    # Make sure the python version matches
    python_ver = (sys.version_info.major, sys.version_info.minor)
    if armor.py_ver != python_ver:
        print("You are using python {}, but this script was packed with {}, expect errors!".format(python_ver, armor.py_ver))
    co = restore_codeobj(armor.code, pubkey)
    co = deobfusc_codeobj(co, pubkey)
    pyc_data = armor.import_magic.ljust(16, b"\x00") + marshal.dumps(co)
    return pyc_data

def main():
    unpack(sys.argv[1], sys.argv[2], sys.argv[3]

def unpack(enc, key, pyc_out):
    with open(enc, "rb") as fd:
        enc = fd.read()
    with open(key, "rb") as fd:
        key = fd.read()
    dec = do_unpack(enc, key)
    with open(pyc_out, "wb") as fd:
        fd.write(dec)

if __name__ == '__main__':
    main()
