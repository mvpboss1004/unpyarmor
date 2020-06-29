# SPDX-License-Identifier: GPL-3.0+
# Deobfuscation / unpacking code

import marshal
import struct
import sys
from io import BytesIO

import dis

from .crypto import *

def parse_key(keyi):
    # Decrypt the pytransform.key to the RSA public key
    r = BytesIO(keyi)
    key0_len = struct.unpack("<H", r.read(2))[0]
    key1_len = struct.unpack("<H", r.read(2))[0]
    r.seek(16)
    key0 = r.read(key0_len)
    key1 = r.read(key1_len)
    # decrypt the first part
    keyinp = des3_decrypt(key0[:24], key0[24:32], key0[32:])
    keyinp = decode_buffer(keyinp)
    key, iv = derive_keys(keyinp)[0]
    # decrypt the second part
    decrsa = des3_decrypt(key, iv, key1)
    decrsa = decode_buffer(decrsa)
    return decrsa

def restore_codeobj(enc_co, pubkey):
    # Unwrap the obfuscated code object (from bytes)
    key, iv = derive_keys(pubkey)[0]
    deccode = des3_decrypt(key, iv, enc_co)
    deccode = decode_buffer(deccode)
    co = marshal.loads(deccode)
    return co

JUMP_OPCODES = [111, 112, 113, 114, 115, 119]

def fix_code(code, stub_size):
    # replace jump to stub with return
    code = code[:-2] + b"S\x00" # RETURN_VALUE
    # fix absolute jumps
    extend = None
    code = bytearray(code)
    for i in range(0, len(code), 2):
        op = code[i]
        arg = code[i+1]
        if op == 144:
            extend = arg << 8
            continue
        if op in JUMP_OPCODES:
            if extend is not None:
                arg |= extend
                arg -= stub_size
                code[i+1] = arg & 0xff
                code[i-1] = arg >> 8
            else:
                arg -= stub_size
                code[i+1] = arg
        extend = None
    return bytes(code)

def decrypt_code_wrap(code, flags, pubkey):
    # Decrypt code with wrap enabled
    keys = derive_keys(pubkey)
    enc = code[32:-16] # Remove stub
    if flags & 0x40000000: # obf_code == 1
        code = xor_decrypt(keys[2][0], enc)
        code = fix_code(code, 32)
    elif flags & 0x8000000: # obf_code == 2
        code = des3_decrypt(keys[0][0], keys[0][1], enc)
        code = fix_code(code, 32)
    return code

def decrypt_code_jump(code, flags, pubkey):
    # Decrypt code with wrap disabled
    keys = derive_keys(pubkey)
    # search for jump at end of stub
    stub_size = 2
    for i in range(0, len(code), 2):
        if code[i] == 110: # JUMP_FORWARD
            stub_size = i+2
            break
    enc = code[stub_size:-8] # Remove stub
    if flags & 0x40000000: # obf_code == 1
        code = xor_decrypt(keys[2][0], enc)
    elif flags & 0x8000000: # obf_code == 2
        code = des3_decrypt(keys[1][0], keys[1][1], enc)
    return code

def deobfusc_codeobj(co, pubkey):
    # Deobfuscate a code object
    code = co.co_code
    flags = co.co_flags
    consts = []
    # decode sub-functions
    for const in co.co_consts:
        if isinstance(const, type(co)):
            const = deobfusc_codeobj(const, pubkey)
        consts.append(const)
    if flags & 0x48000000:
        if "__armor_enter__" in co.co_names and "__armor_exit__" in co.co_names: # wrap_mode == 1
            code = decrypt_code_wrap(co.co_code, flags, pubkey)
        elif "__armor__" in co.co_names: # wrap_mode == 0
            code = decrypt_code_jump(co.co_code, flags, pubkey)
        else:
            print("warning: could not detect stub in", co)
    # remove obfuscation flags
    # note: 0x20000000 means allow external usage
    flags &= ~(0x40000000 | 0x20000000 | 0x8000000)
    co = co.replace(co_code=code, co_flags=flags, co_consts=tuple(consts))
    return co
