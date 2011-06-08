import binascii
import hashlib
import random
import struct

import pyDes

from . import constants
from . import types

class ValidationException(types.KerberosException):
    pass

# Assume input and output are multiples of 8 bits.  The _nfold
# function is based on the MIT krb5_nfold C implementation:
# 
# Copyright (C) 1998 by the FundsXpress, INC.
# 
# All rights reserved.
# 
# Export of this software from the United States of America may require
# a specific license from the United States Government.  It is the
# responsibility of any person or organization contemplating export to
# obtain such a license before exporting.
# 
# WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
# distribute this software and its documentation for any purpose and
# without fee is hereby granted, provided that the above copyright
# notice appear in all copies and that both that copyright notice and
# this permission notice appear in supporting documentation, and that
# the name of FundsXpress. not be used in advertising or publicity pertaining
# to distribution of the software without specific, written prior
# permission.  FundsXpress makes no representations about the suitability of
# this software for any purpose.  It is provided "as is" without express
# or implied warranty.
# 
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
# WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#
def _nfold(outlen, instr):
    """instr is a string (which represents binary data, not unicode or
    anything readable); outlen is a number of bits to output (which
    must be a multiple of 8); returns a string."""

    assert outlen % 8 == 0

    # inbits and outbits are really byte counts.  This is an
    # unfortunate artifact of the MIT implementation, which is easier
    # to duplicate than to fix.

    inbits = len(instr)
    inarray = [ord(c) for c in instr]
    outbits = outlen / 8
    outarray = [0] * outbits

    def _lcm(a, b):
        while b != 0:
            a, b = b, a % b
        return a

    lcm = outbits * inbits / _lcm(outbits, inbits)
    byte = 0

    # this will end up cycling through the input
    # lcm(inlen,outlen)/inlen times, which is correct
    for i in xrange(lcm - 1, -1, -1):
        # compute the offset of the msbit in the input which gets
        # added to this byte
        msbit = (
            # first, start with the msbit in the first, unrotated byte
            ((inbits << 3) - 1) +
            # then, for each byte, shift to the right for each repetition
            (((inbits << 3) + 13) * (i / inbits)) +
            # last, pick out the correct byte within that shifted repetition
            ((inbits - (i % inbits)) << 3)
            ) % (inbits << 3)

        byte += (((inarray[((inbits - 1) - (msbit >> 3)) % inbits] << 8) |
                  (inarray[((inbits) - (msbit >> 3)) % inbits])) >>
                 ((msbit & 7) + 1)) & 0xff

        byte += outarray[i % outbits]
        outarray[i % outbits] = byte & 0xff

        byte >>= 8

    for i in xrange(outbits - 1, -1, -1):
        if byte == 0:
            break
        byte += outarray[i]
        outarray[i] = byte & 0xff;

        byte >>= 8

    return "".join([chr(i) for i in outarray])

def _make_random_bytes(bytecount):
    r = random.SystemRandom()
    return "".join(chr(r.getrandbits(8)) for c in xrange(0, bytecount))

class Crc32(object):
    @staticmethod
    def make_checksum(plaintext):
        crc = (binascii.crc32(plaintext, 0xffffffff) ^ 0xffffffff) & 0xffffffff
        return struct.pack("<I", crc)

class DesCbc(object):
    def __init__(self, key, iv):
        self.des = pyDes.des(key, pyDes.CBC, iv)

    def encrypt(self, plaintext):
        return self.des.encrypt(plaintext)

    def decrypt(self, ciphertext):
        return self.des.decrypt(ciphertext)

class DesCbcCrcProfile(object):
    # confounder | checksum | msg | pad

    ZERO_CHECKSUM = "\0\0\0\0"

    def __init__(self, key):
        self.des = DesCbc(key, key)
        sum_key = "".join(chr(ord(c) ^ 0xf0) for c in key)
        self.sum_des = DesCbc(sum_key, '\0' * 8)

    def encrypt(self, usage, plaintext):
        confounder = _make_random_bytes(8)
        unpad_len = len(confounder) + len(self.ZERO_CHECKSUM) + len(plaintext)
        pad = _make_random_bytes((8 - (unpad_len % 8)) % 8)
        checksum = Crc32.make_checksum(
            confounder + self.ZERO_CHECKSUM + plaintext + pad)
        c = self.des.encrypt(confounder + checksum + plaintext + pad)
        return c

    def decrypt(self, usage, ciphertext):
        dec_data = self.des.decrypt(ciphertext)
        confounder = dec_data[0:8]
        checksum = dec_data[8:12]
        msg_pad = dec_data[12:]
        calc_checksum = Crc32.make_checksum(
            confounder + self.ZERO_CHECKSUM + msg_pad)
        if checksum != calc_checksum:
            raise ValidationException
        return msg_pad

    def required_checksum_type(self):
        return constants.ChecksumType.rsa_md5_des

    def make_checksum(self, usage, plaintext):
        confounder = _make_random_bytes(8)
        return self.sum_des.encrypt(
            confounder + hashlib.md5(confounder + plaintext).digest())

    def verify_checksum(self, usage, plaintext, checksum):
        dec_data = self.sum_des.decrypt(checksum)
        confounder = dec_data[0:8]
        checksum = dec_data[8:]
        calc_checksum = hashlib.md5(confounder + plaintext).digest()
        return checksum == calc_checksum

def _pad_len(unpad_len, multiple):
    return (multiple - (unpad_len % multiple)) % multiple

class HMac(object):
    def __init__(self, hash, key):
        self.hash = hash

        padded_key = key
        if len(padded_key) > hash.block_size:
            padded_key = padded_key[:hash.block_size]
        elif len(padded_key) < hash.block_size:
            padded_key += "\0" * (hash.block_size - len(padded_key))

        self.inner = self.hash.copy()
        key_xor_ipad = "".join((chr(ord(c) ^ 0x36) for c in padded_key))
        self.inner.update(key_xor_ipad)

        self.outer = self.hash.copy()
        key_xor_opad = "".join((chr(ord(c) ^ 0x5c) for c in padded_key))
        self.outer.update(key_xor_opad)

    def __call__(self, text):
        icopy = inner.copy()
        icopy.update(text)

        ocopy = outer.copy()
        ocopy.update(icopy.digest())

        return ocopy.digest()

class SimplifiedProfile(object):
    # E(conf | plaintext | pad) | H(conf | plaintext | pad)

    # This doesn't do any caching of derived keys.  If that turns out
    # to be a performance problem, we can add it later.

    # uses: hmac_output_size, hash, key_generation_size, random_to_key
    # cipher_block_size, enc, dec

    def __init__(self, key):
        self.key = key

    def derive_key(self, constant):
        if len(constant) == self.cipher_block_size():
            input = constant
        else:
            input = _nfold(self.cipher_block_size(), constant)

        derived_key = ""

        while len(derived_key) < self.key_generation_size():
            enc_data = self.raw_encrypt(self.key, input)
            derived_key += enc_data
            input = enc_data
        
        return self.random_to_key(derived_key[:self.key_generation_size()])

    def derive_key_usage(self, usage, octet):
        return self.derive_key_usage(struct.pack(">Ib", usage, octet))

    def hmac(self, usage, data):
        hmac_func = HMac(self.hash, self.derive_key_usage(usage, 0x55))
        return hmac_func(data)[:self.hmac_output_size()]

    def encrypt(self, usage, plaintext):
        confounder = _make_random_bytes(self.cipher_block_size())
        unpad_len = len(confounder) + len(plaintext)
        pad = _make_random_bytes(_pad_len(unpad_len, 8))
        cpp = confounder + plaintext + pad
        ke = self.derive_key_usage(usage, 0xaa)
        return self.raw_encrypt(ke, cpp) + self.hmac(usage, cpp)

    def decrypt(self, usage, ciphertext):
        ke = self.derive_key_usage(usage, 0xaa)
        plaintext = self.raw_decrypt(ke, ciphertext[:-self.hmac_output_size()])
        if ciphertext[-self.hmac_output_size():] != self.hmac(usage, plaintext):
            raise ValidationException
        return plaintext

    def make_checksum(self, usage, plaintext):
        hmac_func = HMac(self.hash, self.derive_key_usage(usage, 0x99))
        return hmac_func(usage, plaintext)

    def verify_checksum(self, usage, plaintext, checksum):
        return checksum == self.make_checksum(usage, plaintext)

class Des3CbcHmacSha1KdProfile(object):
    def key_generation_size(self):
        return 21

    def hash(self):
        return hashlib.sha1()

    def hmac_output_size(self):
        return 20

    def message_block_size(self):
        return 8

    def cipher_block_size(self):
        return 8

    def required_checksum_type(self):
        return constants.ChecksumType.rsa_md5_des

    def raw_encrypt(self, key, plaintext):
        pass

    def raw_decrypt(self, key, ciphertext):
        pass

    def random_to_key(self, data):
        pass

class Key(object):
    def __init__(self):
        self.etype = None
        self.kvno = None
        self.data = None
        self._profile = None

    def __str__(self):
        return str((self.etype, "{0} octets".format(len(self.data))))

    def profile(self):
        if self._profile is not None:
            return self._profile

        if self.etype == constants.EncType.des_cbc_crc:
            self._profile = DesCbcCrcProfile(self.data)
        else:
            raise types.KerberosException(
                "Unusable etype {0}".format(self.etype))

        return self._profile

    def encrypt(self, usage, plaintext):
        return self.profile().encrypt(usage, plaintext)

    def decrypt(self, usage, ciphertext):
        return self.profile().decrypt(usage, ciphertext)

    def make_checksum(self, usage, plaintext):
        return self.profile().make_checksum(usage, plaintext)

    def verify_checksum(self, usage, plaintext, checksum):
        return self.profile().verify_checksum(usage, plaintext, checksum)

    def to_asn1(self):
        return {"keytype": int(self.etype),
                "keyvalue": self.data}

    def from_asn1(self, data):
        self.etype = constants.EncType(data.getComponentByName("keytype"))
        self.data = data.getComponentByName("keyvalue")
        return self

    def encrypt_as_asn1(self, *args, **kwargs):
        d = {"etype": int(self.etype),
             "cipher": self.encrypt(*args, **kwargs)}
        if self.kvno is not None:
            d["kvno"] = self.kvno
        return d

    def make_checksum_as_asn1(self, *args, **kwargs):
        cksumtype = self.profile().required_checksum_type()

        return {"cksumtype": int(cksumtype),
                "checksum": self.make_checksum(*args, **kwargs)}

if __name__ == '__main__':
    # Test vectors from RFC3961 A.5

    assert Crc32.make_checksum("foo") == "\x33\xbc\x32\x73"
    assert Crc32.make_checksum("test0123456789") == "\xd6\x88\x3e\xb8"
    assert Crc32.make_checksum("MASSACHVSETTS INSTITVTE OF TECHNOLOGY"
                               ) == "\xf7\x80\x41\xe3"
    assert Crc32.make_checksum("\x80\x00") == "\x4b\x98\x83\x3b"

    # Test vectors from RFC3961 A.1

    assert _nfold(64, "012345") == "\xbe\x07\x26\x31\x27\x6b\x19\x55"
    assert _nfold(56, "password") == "\x78\xa0\x7b\x6c\xaf\x85\xfa"
    assert _nfold(64, "Rough Consensus, and Running Code") == \
           "\xbb\x6e\xd3\x08\x70\xb7\xf0\xe0"
    assert _nfold(168, "password") == \
           "\x59\xe4\xa8\xca\x7c\x03\x85\xc3\xc3\x7b\x3f\x6d\x20\x00\x24\x7c\xb6\xe6\xbd\x5b\x3e"
    assert _nfold(192, "MASSACHVSETTS INSTITVTE OF TECHNOLOGY") == \
           "\xdb\x3b\x0d\x8f\x0b\x06\x1e\x60\x32\x82\xb3\x08\xa5\x08\x41\x22\x9a\xd7\x98\xfa\xb9\x54\x0c\x1b"
    assert _nfold(168, "Q") == \
           "\x51\x8a\x54\xa2\x15\xa8\x45\x2a\x51\x8a\x54\xa2\x15\xa8\x45\x2a\x51\x8a\x54\xa2\x15"
    assert _nfold(168, "ba") == \
           "\xfb\x25\xd5\x31\xae\x89\x74\x49\x9f\x52\xfd\x92\xea\x98\x57\xc4\xba\x24\xcf\x29\x7e"
    assert _nfold(64, "kerberos") == \
           "\x6b\x65\x72\x62\x65\x72\x6f\x73"
    assert _nfold(128, "kerberos") == \
           "\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93"
    assert _nfold(168, "kerberos") == \
           "\x83\x72\xc2\x36\x34\x4e\x5f\x15\x50\xcd\x07\x47\xe1\x5d\x62\xca\x7a\x5a\x3b\xce\xa4"
    assert _nfold(256, "kerberos") == \
           "\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93\x5c\x9b\xdc\xda\xd9\x5c\x98\x99\xc4\xca\xe4\xde\xe6\xd6\xca\xe4"
