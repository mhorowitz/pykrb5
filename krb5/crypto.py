import binascii
import hashlib
import random
import struct

import pyDes

from . import constants
from . import types

class ValidationException(types.KerberosException):
    pass

"""
      We first define a primitive called n-folding, which takes a
      variable-length input block and produces a fixed-length output
      sequence.  The intent is to give each input bit approximately
      equal weight in determining the value of each output bit.  Note
      that whenever we need to treat a string of octets as a number, the
      assumed representation is Big-Endian -- Most Significant Byte
      first.

      To n-fold a number X, replicate the input value to a length that
      is the least common multiple of n and the length of X.  Before
      each repetition, the input is rotated to the right by 13 bit
      positions.  The successive n-bit chunks are added together using
      1's-complement addition (that is, with end-around carry) to yield
      a n-bit result....
"""

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
    anything readable); outlen is a number of characters to output;
    returns a string."""

    # inbits and outbits are really byte counts.  This is an
    # unfortunate artifact of the MIT implementation, which is easier
    # to duplicate than to fix.

    inbits = len(instr)
    inarray = [ord(c) for c in instr]
    outbits = outlen
    outarray = [0] * outlen

    def _lcm(a, b):
        while b:
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
                 ((msbit & 7) + 1))

        byte += outarray[i % outbits]
        outarray[i % outbits] = byte & 0xff

        byte >>= 8

    for i in xrange(outbits - 1, -1, -1):
        if not byte:
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

class DesCbcCrcProfile(object):
    # confounder | checksum | msg | pad

    ZERO_CHECKSUM = "\0\0\0\0"

    def __init__(self, key, ctor, enc, dec):
        self.enc = enc
        self.dec = dec
        self.des = ctor(key, key)
        sum_key = "".join(chr(ord(c) ^ 0xf0) for c in key)
        self.sum_des = ctor(sum_key, '\0' * 8)

    def encrypt(self, usage, plaintext):
        confounder = _make_random_bytes(8)
        unpad_len = len(confounder) + len(self.ZERO_CHECKSUM) + len(plaintext)
        pad = _make_random_bytes((8 - (unpad_len % 8)) % 8)
        checksum = Crc32.make_checksum(
            confounder + self.ZERO_CHECKSUM + plaintext + pad)
        c = self.enc(self.des, confounder + checksum + plaintext + pad)
        return c

    def decrypt(self, usage, ciphertext):
        dec_data = self.dec(self.des, ciphertext)
        confounder = dec_data[0:8]
        checksum = dec_data[8:12]
        msg_pad = dec_data[12:]
        calc_checksum = Crc32.make_checksum(
            confounder + self.ZERO_CHECKSUM + msg_pad)
        if checksum != calc_checksum:
            raise ValidationException
        return msg_pad

    def make_checksum(self, usage, plaintext):
        confounder = _make_random_bytes(8)
        return self.enc(self.sum_des,
                        confounder +
                        hashlib.md5(confounder + plaintext).digest())

    def verify_checksum(self, usage, plaintext, checksum):
        dec_data = self.dec(self.sum_des, checksum)
        confounder = dec_data[0:8]
        checksum = dec_data[8:]
        calc_checksum = hashlib.md5(confounder + plaintext).digest()
        return checksum == calc_checksum

class Key(object):
    REQUIRED_CKSUM_TYPES = {
        constants.EncType.des_cbc_crc: constants.ChecksumType.rsa_md5_des
        }

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
            self._profile = DesCbcCrcProfile(
                self.data,
                lambda key, iv: pyDes.des(key, pyDes.CBC, iv),
                lambda des, plain: des.encrypt(plain),
                lambda des, cipher: des.decrypt(cipher))
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
        cksumtype = self.REQUIRED_CKSUM_TYPES[self.etype]

        return {"cksumtype": int(cksumtype),
                "checksum": self.make_checksum(*args, **kwargs)}

if __name__ == '__main__':
    assert Crc32.make_checksum("foo") == "\x33\xbc\x32\x73"
    assert Crc32.make_checksum("test0123456789") == "\xd6\x88\x3e\xb8"
    assert Crc32.make_checksum("MASSACHVSETTS INSTITVTE OF TECHNOLOGY"
                               ) == "\xf7\x80\x41\xe3"
    assert Crc32.make_checksum("\x80\x00") == "\x4b\x98\x83\x3b"

    assert _nfold(64, "012345") == "\xbe\x07\x26\x31\x27\x6b\x19\x55"
    assert _nfold(56, "password") == "\x78\xa0\x7b\x6c\xaf\x85\xfa"
    assert _nfold(64, "Rough Consensus, and Running Code") == \
        "\xbb\x6e\xd3\x08\x70\xb7\xf0\xe0"

    assert _nfold(168, "password") == \
        "\x59\xe4\xa8\xca\x7c\x03\x85\xc3\xc3\x7b\x3f\x6d\x20\x00\x24\x7c\xb6\xe6\xbd\x5b\x3e"
