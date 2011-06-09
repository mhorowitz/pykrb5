import binascii
import hashlib
import itertools
import random
import struct

import pyDes

from . import asn1
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

def _pad_len(unpad_len, multiple):
    return (multiple - (unpad_len % multiple)) % multiple

def _compute_des_parity(octet):
    parity = octet
    parity ^= parity >> 4
    parity ^= parity >> 2
    parity ^= parity >> 1
    if parity & 1 == 0:
        octet ^= 1
    return octet

WEAK_DES_KEYS = set([
    "\x01" * 8,
    "\xfe" * 8,
    "\xe0" * 4 + "\xf1" * 4,
    "\x1f" * 4 + "\x0e" * 4,

    "\x01\x1f\x01\x1f\x01\x0e\x01\x0e",
    "\x1f\x01\x1f\x01\x0e\x01\x0e\x01",
    "\x01\xe0\x01\xe0\x01\xf1\x01\xf1",
    "\xe0\x01\xe0\x01\xf1\x01\xf1\x01",
    "\x01\xfe\x01\xfe\x01\xfe\x01\xfe",
    "\xfe\x01\xfe\x01\xfe\x01\xfe\x01",
    "\x1f\xe0\x1f\xe0\x0e\xf1\x0e\xf1",
    "\xe0\x1f\xe0\x1f\xf1\x0e\xf1\x0e",
    "\x1f\xfe\x1f\xfe\x0e\xfe\x0e\xfe",
    "\xfe\x1f\xfe\x1f\xfe\x0e\xfe\x0e",
    "\xe0\xfe\xe0\xfe\xf1\xfe\xf1\xfe",
    "\xfe\xe0\xfe\xe0\xfe\xf1\xfe\xf1"
    ])

def _des_octets_to_key(octets):
    key = "".join((chr(_compute_des_parity(octet)) for octet in octets))
    if key in WEAK_DES_KEYS:
        octets[7] ^= 0xf0
        key = "".join((chr(_compute_des_parity(octet)) for octet in octets))
    return key

def _des_random_to_key(data):
    octets = [0] * 8
    for i, ch in enumerate(data):
        octets[i] = ord(ch)
        octets[7] |= (octets[i] & 1) << (i + 1)
    return _des_octets_to_key(octets)

def _des3_random_to_key(data):
    return _des_random_to_key(data[0:7]) + \
           _des_random_to_key(data[7:14]) + \
           _des_random_to_key(data[14:21])

def _mit_des_string_to_key(text, salt):
    text = text.encode("utf-8")
    salt = salt.encode("utf-8")

    s = text + salt + "\0" * _pad_len(len(text) + len(salt), 8)

    def shift_7bit(n):
        return (n & 0x7f) << 1

    def reverse_7bit(n):
        ret = 0
        for i in xrange(0, 7):
            if n & (1 << i) != 0:
                ret |= 1 << (7 - i)
        return ret

    octets = [0] * 8

    s16 = s + "\0" * _pad_len(len(s), 16)
    # from grouper() recipe in itertools doc
    args = [iter(s16)] * 16
    for chunk in itertools.izip_longest(*args):
        octets = itertools.imap(lambda a, b, c: a ^ b ^ c, octets,
                                (shift_7bit(ord(ch)) for ch in chunk[0:8]),
                                (reverse_7bit(ord(ch)) for ch in chunk[15:7:-1])
                                )

        octets = [o for o in octets]

    tempkey = _des_octets_to_key(octets)
    key = DesCbc(tempkey, tempkey).encrypt(s)[-8:]
    return _des_octets_to_key((ord(ch) for ch in key))

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

class Des3Cbc(object):
    def __init__(self, key, iv):
        self.des = pyDes.triple_des(key, pyDes.CBC, iv)

    def encrypt(self, plaintext):
        return self.des.encrypt(plaintext)

    def decrypt(self, ciphertext):
        return self.des.decrypt(ciphertext)

class DesCbcCrcProfile(object):
    # confounder | checksum | msg | pad

    ZERO_CHECKSUM = "\0\0\0\0"

    def __init__(self, key):
        # TODO marc: see the comment in Key.set_data_from_string
        if key is not None:
            self.des = DesCbc(key, key)
            sum_key = "".join(chr(ord(c) ^ 0xf0) for c in key)
            self.sum_des = DesCbc(sum_key, '\0' * 8)

    def encrypt(self, usage, plaintext):
        confounder = _make_random_bytes(8)
        unpad_len = len(confounder) + len(self.ZERO_CHECKSUM) + len(plaintext)
        pad = _make_random_bytes(_pad_len(unpad_len, 8))
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

    def string_to_key(self, text, salt):
        return _mit_des_string_to_key(text, salt)

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
        icopy = self.inner.copy()
        icopy.update(text)

        ocopy = self.outer.copy()
        ocopy.update(icopy.digest())

        return ocopy.digest()

class SimplifiedProfile(object):
    # E(conf | plaintext | pad) | H(conf | plaintext | pad)

    # This doesn't do any caching of derived keys.  If that turns out
    # to be a performance problem, we can add it later.

    def __init__(self, key):
        self.key = key

    def derive_key(self, base_key, constant):
        if len(constant) == self.cipher_block_size():
            input = constant
        else:
            input = _nfold(self.cipher_block_size() * 8, constant)

        derived_key = ""

        while len(derived_key) < self.key_generation_size():
            enc_data = self.raw_encrypt(base_key, input)
            derived_key += enc_data
            input = enc_data
        
        return self.random_to_key(derived_key[:self.key_generation_size()])

    def derive_key_usage(self, usage, octet):
        return self.derive_key(self.key, struct.pack(">IB", int(usage), octet))

    def hmac(self, usage, data):
        hmac_func = HMac(self.raw_hash(), self.derive_key_usage(usage, 0x55))
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
        return plaintext[self.cipher_block_size():]

    def make_checksum(self, usage, plaintext):
        hmac_func = HMac(self.raw_hash(), self.derive_key_usage(usage, 0x99))
        return hmac_func(plaintext)

    def verify_checksum(self, usage, plaintext, checksum):
        return checksum == self.make_checksum(usage, plaintext)

class Des3CbcHmacSha1KdProfile(SimplifiedProfile):
    ZEROES = "\0" * 8

    def key_generation_size(self):
        return 21

    def raw_hash(self):
        return hashlib.sha1()

    def hmac_output_size(self):
        return 20

    def message_block_size(self):
        return 8

    def cipher_block_size(self):
        return 8

    def required_checksum_type(self):
        return constants.ChecksumType.hmac_sha1_des3_kd

    def raw_encrypt(self, key, plaintext):
        return Des3Cbc(key, self.ZEROES).encrypt(plaintext)

    def raw_decrypt(self, key, ciphertext):
        return Des3Cbc(key, self.ZEROES).decrypt(ciphertext)

    def random_to_key(self, data):
        return _des3_random_to_key(data)

    def string_to_key(self, text, salt):
        text = text.encode("utf-8")
        salt = salt.encode("utf-8")

        s = text + salt
        tmpkey = self.random_to_key(_nfold(168, s))
        return self.derive_key(tmpkey, "kerberos")

class Key(object):
    def __init__(self):
        self.etype = None
        self.kvno = None
        self.data = None
        self._profile = None

    def __str__(self):
        return str((self.etype, "{0} octets".format(len(self.data))))

    def set_data_from_string(self, text, salt):
        self.data = self.profile().string_to_key(text, salt)
        # This set up a keyless profile, so we delete it so it can be
        # recreated again with the key now that it's set.  TODO marc:
        # refactor the profile into a keyless type and a keyed typel
        # so this hack won't be needed. (also see
        # DesCbcCrcProfile.__init__)
        self._profile = None

    def profile(self):
        if self._profile is not None:
            return self._profile

        if self.etype == constants.EncType.des_cbc_crc:
            self._profile = DesCbcCrcProfile(self.data)
        elif self.etype == constants.EncType.des3_cbc_sha1_kd:
            self._profile = Des3CbcHmacSha1KdProfile(self.data)
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
        self.data = str(data.getComponentByName("keyvalue"))
        return self

    def encrypted_data(self, *args, **kwargs):
        d = {"etype": int(self.etype),
             "cipher": self.encrypt(*args, **kwargs)}
        if self.kvno is not None:
            d["kvno"] = self.kvno
        return d

    def encrypt_as_asn1(self, *args, **kwargs):
        enc_data = asn1.EncryptedData()
        enc_data.setComponentByName('etype', int(self.etype))
        if self.kvno is not None:
            enc_data.setComponentByName('kvno', self.kvno)
        enc_data.setComponentByName('cipher', self.encrypt(*args, **kwargs))
        return enc_data

    def make_checksum_as_asn1(self, *args, **kwargs):
        return {"cksumtype": int(self.profile().required_checksum_type()),
                "checksum": self.make_checksum(*args, **kwargs)}

if __name__ == '__main__':
    # Test vectors from RFC2104
    assert HMac(hashlib.md5(), "\x0b" * 16)("Hi There") == \
           "\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d"
    assert HMac(hashlib.md5(), "Jefe")("what do ya want for nothing?") == \
           "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38"
    assert HMac(hashlib.md5(), "\xAA" * 16)("\xDD" * 50) == \
           "\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6"

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

    # Test vectors from RFC3961 A.2

    assert _mit_des_string_to_key("password", "ATHENA.MIT.EDUraeburn") == \
           "\xcb\xc2\x2f\xae\x23\x52\x98\xe3"
    assert _mit_des_string_to_key("potatoe", "WHITEHOUSE.GOVdanny") == \
           "\xdf\x3d\x32\xa7\x4f\xd9\x2a\x01"
    assert _mit_des_string_to_key(u"\U0001d11e", "EXAMPLE.COMpianist") == \
           "\x4f\xfb\x26\xba\xb0\xcd\x94\x13"
    assert _mit_des_string_to_key(u"\xdf", u"ATHENA.MIT.EDUJuri\u0161i\u0107") == \
           "\x62\xc8\x1a\x52\x32\xb5\xe6\x9d"
    assert _mit_des_string_to_key("11119999", "AAAAAAAA") == \
           "\x98\x40\x54\xd0\xf1\xa7\x3e\x31"
    assert _mit_des_string_to_key("NNNN6666", "FFFFAAAA") == \
           "\xc4\xbf\x6b\x25\xad\xf7\xa4\xf8"

    # Test vectors from RFC3961 A.3

    assert Des3CbcHmacSha1KdProfile("\xdc\xe0\x6b\x1f\x64\xc8\x57\xa1\x1c\x3d\xb5\x7c\x51\x89\x9b\x2c\xc1\x79\x10\x08\xce\x97\x3b\x92").derive_key_usage(1, 0x55) == \
           "\x92\x51\x79\xd0\x45\x91\xa7\x9b\x5d\x31\x92\xc4\xa7\xe9\xc2\x89\xb0\x49\xc7\x1f\x6e\xe6\x04\xcd"

    assert Des3CbcHmacSha1KdProfile("\x5e\x13\xd3\x1c\x70\xef\x76\x57\x46\x57\x85\x31\xcb\x51\xc1\x5b\xf1\x1c\xa8\x2c\x97\xce\xe9\xf2").derive_key_usage(1, 0xaa) == \
           "\x9e\x58\xe5\xa1\x46\xd9\x94\x2a\x10\x1c\x46\x98\x45\xd6\x7a\x20\xe3\xc4\x25\x9e\xd9\x13\xf2\x07"

    # Test vectors from RFC3961 A.4

    def des3string_to_key(text, salt):
        return Des3CbcHmacSha1KdProfile(None).string_to_key(text, salt)

    assert des3string_to_key("password", "ATHENA.MIT.EDUraeburn") == \
           "\x85\x0b\xb5\x13\x58\x54\x8c\xd0\x5e\x86\x76\x8c\x31\x3e\x3b\xfe\xf7\x51\x19\x37\xdc\xf7\x2c\x3e"
    assert des3string_to_key("potatoe", "WHITEHOUSE.GOVdanny") == \
           "\xdf\xcd\x23\x3d\xd0\xa4\x32\x04\xea\x6d\xc4\x37\xfb\x15\xe0\x61\xb0\x29\x79\xc1\xf7\x4f\x37\x7a"
    assert des3string_to_key("penny", "EXAMPLE.COMbuckaroo") == \
           "\x6d\x2f\xcd\xf2\xd6\xfb\xbc\x3d\xdc\xad\xb5\xda\x57\x10\xa2\x34\x89\xb0\xd3\xb6\x9d\x5d\x9d\x4a"
    assert des3string_to_key(u"\xdf", u"ATHENA.MIT.EDUJuri\u0161i\u0107") == \
           "\x16\xd5\xa4\x0e\x1c\xe3\xba\xcb\x61\xb9\xdc\xe0\x04\x70\x32\x4c\x83\x19\x73\xa7\xb9\x52\xfe\xb0"
    assert des3string_to_key(u"\U0001d11e", "EXAMPLE.COMpianist") == \
           "\x85\x76\x37\x26\x58\x5d\xbc\x1c\xce\x6e\xc4\x3e\x1f\x75\x1f\x07\xf1\xc4\xcb\xb0\x98\xf4\x0b\x19"

    # Test vectors from RFC3961 A.5

    assert Crc32.make_checksum("foo") == "\x33\xbc\x32\x73"
    assert Crc32.make_checksum("test0123456789") == "\xd6\x88\x3e\xb8"
    assert Crc32.make_checksum("MASSACHVSETTS INSTITVTE OF TECHNOLOGY"
                               ) == "\xf7\x80\x41\xe3"
    assert Crc32.make_checksum("\x80\x00") == "\x4b\x98\x83\x3b"

