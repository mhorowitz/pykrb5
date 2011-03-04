import binascii
import hashlib
import random
import struct

import pyDes

from . import constants
from . import types

class ValidationException(types.KerberosException):
    pass

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
        self.etype = data.getComponentByName("keytype")
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
