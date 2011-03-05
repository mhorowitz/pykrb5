"""This is a hokey test client.  It is nowhere near a real zephyr
notice creator."""

import socket
import struct
import sys
import time

import krb5.client

def z_make_ascii_16(value):
    return "0x%04X" % value

def z_make_ascii_32(value):
    return "0x%08X" % value

def z_make_ascii(value):
    return " ".join("0x" + "".join("%02X" % ord(c) for c in value[i:i+4])
                    for i in xrange(0, len(value), 4))

def z_make_zcode(value):
    return "Z" + value.replace("\xff", "\xff\xf1").replace("\x00", "\xff\xf0")

DELIM = "\0"
REALM = "ATHENA.MIT.EDU"
KEY_USAGE = 1027

from_ip = socket.inet_aton(socket.gethostbyname(socket.gethostname()))

kclient = krb5.client.Client()
session = kclient.get_session("zephyr/zephyr@" + REALM)

version = "ZEPH0.2"
kind = 0 # unsafe
uid = struct.pack("!4sii", from_ip, time.time(), 0)
ztime = time.time()
port = 0
auth = 1 # yes
authent = session.make_ap_req_bytes()
class_ = "message"
class_inst = "personal"
opcode = ""
sender = str(session.client)
recipient = sys.argv[1]
default_format = ""
multiuid = uid
checksum = 0
multinotice = ""
sig = "py"
message = sys.argv[2]

if "@" not in recipient:
    recipient += "@" + REALM

before_checksum = [
    version,
    None,
    z_make_ascii_32(kind),
    z_make_ascii(uid),
    z_make_ascii_16(port),
    z_make_ascii_32(auth),
    z_make_ascii_32(len(authent)),
    z_make_zcode(authent),
    class_,
    class_inst,
    opcode,
    sender,
    recipient,
    default_format
    ]

after_checksum = [
    multinotice,
    z_make_ascii(multiuid)
    ]

body = [
    sig,
    message
    ]

header_count = len(before_checksum) + 1 + len(after_checksum)
before_checksum[1] = z_make_ascii_32(header_count)

checksum_data = DELIM.join(before_checksum + after_checksum + body)
checksum = z_make_zcode(session.key.make_checksum(KEY_USAGE, checksum_data))

fields = before_checksum + [checksum] + after_checksum + body
notice = DELIM.join(fields)

addr = socket.getaddrinfo("localhost", "zephyr-hm", 0, 0, socket.IPPROTO_UDP)[0]
s = socket.socket(*addr[0:3])
s.sendto(notice, addr[4])
