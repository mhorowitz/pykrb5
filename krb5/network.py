import socket
import struct

from . import types

class KDCConnection(object):
    def __init__(self, addr):
        self.addr = addr

    @staticmethod
    def recv_all(socket, count):
        data = ""
        while count > 0:
            buf = socket.recv(count)
            if buf == "":
                return data
            data += buf
            count -= len(buf)
        return data

    def send_kdc(self, message):
        s = socket.socket(*self.addr[0:3])
        if self.addr[2] == socket.IPPROTO_TCP:
            s.connect(self.addr[4])
            s.settimeout(3)
            s.sendall(struct.pack('!i', len(message)))
            s.sendall(message)

            rep_len = struct.unpack('!i', self.recv_all(s, 4))
            rep = self.recv_all(s, rep_len)
            s.close()
            return rep
        elif self.addr[2] == socket.IPPROTO_UDP:
            # s.connect(self.addr[4])
            s.sendto(message, self.addr[4])
            # this is a UDP socket, so just specify a buffer larger
            # than a typical IP packet, and we'll get the next packet.
            return s.recv(1500)

class KDCConnectionFactory(object):
    def get_connections(self, realm):
        # TODO marc: don't hardwire this.
        realms = {"ATHENA.MIT.EDU" : (('kerberos.mit.edu', 88),),
                  "NERD-MILITIA.ORG" : (('kerberos.nerd-militia.org', 88),),
                  "TOYBOX.ORG" : (('69.25.196.68', 88),),
                  }
        
        if realm not in realms:
            raise types.KerberosException("No KDCs for realm {0}".format(realm))

        for server in realms[realm]:
            for addr in socket.getaddrinfo(
                server[0], server[1], 0, 0, socket.IPPROTO_UDP):
                yield KDCConnection(addr)
