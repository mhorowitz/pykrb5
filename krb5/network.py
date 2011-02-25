import socket

from . import types

class KDCConnection(object):
    def __init__(self, addr):
        self.addr = addr

    def send_kdc(self, message):
        return "response"

class KDCConnectionFactory(object):
    def get_connections(self, realm):
        # TODO marc: don't hardwire this.
        realms = {"ATHENA.MIT.EDU" : (('kerberos.mit.edu', 88),)}
        
        if realm not in realms:
            raise KerberosException("No KDCs for realm {0}".format(realm))

        for server in realms[realm]:
            for addr in socket.getaddrinfo(*server):
                yield KDCConnection(addr)
