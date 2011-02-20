import re
import struct

from pyasn1.codec.der import decoder, encoder

from . import asn1
from . import constants

class KerberosException(Exception): pass

def _asn1_decode(data, asn1Spec):
    if isinstance(data, basestring):
        data, substrate = decoder.decode(data, asn1Spec=asn1Spec)
        if substrate != '':
            raise KerberosException("asn1 encoding invalid")
    return data

# A principal can be represented as:

class Principal(object):
    """The principal's value can be supplied as:
* a single string
* a sequence containing a sequence of component strings and a realm string
* a sequence whose first n-1 elemeents are component strings and whose last
  component is the realm

If the value contains no realm, then default_realm will be used."""
    def __init__(self, value=None, default_realm=None, type=None):
        self.type = constants.PrincipalNameType.unknown
        self.components = []
        self.realm = None

        if value is None:
            return

        if isinstance(value, basestring):
            m = re.match(r'((?:[^\\]|\\.)+?)(@((?:[^\\@]|\\.)+))?$', value)
            if not m:
                raise KerberosException("invalid principal syntax")

            def unquote_component(comp):
                return re.sub(r'\\(.)', r'\1', comp)

            if m.group(2) is not None:
                self.realm = unquote_component(m.group(3))
            else:
                self.realm = default_realm

            self.components = [
                unquote_component(qc)
                for qc in re.findall(r'(?:[^\\/]|\\.)+', m.group(1))]
        elif len(value) == 2:
            self.components = value[0]
            self.realm = value[-1]
            if isinstance(self.components, basestring):
                self.components = [self.components]
        elif len(value) >= 2:
            self.components = value[0:-1]
            self.realm = value[-1]
        else:
            raise KerberosException("invalid principal value")

        if type is not None:
            self.type = type

    def __eq__(self, other):
        if isinstance(other, basestring):
            other = Principal(other)

        return (self.type == constants.PrincipalNameType.unknown or \
                other.type == constants.PrincipalNameType.unknown or \
                self.type == other.type) and \
            self.components == other.components and \
            self.realm == other.realm

    def __str__(self):
        def quote_component(comp):
            return re.sub(r'([\\/@])', r'\\\1', comp)

        ret = "/".join([quote_component(c) for c in self.components])
        if self.realm is not None:
            ret += "@" + self.realm

        return ret

    def __repr__(self):
        return "Principal((" + repr(self.components) + ", " + \
               repr(self.realm) + "), t=" + str(self.type) + ")"

    def from_asn1(self, data, realm_component, name_component):
        name = data.getComponentByName(name_component)
        self.type = constants.PrincipalNameType(
            name.getComponentByName('name-type'))
        self.components = [
            str(c) for c in name.getComponentByName('name-string')]
        self.realm = str(data.getComponentByName(realm_component))

class Address(object):
    DIRECTIONAL_AP_REQ_SENDER = struct.pack('!I', 0)
    DIRECTIONAL_AP_REQ_RECIPIENT = struct.pack('!I', 1)

    def __init__(self):
        self.type = None
        self.data = None

    def __str__(self):
        family = self.family

        if family is not None:
            return str((family, self.address))
        else:
            return str((self.type, self.value))

    @property
    def family(self):
        if self.type == constants.AddressType.ipv4:
            return socket.AF_INET
        elif self.type == constants.AddressType.ipv6:
            return socket.AF_INET6
            self.address = socket.inet_pton(self.family, data)
        else:
            return None

    @property
    def address(self):
        if self.type == constants.AddressType.ipv4:
            return socket.inet_pton(self.family, data)
        elif self.type == constants.AddressType.ipv6:
            return socket.inet_pton(self.family, data)
        else:
            return None

    def encode(self):
        # ipv4-mapped ipv6 addresses must be encoded as ipv4.
        pass

class Key(object):
    def __init__(self):
        self.etype = None
        self.data = None

    def __str__(self):
        return str((self.etype, "{0} octets".format(len(self.data))))

    # This is gonna need a few more methods someday.

class EncryptedData(object):
    def __init__(self):
        self.etype = None
        self.kvno = None
        self.ciphertext = None

    def from_asn1(self, data):
        data = _asn1_decode(data, asn1.EncryptedData())
        self.etype = constants.EncType(data.getComponentByName('etype'))
        self.kvno = int(data.getComponentByName('kvno'))
        self.ciphertext = str(data.getComponentByName('cipher'))

class Ticket(object):
    def __init__(self):
        # This is the kerberos version, not the service principal key
        # version number.
        self.tkt_vno = None
        self.service_principal = None
        self.encrypted_part = None

    def from_asn1(self, data):
        data = _asn1_decode(data, asn1.Ticket())
        self.tkt_vno = int(data.getComponentByName('tkt-vno'))
        self.service_principal = Principal()
        self.service_principal.from_asn1(data, 'realm', 'sname')
        self.encrypted_part = EncryptedData()
        self.encrypted_part.from_asn1(data.getComponentByName('enc-part'))

    def __str__(self):
        return "<Ticket for {0} vno {1}>".format(self.service_principal,
                                                 self.encrypted_part.kvno)

if __name__ == '__main__':
    # TODO marc: turn this into a real test
    print Principal("marc")
    print Principal(("marc", None))
    print Principal((("marc",), None))
    print Principal("marc@ATHENA.MIT.EDU")
    print Principal("marc", default_realm="ATHENA.MIT.EDU")
    print Principal("marc@ATHENA.MIT.EDU", default_realm="EXAMPLE.COM")
    print Principal(("marc", "ATHENA.MIT.EDU"))
    print Principal((("marc"), "ATHENA.MIT.EDU"))
    print Principal("marc/root")
    print Principal(("marc", "root", "ATHENA.MIT.EDU"))
    print Principal((("marc", "root"), "ATHENA.MIT.EDU"))
    print Principal("marc\\/root")
