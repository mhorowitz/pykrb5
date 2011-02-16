import flufl.enum

class RestrictedSet(set):
    """Like set, but only a restricted set of values are permitted"""

    def __init__(self, allowed_values):
        """allowed_values can be anything which implements the 'in'
        membership operator"""

        set.__init__(self)
        self.allowed_values = allowed_values
        self.clear()

    def _check_allowed(self, value):
        if value not in self.allowed_values:
            raise KeyError("{0} is not a {1}".format(
                value, type(self).__name__))

    @staticmethod
    def _wrap_elem_check(method):
        def f(self, elem):
            self._check_allowed(elem)
            return method(self, elem)
        f.__name__ = method.__name__
        return f

    @staticmethod
    def _wrap_other_check(method):
        def f(self, other):
            for elem in other:
                self._check_allowed(elem)
            return method(self, other)
        return f

    @staticmethod
    def _wrap_others_check(method):
        def f(self, *others):
            for other in others:
                for elem in other:
                    self._check_allowed(elem)
            return method(self, *others)
        return f

for f in ('add', 'remove', 'discard'):
    setattr(RestrictedSet, f, RestrictedSet._wrap_elem_check(getattr(set, f)))
for f in ('__or__', '__and__', '__sub__',
          'symmetric_difference', '__xor__',
          'symmetric_difference_update', '__ixor__'):
    setattr(RestrictedSet, f, RestrictedSet._wrap_other_check(getattr(set, f)))
for f in ('union', 'difference', 'update', 'intersection_update',
          'difference_update'):
    setattr(RestrictedSet, f, RestrictedSet._wrap_others_check(getattr(set, f)))

class Flags(RestrictedSet):
    def __init__(self, allowed_values):
        """allowed_values must be a flufl.enum.Enum class"""
        RestrictedSet.__init__(self, allowed_values)

    # This class might at first seem generic, but the encoding of the
    # bit values into the mask is a bit unusual.  See rfc4120 section
    # 5.2.8.

    def to_bitmask(self):
        mask = 0
        for f in self:
            mask |= 1 << (31 - int(f))
        return mask

    def from_bitmask(self, mask):
        self.clear()
        for f in self.allowed_values:
            if mask & (1 << (31 - int(f))) != 0:
                self.add(f)

class TicketFlag(flufl.enum.Enum):
    reserved = 0
    forwardable = 1
    forwarded = 2
    proxiable = 3
    proxy = 4
    may_postdate = 5
    postdated = 6
    invalid = 7
    renewable = 8
    initial = 9
    pre_authent = 10
    hw_authent = 11
    transited_policy_checked = 12
    ok_as_delegate = 13

class TicketFlags(Flags):
    def __init__(self):
        Flags.__init__(self, TicketFlag)

class APOption(flufl.enum.Enum):
    pass

class APOptions(Flags):
    def __init__(self):
        Flags.__init__(self, APOption)

class AddressType(flufl.enum.Enum):
    ipv4 = 2
    directional = 3
    chaosnet = 5
    xns = 6
    iso = 7
    decnet_phase_iv = 12
    appletalk_ddp = 16
    netbios = 20
    ipv6 = 24

class LastRequestType(flufl.enum.Enum):
    # TODO
    pass

class AuthorizationDataType(flufl.enum.Enum):
    # TODO
    pass

class PrincipalNameType(flufl.enum.Enum):
    unknown = 0
    principal = 1
    srv_inst = 2
    srv_hst = 3
    srv_xhst = 4
    uid = 5
    x500_principal = 6
    smtp_name = 7
    enterprise = 10

class EncType(flufl.enum.Enum):
    des_cbc_crc = 1
    des_cbc_md4 = 2
    des_cbc_md5 = 3
    _reserved_4 = 4
    des3_cbc_md5 = 5
    _reserved_6 = 6
    des3_cbc_sha1 = 7
    dsaWithSHA1_CmsOID = 9
    md5WithRSAEncryption_CmsOID = 10
    sha1WithRSAEncryption_CmsOID = 11
    rc2CBC_EnvOID = 12
    rsaEncryption_EnvOID = 13
    rsaES_OAEP_ENV_OID = 14
    des_ede3_cbc_Env_OID = 15
    des3_cbc_sha1_kd = 16
    aes128_cts_hmac_sha1_96 = 17
    aes256_cts_hmac_sha1_96 = 18
    rc4_hmac = 23
    rc4_hmac_exp = 24
    subkey_keymaterial = 65
