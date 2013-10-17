# Copyright (c) 2013, Marc Horowitz
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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

    def to_bit_tuple(self):
        """The return value is implicitly padded out to 32 elements"""
        if len(self) == 0:
            return (0,) * 32

        max_value = max(int(f) for f in self)

        return tuple(1 if self.allowed_values(b) in self else 0
                     for b in xrange(0, max(32, max_value + 1)))

    def from_bit_iter(self, bt):
        self.clear()
        for i, v in enumerate(bt):
            if v == 1:
                self.add(self.allowed_values(i))
        return self

    def to_asn1(self, component):
        return component.clone(self.to_bit_tuple())

    def from_asn1(self, component):
        return self.from_bit_iter(component)

class Asn1Tags(flufl.enum.Enum):
    ticket = 1
    authenticator = 2
    as_req = 10
    as_rep = 11
    tgs_req = 12
    tgs_rep = 13
    ap_req = 14
    ap_rep = 15
    enc_as_rep_part = 25
    enc_tgs_rep_part = 26
    krb_error = 30

class PADataTypes(flufl.enum.Enum):
    tgs_req = 1
    enc_timestamp = 2
    etype_info = 11
    sam_response = 13
    etype_info2 = 19

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
    # the rest aren't in the spec, but are in MIT's source tree.
    enc_pa_rep = 15
    anonymous = 16
    

class TicketFlags(Flags):
    def __init__(self):
        Flags.__init__(self, TicketFlag)

class KDCOption(flufl.enum.Enum):
    reserved = 0
    forwardable = 1
    forwarded = 2
    proxiable = 3
    proxy = 4
    allow_postdate = 5
    postdated = 6
    unused7 = 7
    renewable = 8
    unused9 = 9
    unused10 = 10
    opt_hardware_auth = 11
    unused12 = 12
    unused13 = 13
    unused14 = 14
    unused15 = 15
    disable_transited_check = 26
    renewable_ok = 27
    enc_tkt_in_skey = 28
    renew = 30
    validate = 31

class KDCOptions(Flags):
    def __init__(self):
        Flags.__init__(self, KDCOption)

class APOption(flufl.enum.Enum):
    reserved = 0
    use_session_key = 1
    mutual_required = 2

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

class ChecksumType(flufl.enum.Enum):
    rsa_md5_des = 8
    hmac_sha1_des3_kd = 12

class KeyUsageValue(flufl.enum.Enum):
    as_req_pa_enc_timestamp = 1
    as_rep_enc_part = 3
    tgs_req_auth_data_session = 4
    tgs_req_auth_data_subkey = 5
    pa_tgs_req_checksum = 6
    pa_tgs_req_authenticator = 7
    tgs_rep_session = 8
    tgs_rep_subkey = 9
    ap_req_checksum = 10
    ap_req_authenticator = 11

class ErrorCode(flufl.enum.Enum):
    kdc_err_none = 0
    kdc_err_name_exp = 1
    kdc_err_service_exp = 2
    kdc_err_bad_pvno = 3
    kdc_err_c_old_mast_kvno = 4
    kdc_err_s_old_mast_kvno = 5
    kdc_err_c_principal_unknown = 6
    kdc_err_s_principal_unknown = 7
    kdc_err_principal_not_unique = 8
    kdc_err_null_key = 9
    kdc_err_cannot_postdate = 10
    kdc_err_never_valid = 11
    kdc_err_policy = 12
    kdc_err_badoption = 13
    kdc_err_etype_nosupp = 14
    kdc_err_sumtype_nosupp = 15
    kdc_err_padata_type_nosupp = 16
    kdc_err_trtype_nosupp = 17
    kdc_err_client_revoked = 18
    kdc_err_service_revoked = 19
    kdc_err_tgt_revoked = 20
    kdc_err_client_notyet = 21
    kdc_err_service_notyet = 22
    kdc_err_key_expired = 23
    kdc_err_preauth_failed = 24
    kdc_err_preauth_required = 25
    kdc_err_server_nomatch = 26
    kdc_err_must_use_user2user = 27
    kdc_err_path_not_accepted = 28
    kdc_err_svc_unavailable = 29
    krb_ap_err_bad_integrity = 31
    krb_ap_err_tkt_expired = 32
    krb_ap_err_tkt_nyv = 33
    krb_ap_err_repeat = 34
    krb_ap_err_not_us = 35
    krb_ap_err_badmatch = 36
    krb_ap_err_skew = 37
    krb_ap_err_badaddr = 38
    krb_ap_err_badversion = 39
    krb_ap_err_msg_type = 40
    krb_ap_err_modified = 41
    krb_ap_err_badorder = 42
    krb_ap_err_badkeyver = 44
    krb_ap_err_nokey = 45
    krb_ap_err_mut_fail = 46
    krb_ap_err_baddirection = 47
    krb_ap_err_method = 48
    krb_ap_err_badseq = 49
    krb_ap_err_inapp_cksum = 50
    krb_ap_path_not_accepted = 51
    krb_err_response_too_big = 52
    krb_err_generic = 60
    krb_err_field_toolong = 61
    kdc_error_client_not_trusted = 62
    kdc_error_kdc_not_trusted = 63
    kdc_error_invalid_sig = 64
    kdc_err_key_too_weak = 65
    kdc_err_certificate_mismatch = 66
    krb_ap_err_no_tgt = 67
    kdc_err_wrong_realm = 68
    krb_ap_err_user_to_user_required = 69
    kdc_err_cant_verify_certificate = 70
    kdc_err_invalid_certificate = 71
    kdc_err_revoked_certificate = 72
    kdc_err_revocation_status_unknown = 73
    kdc_err_revocation_status_unavailable = 74
    kdc_err_client_name_mismatch = 75
    kdc_err_kdc_name_mismatch = 76
