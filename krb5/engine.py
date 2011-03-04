import datetime
import random

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error

from . import asn1
from . import constants
from . import crypto
from . import session
from . import types

def _make_nonce():
    return random.SystemRandom().getrandbits(32)

def _make_tgs_req_bytes(client_session, service, subkey=None):
    tgs_req = asn1.TGSReq()

    req_body = asn1.seq_set(tgs_req, 'req-body')
    opts = constants.KDCOptions()
    asn1.seq_set_flags(req_body, 'kdc-options', opts)
    asn1.seq_set(req_body, 'cname', client_session.client.components_to_asn1)
    req_body.setComponentByName('realm', client_session.client.realm)
    asn1.seq_set(req_body, 'sname', service.components_to_asn1)
    req_body.setComponentByName('till', types.KerberosTime.to_asn1(
        types.KerberosTime.INDEFINITE))
    req_body.setComponentByName('nonce', _make_nonce())
    asn1.seq_set_iter(req_body, 'etype', (int(constants.EncType.des_cbc_crc),))

    # This is an annoying problem.  I don't know if this is an
    # ambiguity in the spec, or just a pyasn1 api impedance mismatch.
    # req_body has two tags, a context tag within the containing
    # Sequence, and a sequence tag describing itself.  The MIT kdc
    # computes a checksum without the context tag, but if I naively
    # encode the req-body and checksum it, that includes both tags, so
    # the KDC fails checksum verification.  Empirically, I can clone
    # the req-body with an overriding tag-set, and it all works ok.

    req_body_like_the_kdc_wants_it = req_body.clone(
        tagSet=asn1.KDCReqBody.tagSet, cloneValueFlag=True)

    # TODO marc: different usage for ap exchange

    body_cksum = client_session.key.make_checksum_as_asn1(
        constants.KeyUsageValue.pa_tgs_req_checksum,
        encoder.encode(req_body_like_the_kdc_wants_it))

    now = datetime.datetime.utcnow()

    authenticator = asn1.Authenticator()
    authenticator.setComponentByName('authenticator-vno', 5)
    authenticator.setComponentByName('crealm', client_session.client.realm)
    asn1.seq_set(authenticator, 'cname',
                 client_session.client.components_to_asn1)
    asn1.seq_set_dict(authenticator, 'cksum', body_cksum)
    authenticator.setComponentByName('cusec', now.microsecond)
    authenticator.setComponentByName('ctime', types.KerberosTime.to_asn1(now))
    if subkey is not None:
        asn1.seq_set_dict(authenticator, 'subkey', subkey.to_asn1())

    encoder.encode(authenticator)

    ap_req = asn1.APReq()
    ap_req.setComponentByName('pvno', 5)
    ap_req.setComponentByName('msg-type', int(constants.Asn1Tags.ap_req))
    asn1.seq_set_flags(ap_req, 'ap-options', constants.APOptions())
    asn1.seq_set(ap_req, 'ticket', client_session.ticket.to_asn1)
    asn1.seq_set_dict(ap_req, 'authenticator', 
                      client_session.key.encrypt_as_asn1(
                          constants.KeyUsageValue.pa_tgs_req_authenticator,
                          encoder.encode(authenticator)))

    tgs_req.setComponentByName('pvno', 5)
    tgs_req.setComponentByName('msg-type', int(constants.Asn1Tags.tgs_req))
    asn1.seq_append(tgs_req, 'padata', {
        'padata-type': int(constants.PreauthTypes.tgs_req),
        'padata-value': encoder.encode(ap_req)
        })

    print tgs_req, ap_req, authenticator
    print repr(encoder.encode(tgs_req))

    return encoder.encode(tgs_req)

def _parse_tgs_rep_bytes(bytes, client_session, subkey=None):
    """Returns a tuple of (TGSRep, EncKDCRepPart), or a KrbError."""
    try:
        krb_error, substrate = decoder.decode(bytes, asn1Spec=asn1.KrbError())
        return krb_error
    except PyAsn1Error:
        pass

    tgs_rep, substrate = decoder.decode(bytes, asn1Spec=asn1.TGSRep())
    enc_data = tgs_rep.getComponentByName(
        'enc-part').getComponentByName('cipher')
    if subkey is not None:
        dec_data = subkey.decrypt(
            constants.KeyUsageValue.tgs_rep_subkey, enc_data)
    else:
        dec_data = client_session.key.decrypt(
            constants.KeyUsageValue.tgs_rep_session, enc_data)
    enc_tgs_rep_part, substrate = decoder.decode(
        dec_data, asn1Spec=asn1.EncTGSRepPart())
    return (tgs_rep, enc_tgs_rep_part)

def do_tgs_exchange(connections, client_session, service, subkey=None):
    for c in connections:
        # make a new request each time, so the nonce and current timestamp
        # are fresh.
        response = c.send_kdc(_make_tgs_req_bytes(client_session, service,
                                                  subkey=subkey))
        if response is None:
            continue

        parsed = _parse_tgs_rep_bytes(response, client_session, subkey=subkey)
        if isinstance(parsed, asn1.KrbError):
            # TODO marc: if one kdc gives us an error, do we retry, or
            # give up?  For now, give up.
            raise types.KerberosException(constants.ErrorCode(
                parsed.getComponentByName('error-code')).enumname)

        tgs_rep, enc_tgs_rep_part = parsed
        s = session.ApplicationSession()

        def opt(ctor, component):
            if component is not None:
                return ctor(component)

        s.client = types.Principal().from_asn1(tgs_rep, 'crealm', 'cname')
        s.service = types.Principal().from_asn1(
            enc_tgs_rep_part, 'srealm', 'sname')
        s.key = crypto.Key().from_asn1(
            enc_tgs_rep_part.getComponentByName('key'))
        s.auth_time = types.KerberosTime.from_asn1(
            enc_tgs_rep_part.getComponentByName('authtime'))
        s.start_time = opt(types.KerberosTime.from_asn1,
                           enc_tgs_rep_part.getComponentByName('starttime'))
        s.end_time = types.KerberosTime.from_asn1(
            enc_tgs_rep_part.getComponentByName('endtime'))
        s.renew_until = opt(types.KerberosTime.from_asn1,
                            enc_tgs_rep_part.getComponentByName('renew-till'))
        s.ticket_flags.from_asn1(enc_tgs_rep_part.getComponentByName('flags'))
        s.ticket.from_asn1(tgs_rep.getComponentByName('ticket'))
        # TODO marc: addresses, last_requests
        return s

def get_service(connection_factory, client_tgt, service, other_tgts):
    other_sessions = []

    # TODO marc: add support for transited realm configuration,
    # service referrals, and cross-realm routing.

#   from . import crypto
#   tgt_key = crypto.Key()
#   tgt_key.etype = constants.EncType.des_cbc_crc
#   tgt_key.data = "\x1c\x58\xfd\xc2\xa8\x37\x1c\x5e"
#   print client_tgt.ticket.encrypted_part.kvno
#   tgt_key.decrypt(0, client_tgt.ticket.encrypted_part.ciphertext)

    if client_tgt.client.realm == service.realm:
        service_tgt = client_tgt
    else:
        service_tgs = types.Principal(("krbtgt", service.realm,
                                       client_tgt.client.realm))
        service_tgt = \
            next((s for s in other_tgts if s.service == service), None) or \
            do_tgs_exchange(
                connection_factory.get_connections(client_tgt.client.realm),
                client_tgt, service_tgs)
        if service_tgt is not Null:
            other_sessions.append(service_tgt)

    return (
        do_tgs_exchange(connection_factory.get_connections(service.realm),
                        service_tgt, service),
        other_sessions)
