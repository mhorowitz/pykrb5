import datetime
import random

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error

from . import asn1
from . import constants
from . import crypto
from . import session
from . import types

def _raise_krb_error(krb_error):
    code = constants.ErrorCode(krb_error.getComponentByName('error-code'))
    etext = krb_error.getComponentByName('e-text')
    if etext is not None:
        etext = str(etext).rstrip("\0")
    if etext:
        raise types.KerberosException("{0} ({1})".format(
            code.enumname, etext))
    else:
        raise types.KerberosException(code.enumname)

def _make_nonce():
    return random.SystemRandom().getrandbits(32)

def _make_kdc_req_body(kdc_req, service):
    req_body = asn1.seq_set(kdc_req, 'req-body')
    opts = constants.KDCOptions()
    asn1.seq_set_flags(req_body, 'kdc-options', opts)
    req_body.setComponentByName('realm', service.realm)
    asn1.seq_set(req_body, 'sname', service.components_to_asn1)
    req_body.setComponentByName('till', types.KerberosTime.to_asn1(
        types.KerberosTime.INDEFINITE))
    req_body.setComponentByName('nonce', _make_nonce())
    # TODO marc: make the etype list a parameter
    asn1.seq_set_iter(req_body, 'etype',
                      (int(constants.EncType.des3_cbc_sha1_kd),
                       int(constants.EncType.des_cbc_crc)))
    return req_body

def _make_kdc_session(kdc_rep, enc_kdc_rep_part):
    s = session.KDCSession()

    def opt(ctor, component):
        if component is not None:
            return ctor(component)

    s.client = types.Principal().from_asn1(kdc_rep, 'crealm', 'cname')
    s.service = types.Principal().from_asn1(
        enc_kdc_rep_part, 'srealm', 'sname')
    s.key = crypto.Key().from_asn1(
        enc_kdc_rep_part.getComponentByName('key'))
    s.auth_time = types.KerberosTime.from_asn1(
        enc_kdc_rep_part.getComponentByName('authtime'))
    s.start_time = opt(types.KerberosTime.from_asn1,
                       enc_kdc_rep_part.getComponentByName('starttime'))
    s.end_time = types.KerberosTime.from_asn1(
        enc_kdc_rep_part.getComponentByName('endtime'))
    s.renew_until = opt(types.KerberosTime.from_asn1,
                        enc_kdc_rep_part.getComponentByName('renew-till'))
    s.ticket_flags.from_asn1(enc_kdc_rep_part.getComponentByName('flags'))
    s.ticket.from_asn1(kdc_rep.getComponentByName('ticket'))
    # TODO marc: addresses, last_requests
    return s

def _make_as_req_bytes(client, service, padata=None):
    as_req = asn1.ASReq()

    req_body = _make_kdc_req_body(as_req, service)
    asn1.seq_set(req_body, 'cname', client.components_to_asn1)
    req_body.setComponentByName('realm', client.realm)

    as_req.setComponentByName('pvno', 5)
    as_req.setComponentByName('msg-type', int(constants.Asn1Tags.as_req))
    if padata is not None:
        asn1.seq_append(as_req, 'padata', padata)

    return encoder.encode(as_req)

def _parse_as_rep_bytes(bytes):
    """Returns an ASRep or a KrbError."""
    try:
        krb_error, substrate = decoder.decode(bytes, asn1Spec=asn1.KrbError())
        return krb_error
    except PyAsn1Error:
        pass

    as_rep, substrate = decoder.decode(bytes, asn1Spec=asn1.ASRep())
    return as_rep

def _get_pw_key(prompter, client, etype, salt=None):
    if salt is None:
        salt = client.realm + "".join(client.components)

    # Ask the user for their password

    inputs = prompter((("Password for {0}".format(client), True),))

    pw_key = crypto.Key()
    pw_key.etype = etype
    pw_key.set_data_from_string(inputs[0], salt)

    return pw_key

def _do_as_exchange(connection, prompter, client, service):
    # make a new request each time, so the nonce and current timestamp
    # are fresh.

    response = connection.send_kdc(_make_as_req_bytes(client, service))
    if response is None:
        return None

    parsed = _parse_as_rep_bytes(response)
    if isinstance(parsed, asn1.KrbError):
        # TODO marc: if one kdc gives us an error, do we retry, or
        # give up?  For now, give up.

        if constants.ErrorCode(parsed.getComponentByName('error-code')) != \
           constants.ErrorCode.kdc_err_preauth_required:
            _raise_krb_error(parsed)

        preauth_method_data, substrate = decoder.decode(
            parsed.getComponentByName('e-data'),
            asn1Spec=asn1.MethodData())

        return preauth_method_data

    as_rep = parsed

    enc_data = as_rep.getComponentByName('enc-part')

    pw_key = _get_pw_key(prompter, client,
                         constants.EncType(
                             enc_data.getComponentByName('etype')))

    return pw_key, as_rep

def _do_preauth_as_exchange(connection, prompter, client, service,
                            preauth_method_data):
    # TODO marc: We only support password preauthentication
    # via a prompter callback.  A more general interface might
    # get the whole as_rep and is responsible for returning an
    # EncASRepPart (perhaps it returns the decrypted bytes,
    # and we handle the ASN.1 here).

    # Extract the preauth data from the error's e-data

    methods = [
        (constants.PADataTypes(d.getComponentByName('padata-type')),
         d.getComponentByName('padata-value'))
        for d in preauth_method_data]

    patypes = tuple(d[0] for d in methods)

    if constants.PADataTypes.enc_timestamp not in patypes:
        raise types.KerberosException(
            "Can't handle method data patypes {0}".format(patypes))

    # Construct the un-encrypted timestamp

    ts = asn1.PAEncTSEnc()
    now = datetime.datetime.utcnow()
    ts.setComponentByName('patimestamp',
                          types.KerberosTime.to_asn1(now))
    ts.setComponentByName('pausec', now.microsecond)

    # Get the etype and salt from the etype-info2

    ei2_bytes = next((d[1] for d in methods
                      if d[0] == constants.PADataTypes.etype_info2),
                     None)
    ei2, substrate = decoder.decode(
        ei2_bytes, asn1Spec = asn1.ETypeInfo2())

    # Get the etype, and the associated salt if any

    etype = constants.EncType(ei2[0].getComponentByName('etype'))
    salt = ei2[0].getComponentByName('salt')
    
    # Encrypt the timestamp in the user's password, converted
    # to a key.

    pw_key = _get_pw_key(prompter, client, etype, salt)

    enc_ts_bytes = encoder.encode(pw_key.encrypt_as_asn1(
        constants.KeyUsageValue.as_req_pa_enc_timestamp,
        encoder.encode(ts)))

    padata = {
        'padata-type': int(constants.PADataTypes.enc_timestamp),
        'padata-value': enc_ts_bytes
        }

    # Do a preauthenticated request

    response = connection.send_kdc(_make_as_req_bytes(client, service, padata))
    if response is None:
        return None

    parsed = _parse_as_rep_bytes(response)
    if isinstance(parsed, asn1.KrbError):
        _raise_krb_error(parsed)

    as_rep = parsed

    return pw_key, as_rep

def _make_tgs_req_bytes(client_session, service, subkey=None):
    tgs_req = asn1.TGSReq()

    req_body = _make_kdc_req_body(tgs_req, service)

    # TODO marc: TGS only: enc-authorization-data
    # TODO marc: TGS only: additional-tickets

    # This is an annoying problem.  I don't know if this is an
    # ambiguity in the spec, or just a pyasn1 api impedance mismatch.
    # req_body has two tags, a context tag within the containing
    # Sequence, and a sequence tag describing itself.  The MIT kdc
    # computes a checksum without the context tag, but if I naively
    # encode the req-body and checksum it, that includes both tags, so
    # the KDC fails checksum verification.  Empirically, I can clone
    # the req-body with an overriding tagSet, and it all works ok.

    req_body_like_the_kdc_wants_it = req_body.clone(
        tagSet=asn1.KDCReqBody.tagSet, cloneValueFlag=True)

    body_cksum = client_session.key.make_checksum_as_asn1(
        # TGS/AP
        constants.KeyUsageValue.pa_tgs_req_checksum,
        encoder.encode(req_body_like_the_kdc_wants_it))

    ap_req_bytes = client_session.make_ap_req_bytes(
        constants.KeyUsageValue.pa_tgs_req_authenticator,
        checksum=body_cksum, subkey=subkey)

    tgs_req.setComponentByName('pvno', 5)
    tgs_req.setComponentByName('msg-type', int(constants.Asn1Tags.tgs_req))
    asn1.seq_append(tgs_req, 'padata', {
        'padata-type': int(constants.PADataTypes.tgs_req),
        'padata-value': ap_req_bytes
        })

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

def _do_tgs_exchange(connections, client_session, service, subkey=None):
    # TODO marc: add a mechanism to generate a subkey (suggestion: if
    # subkey == True, then make one up.)

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
            _raise_krb_error(parsed)

        return _make_kdc_session(*parsed)

def get_initial_service(connection_factory, prompter, client, service):
    for c in connection_factory.get_connections(client.realm):
        parsed = _do_as_exchange(c, prompter, client, service)

        if parsed is None:
            continue
        elif not isinstance(parsed, asn1.MethodData):
            pw_key, as_rep = parsed
        else:
            method_data = parsed
            parsed = _do_preauth_as_exchange(
                c, prompter, client, service, method_data)
            if parsed is None:
                # TODO marc: this is weird, perhaps it should be an
                # error.
                continue

            pw_key, as_rep = parsed

        dec_data = pw_key.decrypt(
            constants.KeyUsageValue.as_rep_enc_part,
            as_rep.getComponentByName('enc-part').getComponentByName('cipher'))
        try:
            enc_as_rep_part, substrate = decoder.decode(
                dec_data, asn1Spec=asn1.EncASRepPart())
        except PyAsn1Error:
            # The MIT implementation sometimes uses the wrong tag
            # here, so be tolerant of that.
            enc_as_rep_part, substrate = decoder.decode(
                dec_data, asn1Spec=asn1.EncTGSRepPart())

        return _make_kdc_session(as_rep, enc_as_rep_part)

def get_service(connection_factory, client_tgt, service, other_tgts):
    other_sessions = []

    # TODO marc: add support for transited realm configuration,
    # service referrals, and cross-realm routing.

    if client_tgt.client.realm == service.realm:
        service_tgt = client_tgt
    else:
        service_tgs = types.Principal(("krbtgt", service.realm,
                                       client_tgt.client.realm))
        service_tgt = \
            next((s for s in other_tgts if s.service == service), None) or \
            _do_tgs_exchange(
                connection_factory.get_connections(client_tgt.client.realm),
                client_tgt, service_tgs)
        if service_tgt is not None:
            other_sessions.append(service_tgt)

    return (
        _do_tgs_exchange(connection_factory.get_connections(service.realm),
                         service_tgt, service),
        other_sessions)
