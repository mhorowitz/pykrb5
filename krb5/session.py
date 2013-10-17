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

import datetime

from pyasn1.codec.der import decoder, encoder

from . import asn1
from . import constants
from . import types

class Session(object):
    # This is the abstract data which represents a session between a
    # client and service.  The kdc, client, and service all see it.

    def __init__(self):
        self.client = None
        self.service = None
        self.u2u_ticket = None
        self.key = None
        self.auth_time = None
        self.start_time = None
        self.end_time = None
        self.renew_until = None
        self.ticket_flags = constants.TicketFlags()
        self.addresses = []
        self.ticket = types.Ticket()

    def _copy_from(self, other):
        self.client = other.client
        self.service = other.service
        self.u2u_ticket = other.u2u_ticket
        self.key = other.key
        self.auth_time = other.auth_time
        self.start_time = other.start_time
        self.end_time = other.end_time
        self.renew_until = other.renew_until
        self.ticket_flags = other.ticket_flags
        self.addresses = other.addresses
        self.ticket = other.ticket

    def make_ap_req_bytes(self, auth_key_usage,
                          subkey=None, checksum=None):
        now = datetime.datetime.utcnow()

        authenticator = asn1.Authenticator()
        authenticator.setComponentByName('authenticator-vno', 5)
        authenticator.setComponentByName('crealm', self.client.realm)
        asn1.seq_set(authenticator, 'cname',
                     self.client.components_to_asn1)
        if checksum is not None:
            asn1.seq_set_dict(authenticator, 'cksum', checksum)
        authenticator.setComponentByName('cusec', now.microsecond)
        authenticator.setComponentByName('ctime',
                                         types.KerberosTime.to_asn1(now))
        if subkey is not None:
            asn1.seq_set_dict(authenticator, 'subkey', subkey.to_asn1())

        encoder.encode(authenticator)

        ap_req = asn1.APReq()
        ap_req.setComponentByName('pvno', 5)
        ap_req.setComponentByName('msg-type', int(constants.Asn1Tags.ap_req))
        asn1.seq_set_flags(ap_req, 'ap-options', constants.APOptions())
        asn1.seq_set(ap_req, 'ticket', self.ticket.to_asn1)
        asn1.seq_set_dict(ap_req, 'authenticator', 
                          self.key.encrypted_data(
                              auth_key_usage, encoder.encode(authenticator)))

        return encoder.encode(ap_req)

class KDCSession(Session):
    # This is the full set of stuff shared between the kdc and client.

    def __init__(self):
        Session.__init__(self)
        self.last_requests = {}
        # AS only, only if provided in preauthentication.
        self.kdc_time = None

class ApplicationSession(Session):
    # This is the full set of stuff shared between the client and service.

    def __init__(self, client_session):
        Session.__init__(self)
        self._copy_from(client_session)
        self.ap_options = constants.APOptions()
        self.client_subkey = None
        self.client_seqno = None
        self.service_seqno = None
        self.service_subkey = None
        self.client_authorization_data = []

    def make_ap_req_bytes(self, checksum_data=None, subkey=None):
        checksum = None
        if checksum_data is not None:
            checksum = self.key.make_checksum_as_asn1(
                constants.KeyUsageValue.ap_req_checksum, checksum_data)

        return Session.make_ap_req_bytes(
            self, constants.KeyUsageValue.ap_req_authenticator,
            checksum=checksum, subkey=subkey)

    def consume_ap_rep_bytes(self, bytes):
        pass

class ServiceApplicationSession(ApplicationSession):
    # The service gets to see some stuff from the ticket which client
    # doesn't.

    def __init__(self):
        Session.__init__(self)
        self.transited_data = []
        self.ticket_authorization_data = []

# authz data: since this is hard to pick out of the rfc, for my own
# reference: the client can pass authz data to the kdc as part of a
# tgs request.  The input tgt or proxy ticket may include authz data.
# The kdc may issue its own authz data.  This all gets stored in the
# ticket in the tgs-rep.  The client can remember the authz data it
# encoded in the tgs, but it can't know for sure what's in the ticket
# (although this is a function of what it requested), and can't see
# any kdc-issued authz data at all.  additionally, the client can
# include authz data in the authenticator.  The python representation
# is TBD




# what goes in the ccache?  whatever is necessary to avoid a redundant
# kdc transaction.  This includes everything in Session for sure.  In
# the case of a u2u session, the second_ticket is semantically part of
# the service identity, so that needs to be there, too.  The MIT impl
# stores is_skey (which is redundant with second_ticket afaict), and
# authdata, which I'm really not sure about.  Presumably this will
# become clearer if and when I have a use case for this.


# basic operations:

# password -> KDCSession with kdc [tgs]

# tgs -> KDCSession with service

# tgs + other-client-ticket -> u2u KDCSession

# KDCSession -> ApplicationSession (one-way or mutual)

# ApplicationSessibon + data -> safe, priv

# ApplicationSession -> keys
