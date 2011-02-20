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

class ClientSession(Session):
    # This is the full set of stuff shared between the kdc and client.

    def __init__(self):
        Session.__init__(self)
        self.last_requests = {}

class ApplicationSession(Session):
    # This is the full set of stuff shared between the client and service.

    def __init__(self):
        Session.__init__(self)
        self.ap_options = constants.APOptions()
        self.client_subkey = None
        self.client_seqno = None
        self.service_seqno = None
        self.service_subkey = None
        self.client_authorization_data = []

    # ap options, subkey (one per direction), sequence number
    # (one per direction), client authz data.

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

# password -> ClientSession with kdc [tgs]

# tgs -> ClientSession with service

# tgs + other-client-ticket -> u2u ClientSession

# ClientSession -> ApplicationSession (one-way or mutual)

# ApplicationSessibon + data -> safe, priv

# ApplicationSession -> keys
