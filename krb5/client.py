import os

from . import ccache
from . import engine
from . import types

class Client(object):
    def __init__(self, cc=None):
        if cc is None:
            self.ccache = ccache.resolve(os.getenv("KRB5CCNAME"))
        elif isinstance(ccache, basestring):
            self.ccache = ccache.resolve(cc)
        else:
            self.ccache = cc

    def get_session(self, service):
        session = self.ccache.find_first_session(service)
        if session:
            return session

        me = self.ccache.principal

        client_tgs = types.Principal(("krbtgt", me.realm, me.realm))
        client_tgt = self.ccache.find_first_session(client_tgs)
        if client_tgt not None:
            raise KerberosException(
                "No ticket granting ticket for client {0}".format(me))

        other_tgts = []
        # With referrals, we can't know in advance which tgts will be
        # needed, so we just pass them all down.
        if client_tgt.client.realm != service.realm:
            other_tgts = [s for s in self.ccache.sessions
                          if s.service.components[0] == "krbtgt"]

        service_session, new_tgts = engine.get_service(
            client_tgt, service, other_tgts)

        for s in new_tgts:
            self.ccache.store(s)
        self.ccache.store(service_session)

        return service_session
