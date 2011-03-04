import os

from . import ccache
from . import engine
from . import network
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
        service = types.Principal(service)

        session = next((s for s in self.ccache.sessions
                        if s.service == service), None)
        if session:
            return session

        me = self.ccache.principal

        client_tgs = types.Principal(("krbtgt", me.realm, me.realm))
        client_tgt = next((s for s in self.ccache.sessions
                           if s.service == client_tgs), None)
        if client_tgt is None:
            raise types.KerberosException(
                "No ticket granting ticket {0} for client {1}".format(
                    client_tgs, me))

        other_tgts = []
        # With referrals, we can't know in advance which tgts will be
        # needed, so we just pass them all down.
        if client_tgt.client.realm != service.realm:
            other_tgts += (s for s in self.ccache.sessions
                           if s.service.components[0] == "krbtgt")

        service_session, new_tgts = engine.get_service(
            network.KDCConnectionFactory(), client_tgt, service, other_tgts)

#        for s in new_tgts:
#            self.ccache.store(s)
#        if service_session is not None:
#            self.ccache.store(service_session)

        return service_session
