from . import sessions
from . import types

def do_tgs_exchange(connections, tgt, service):
    for c in connections:
        tgs_req = tgt.to_tgs_req()
        tgs_rep = c.send_kdc(tgs_req)
        if tgs_rep.is_ok():
            session = sessions.ApplicationSession()
            session.from_tgs_rep(tgs_rep)
            return session

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
            do_tgs_exchange(
                connection_factory.get_kdcs(client_tgt.client.realm),
                client_tgt, service_tgs)
        if service_tgt is not Null:
            other_sessions.append(service_tgt)

    return [do_tgs_exchange(
        connection_factory.get_kdcs(service.realm), service_tgt, service),
        other_sessions]
