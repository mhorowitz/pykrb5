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

import getpass
import os
import sys

from . import ccache
from . import tgs_client
from . import network
from . import session
from . import types

def terminal_prompter(prompts, name=None, banner=None):
    if name:
        print name
    if banner:
        print banner

    inputs = []

    for text, hidden in prompts:
        if hidden:
            value = getpass.getpass(text + ": ")
        else:
            print text,
            value = sys.stdin.readline()
            value = value.rstrip("\n")
        inputs.append(value)

    return inputs

class Client(object):
    def __init__(self, cc=None):
        if cc is None:
            self.ccache = ccache.resolve()
        elif isinstance(cc, basestring):
            self.ccache = ccache.resolve(cc)
        else:
            self.ccache = cc

    def get_principal(self):
        return self.ccache.principal

    def get_pw_session(self, prompter, client=None, service=None):
        if client is None:
            client = self.get_principal()
            # TODO marc: do something useful if there's no ccache.
            # This requires a notion of default realm, which we
            # currently do not have.
        else:
            client = types.Principal(client)
        if service is None:
            service = types.Principal(("krbtgt", client.realm, client.realm))
        else:
            service = types.Principal(service)

        kdc_session = tgs_client.get_initial_service(
            network.KDCConnectionFactory(), prompter, client, service)

        self.ccache.create(client)
        self.ccache.store(kdc_session)

        return kdc_session

    def get_kdc_session(self, service):
        service = types.Principal(service)

        kdc_session = next((s for s in self.ccache.sessions
                            if s.service == service), None)
        if kdc_session:
            return kdc_session

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

        kdc_session, new_tgts = tgs_client.get_service(
            network.KDCConnectionFactory(), client_tgt, service, other_tgts)

        for s in new_tgts:
            self.ccache.store(s)
        if kdc_session is not None:
            self.ccache.store(kdc_session)

        return kdc_session

    def get_session(self, service):
        return session.ApplicationSession(self.get_kdc_session(service))
