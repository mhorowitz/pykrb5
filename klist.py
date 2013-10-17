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
import krb5.ccache

fcc = krb5.ccache.resolve()

TIME_FORMAT = "%m/%d/%y %H:%M:%S"

print "Ticket cache:", fcc.name
print "Default principal:", fcc.principal
print "{0:{align}}  {1:{align}}  {2:{align}}".format(
    "Valid starting", "Expires", "Service principal", align=len(TIME_FORMAT))
for s in fcc.sessions:
    print "{0}  {1}  {2}".format(
        s.start_time.strftime(TIME_FORMAT), s.end_time.strftime(TIME_FORMAT),
        s.service)
    if s.renew_until is not None:
        print "\trenew until {0}".format(s.renew_until.strftime(TIME_FORMAT))
    print "\tFlags: {0}".format(
        ", ".join([f.enumname for f in s.ticket_flags]))
    print "\tEtype (skey, tkt): {0}, {1}".format(
        s.key.etype.enumname, s.ticket.encrypted_part.etype.enumname)
    print "\tAddresses: {0}".format(
        ", ".join([str(a) for a in s.addresses]) or "(none)")
