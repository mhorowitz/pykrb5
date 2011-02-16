import os
import sys

import krb5.ccache

fcc = krb5.ccache.resolve(os.getenv('KRB5CCNAME'))

for s in fcc.sessions:
    if str(s.server) == sys.argv[1]:
        print "{0}: kvno = {1}".format(s.server, s.ticket.encrypted_part.kvno)
        break
else:
    print "Key not in ccache"
