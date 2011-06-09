import os

import krb5.ccache

fcc = krb5.ccache.resolve(os.getenv('KRB5CCNAME'))

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
