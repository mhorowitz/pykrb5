import sys

import krb5.client

if __name__ == '__main__':
    client = krb5.client.Client()
    session = client.get_session(sys.argv[1])

    print "{0}: kvno = {1}".format(session.service,
                                   session.ticket.encrypted_part.kvno)
