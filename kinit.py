import sys

import krb5.client

if __name__ == '__main__':
    client = krb5.client.Client()
    session = client.get_pw_session(krb5.client.terminal_prompter, sys.argv[1])

    print "Success."
