import sys

import krb5.client

if __name__ == '__main__':
    client = krb5.client.Client()
    name = sys.argv[1] if len(sys.argv) > 1 else None
    session = client.get_pw_session(krb5.client.terminal_prompter, name)
