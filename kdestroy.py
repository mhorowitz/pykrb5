import krb5.ccache

fcc = krb5.ccache.resolve()

fcc.destroy()
