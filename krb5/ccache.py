import contextlib
import fcntl
import os
import socket
import StringIO
import struct
import datetime

from . import constants
from . import session
from . import types

class CredentialCache(object):
    def find_first_session(self, service):
        for s in self.sessions:
            if s.service == service:
                return s
        else:
            return None

class File(CredentialCache):
    def __init__(self, path):
        self.path = path
        self.name = "FILE:" + self.path

    def create(self, principal, time_offset=None):
        header = {'time_offset': time_offset}

        with self._locked_file('wb') as f:
            self._write(f, header, principal, [])

    def destroy(self):
        # TODO marc: write over the data before removing.
        os.remove(self.path)

    def store(self, session):
        with self._locked_file('r+b') as f:
            header, principal, sessions = self._read(f)
            sessions.append(session)
            self._write(f, header, principal, sessions)

    @property
    def principal(self):
        with self._locked_file('rb') as f:
            return self._read(f)[1]

    @property
    def time_offset(self):
        with self._locked_file('rb') as f:
            return self._read(f)[0].get('time_offset')

    @property
    def sessions(self):
        """This returns a sequence of all the credentials in the ccache.
        If you're looking for a specific credential, we suggest you
        use filter() or a list comprehension with a conditional."""
        with self._locked_file('rb') as f:
            return self._read(f)[2]

    @sessions.setter
    def sessions(self, value):
        """This will modify or create the credential cache with the given
        sessions."""
        with self._locked_file('r+b') as f:
            header, principal, sessions = self._read(f)
            self._write(f, header, principal, value)

    _LOCKDATA = 'hhllhh'
    _FVNO_4 = 0x0504
    _TAG_DELTATIME = 1

    @contextlib.contextmanager
    def _locked_file(self, mode):
        with open(self.path, mode) as f:
            if mode.startswith('r'):
                locktype = fcntl.F_RDLCK
            else:
                locktype = fcntl.F_WRLCK

            # Use fcntl instead of a higher-level locking package
            # for compatibility with the MIT implementation.
            lockdata = struct.pack(self._LOCKDATA, locktype, 0, 0, 0, 0, 0)
            fcntl.fcntl(f, fcntl.F_SETLKW, lockdata)
            try:
                yield f
            finally:
                lockdata = struct.pack(self._LOCKDATA, fcntl.F_UNLCK,
                                       0, 0, 0, 0, 0)
#                fcntl.fcntl(f, fcntl.F_SETLKW, lockdata)

    @staticmethod
    @contextlib.contextmanager
    def _string_io(*args):
        s = StringIO.StringIO(*args)
        try:
            yield s
        finally:
            s.close()

    @staticmethod
    def _read_unpack(file, fmt, eofok=False):
        size = struct.calcsize(fmt)
        buf = file.read(size)
        if len(buf) != size:
            if eofok:
                return None
            else:
                raise types.KerberosException(
                    "Truncated field in file credential cache")
        return struct.unpack(fmt, buf)

    @staticmethod
    def _pack_write(file, fmt, *args):
        file.write(struct.pack(fmt, *args))

    def _read(self, file):
        """Returns header, principal, sessions"""

        file.seek(0)

        fvno, = self._read_unpack(file, '!H')
        if fvno != self._FVNO_4:
            raise types.KerberosException(
                "Bad file ccache version number {0}".format(fvno))

        header = self._read_header_tags(file)
        principal = self._read_principal(file)
        sessions = []

        while True:
            ch = file.read(1)
            if ch == "":
                break
            file.seek(-1, os.SEEK_CUR)

            s = session.ApplicationSession()
            s.client = self._read_principal(file)
            s.service = self._read_principal(file)
            s.key = self._read_key(file)
            s.auth_time = self._read_time(file)
            s.start_time = self._read_time(file)
            s.end_time = self._read_time(file)
            s.renew_until = self._read_time(file)
            file.read(1) # is_skey, redundant with second_ticket
            s.ticket_flags = self._read_ticket_flags(file)
            s.addresses = self._read_addresses(file)
            self._read_authdata(file)
            s.ticket = types.Ticket()
            s.ticket.from_asn1(self._read_data(file))
            s.u2u_ticket = types.Ticket()
            u2u_data = self._read_data(file)
            if u2u_data:
                s.u2u_ticket.from_asn1(u2u_data)
            sessions.append(s)

        return header, principal, sessions

    def _write(self, file, header, principal, sessions):
        pass

    @staticmethod
    def _read_header_tags(file):
        tagslen, = File._read_unpack(file, '!H')
        tags = {}
        with File._string_io(file.read(tagslen)) as tagsfile:
            while True:
                result = File._read_unpack(tagsfile, '!HH', True)
                if result is None:
                    break
                if result[0] == File._TAG_DELTATIME:
                    (sec, usec) = File._read_unpack(tagsfile, '!ii')
                    tags['time_offset'] = sec + usec / 1000000
                else:
                    tagsfile.read(result[1])
        return tags

    @staticmethod
    def _write_header_tags(file, tags):
        with File._string_io() as tagsfile:
            value = tags['time_offset']
            if value:
                sec = int(value)
                usec = value - sec
                _pack_write(tagsfile, '!HHii',
                            File._TAG_DELTATIME, struct.calcsize('!ii'),
                            sec, usec)
            buf = tagsfile.getvalue()
            _pack_write(file, '!H', len(buf))
            file.write(buf)

    @staticmethod
    def _read_principal(file):
        princ = types.Principal()

        princ.type = constants.PrincipalNameType(
            File._read_unpack(file, '!i')[0])
        count, = File._read_unpack(file, '!i')
        princ.realm = File._read_data(file)
        princ.components = [File._read_data(file) for c in xrange(0, count)]

        return princ

    @staticmethod
    def _read_data(file):
        size, = File._read_unpack(file, '!i')
        return file.read(size)

    @staticmethod
    def _read_key(file):
        key = types.Key()
        key.etype = constants.EncType(File._read_unpack(file, '!H')[0])
        key.data = File._read_data(file)
        return key

    @staticmethod
    def _read_time(file):
        return datetime.datetime.fromtimestamp(File._read_unpack(file, '!i')[0])

    @staticmethod
    def _read_ticket_flags(file):
        flags = constants.TicketFlags()
        flags.from_bitmask(File._read_unpack(file, '!i')[0])
        return flags

    @staticmethod
    def _read_addresses(file):
        count, = File._read_unpack(file, '!i')
        addrs = []
        for c in xrange(0, count):
            addr = types.Address()
            addr.type, = File._read_unpack(file, '!H')
            addr.data = File._read_data(file)
            addrs.append(addr)
        return addrs

    @staticmethod
    def _read_authdata(file):
        count, = File._read_unpack(file, '!i')
        for c in xrange(0, count):
            type, = File._read_unpack(file, '!H')
            data = File._read_data(file)

def resolve(name):
    left, colon, right = name.partition(":")
    if left == 'FILE':
        return File(right)
    else:
        return None
