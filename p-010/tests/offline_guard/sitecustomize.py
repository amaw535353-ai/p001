"""Fail on IP socket creation and DNS lookup in the offline test process."""

import socket

_socket = socket.socket


def deny(*_args, **_kwargs):
    raise AssertionError("Offline profile attempted network or DNS access")


class OfflineSocket(_socket):
    def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
        if family != socket.AF_UNIX:
            deny()
        super().__init__(family, type, proto, fileno)


socket.socket = OfflineSocket
for name in (
    "getaddrinfo",
    "getnameinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "create_connection",
):
    setattr(socket, name, deny)
