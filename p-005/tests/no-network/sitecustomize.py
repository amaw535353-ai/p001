"""Subprocess network guard; attempts are recorded before raising, even if caught."""

import os
import socket


def denied(*args, **kwargs):
    path = os.environ.get("P005_EGRESS_AUDIT")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write("NETWORK_ATTEMPT\n")
    raise RuntimeError("P005_NETWORK_DISABLED")


class DisabledSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        denied()


socket.socket = DisabledSocket
socket.SocketType = DisabledSocket
for name in (
    "socketpair",
    "fromfd",
    "create_connection",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "getnameinfo",
):
    setattr(socket, name, denied)
