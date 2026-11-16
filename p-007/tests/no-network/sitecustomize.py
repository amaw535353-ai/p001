"""Process-start proof for offline commands; sockets and DNS are disabled."""

import socket


def denied(*args, **kwargs):
    raise RuntimeError("P007-OFFLINE-NETWORK-DISABLED")


socket.socket.connect = denied
socket.socket.connect_ex = denied
socket.getaddrinfo = denied
socket.create_connection = denied
