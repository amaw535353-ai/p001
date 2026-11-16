"""Fail Python network connections/DNS closed, including installed tool workers."""

import socket


def deny(*args, **kwargs):
    raise RuntimeError("P008-OFFLINE-NETWORK-DISABLED")


for method in ("connect", "connect_ex", "bind", "sendto", "sendmsg"):
    setattr(socket.socket, method, deny)
socket.create_connection = deny
socket.getaddrinfo = deny
socket.gethostbyname = deny
