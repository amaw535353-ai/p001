"""Subprocess validation hook: fail every attempted Python network operation."""

import socket


def deny(*_args, **_kwargs):
    raise RuntimeError("P004-OFFLINE-NETWORK-DISABLED")


socket.socket.connect = deny
socket.socket.connect_ex = deny
socket.create_connection = deny
socket.getaddrinfo = deny
