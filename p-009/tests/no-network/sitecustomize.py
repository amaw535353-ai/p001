"""Deliberately disable sockets and DNS in offline verification."""

import socket


def denied(*_, **__):
    raise RuntimeError("OFFLINE-NETWORK-DENIED")


class DeniedSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        denied()


socket.socket = DeniedSocket
socket.create_connection = denied
socket.getaddrinfo = denied
