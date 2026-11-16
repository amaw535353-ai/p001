"""Disable real sockets/DNS while retaining in-process HTTP adapter fixtures."""
import socket

_connect = socket.socket.connect


def forbidden(*args, **kwargs):
    raise RuntimeError("P006_OFFLINE_NETWORK_FORBIDDEN")


def connect(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        forbidden()
    return _connect(self, address)


socket.socket.connect = connect
socket.create_connection = forbidden
socket.getaddrinfo = forbidden
socket.gethostbyname = forbidden
socket.gethostbyname_ex = forbidden
