"""Runtime token authentication; role/tenant cannot be supplied by request metadata."""

import hmac

from p009.models import Principal
from p009.safety import Denied, digest


class Authenticator:
    def __init__(self, bindings: dict[str, Principal]):
        self.bindings = {digest(k.encode()): v for k, v in bindings.items()}

    def authenticate(self, header: str) -> Principal:
        if not header.startswith("Bearer ") or len(header) > 256:
            raise Denied("AUTHENTICATION-REQUIRED")
        token = digest(header[7:].encode())
        for key, principal in self.bindings.items():
            if hmac.compare_digest(token, key):
                return principal
        raise Denied("AUTHENTICATION-DENIED")
