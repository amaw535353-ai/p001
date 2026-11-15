"""No DNS, redirects, prefix expansion, IDNA conversion, or target requests."""

import ipaddress
import re
from urllib.parse import urlsplit


def subnet(inner, outer):
    return (
        inner.version == outer.version
        and int(inner.network_address) >= int(outer.network_address)
        and int(inner.broadcast_address) <= int(outer.broadcast_address)
    )


def host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        if not address.is_loopback:
            raise ValueError("only loopback IPs")
        return str(address)
    except ValueError as exc:
        value = value.lower()
        if not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.test", value
        ):
            raise ValueError("only literal loopback or reserved .test identifiers") from exc
        if any(x.startswith("xn--") or len(x) > 63 for x in value.split(".")) or len(value) > 253:
            raise ValueError("IDNA or oversized host rejected") from exc
        return value


def normalize(kind: str, value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048 or not value.isascii():
        raise ValueError("target encoding/size")
    if any(ord(x) <= 32 or ord(x) == 127 for x in value) or any(x in value for x in "%\\*?#@"):
        raise ValueError("ambiguous target encoding/indirection")
    if kind == "url":
        p = urlsplit(value)
        if p.scheme.lower() not in ("http", "https") or not p.hostname or not p.netloc:
            raise ValueError("absolute HTTP(S) target required")
        if p.netloc.startswith("[") and not re.fullmatch(r"\[[0-9a-fA-F:.]+\](?::[0-9]+)?", p.netloc):
            raise ValueError("ambiguous bracketed authority")
        h = host(p.hostname)
        port = p.port if p.port is not None else (80 if p.scheme.lower() == "http" else 443)
        if not 1 <= port <= 65535 or p.netloc.endswith(":"):
            raise ValueError("invalid port")
        path = p.path or "/"
        if not re.fullmatch(r"/[A-Za-z0-9/_~.:-]*", path):
            raise ValueError("unsupported path characters")
        if "//" in path or any(x in (".", "..") for x in path.split("/")):
            raise ValueError("ambiguous path")
        h = "[" + h + "]" if ":" in h else h
        return f"{p.scheme.lower()}://{h}:{port}{path}"
    if kind in ("ip", "host"):
        h = host(value)
        if kind == "ip":
            return str(ipaddress.ip_address(h))
        return h
    if kind == "cidr":
        network = ipaddress.ip_network(value, strict=True)
        allowed = ipaddress.ip_network("127.0.0.0/8" if network.version == 4 else "::1/128")
        if not subnet(network, allowed):
            raise ValueError("CIDR outside loopback")
        return str(network)
    if kind in ("namespace", "project") and re.fullmatch(r"p00[123]:[a-z0-9][a-z0-9:_-]{0,127}", value):
        return value
    raise ValueError("unmodeled target type")


def matches(kind: str, selector: str, target_kind: str, target: str) -> bool:
    if kind == target_kind and selector == target:
        return True
    if kind == "cidr":
        network = ipaddress.ip_network(selector)
        try:
            if target_kind == "cidr":
                other = ipaddress.ip_network(target)
                return subnet(other, network)
            address = ipaddress.ip_address(
                (urlsplit(target).hostname or "") if target_kind == "url" else target
            )
            return address.version == network.version and address in network
        except ValueError:
            return False
    return False
