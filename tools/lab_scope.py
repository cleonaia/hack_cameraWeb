"""Address scope checks shared by tools that operate on the local lab."""

import ipaddress


LAB_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)


def parse_lab_ipv4(value: str) -> ipaddress.IPv4Address:
    """Parse an IPv4 address and reject destinations outside local lab ranges."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"invalid IPv4 address: {value}") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("only IPv4 addresses are supported")
    if not any(address in network for network in LAB_NETWORKS):
        raise ValueError(f"{address} is outside the private/local lab address ranges")
    return address
