"""Shared address classification for bounded outbound reads.

A company's site on a public address is always in reach; one on a private address (an intranet) only when the
domain allows internal addresses (cremore.domains ``allow_internal``). Never loopback, link-local (cloud metadata
at 169.254.169.254 included), multicast, unspecified, "this network" (0.0.0.0/8) or reserved addresses, nor the
platform addresses clouds put metadata or host services on. An IPv6 address that carries an IPv4 one (mapped, 6to4,
the well-known NAT64 prefix) is judged by that IPv4 address; Teredo, local-use NAT64 and site-local are refused.
Python's ``is_global`` alone is not enough: multicast and NAT64 count as global there.
"""

from __future__ import annotations

import ipaddress

PUBLIC, INTERNAL = "public", "internal"

# Refused whatever the domain allows. Link-local and loopback are refused by kind below; these are the addresses
# a kind does not catch.
_PLATFORM = tuple(ipaddress.ip_network(net) for net in (
    "0.0.0.0/8",           # "this network": never a site, and some systems connect it to themselves
    "168.63.129.16/32",    # Azure's host address (WireServer, platform DNS): a public address in form
    "100.100.100.200/32",  # Alibaba Cloud's instance metadata, inside the shared 100.64.0.0/10
    "fd00:ec2::/64",       # AWS over IPv6: instance metadata (::254), DNS (::253), EKS Pod Identity (::23)
    "fd20:ce::254/128",    # Google Cloud's metadata server over IPv6
    "64:ff9b:1::/48",      # local-use NAT64: its prefix length (and so where the IPv4 sits) is the network's own
    "fec0::/10",           # deprecated site-local
))
_NAT64 = ipaddress.ip_network("64:ff9b::/96")  # the well-known prefix: the IPv4 address is the last 32 bits


def _embedded(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def classify(address) -> str | None:
    """PUBLIC, INTERNAL, or None when the scan never connects there."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if any(ip in net for net in _PLATFORM):
        return None
    if ip.version == 6:
        if ip.teredo is not None:
            return None
        inner = _embedded(ip)
        if inner is not None:
            return classify(inner)
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return None
    return PUBLIC if ip.is_global else INTERNAL  # RFC 1918, unique-local, shared (CGNAT) and the like


def allowed(addresses, *, allow_internal: bool) -> str | None:
    """PUBLIC when every address is public, INTERNAL when some are internal and the domain allows it; None when
    any one may not be reached (a name that also resolves somewhere else is refused whole)."""
    kinds = [classify(address) for address in addresses]
    if not kinds or None in kinds or (INTERNAL in kinds and not allow_internal):
        return None
    return INTERNAL if INTERNAL in kinds else PUBLIC
