"""The addresses the web exposure scan may reach (N4b)."""

from cremore_website_provider.addresses import INTERNAL, PUBLIC, allowed, classify


def test_public_internal_and_never():
    for address in ("8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1"):
        assert classify(address) == PUBLIC, address
    for address in ("10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "fc00::1", "fd12:3456::1",
                    "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::1"):
        assert classify(address) == INTERNAL, address
    # Loopback, link-local (cloud metadata), multicast, unspecified, reserved, platform hosts, whatever the form.
    for address in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "169.254.169.254", "fe80::1",
                    "224.0.0.1", "ff02::1", "0.0.0.0", "0.1.2.3", "::ffff:0.0.0.1", "::", "240.0.0.1", "255.255.255.255", "168.63.129.16",
                    "100.100.100.200", "fd00:ec2::254", "64:ff9b::a9fe:a9fe", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
                    # AWS DNS and EKS Pod Identity, Google's metadata over IPv6, a local-use NAT64 whose /48 prefix
                    # puts 169.254.169.254 where a last-32-bits reading sees a public address, and site-local.
                    "fd00:ec2::253", "fd00:ec2::23", "fd20:ce::254", "64:ff9b:1:a9fe:a9:fe00:808:808", "fec0::1",
                    "not-an-address", "127.0x1"):
        assert classify(address) is None, address


def test_a_name_is_reached_only_when_every_address_may_be():
    assert allowed(["8.8.8.8", "2606:4700::1111"], allow_internal=False) == PUBLIC
    assert allowed(["8.8.8.8", "10.0.0.5"], allow_internal=False) is None  # split answers never slip inside
    assert allowed(["8.8.8.8", "10.0.0.5"], allow_internal=True) == INTERNAL
    assert allowed(["10.0.0.5", "127.0.0.1"], allow_internal=True) is None
    assert allowed([], allow_internal=True) is None
