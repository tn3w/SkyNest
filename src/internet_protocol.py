"""
src/internet_protocol.py

This module provides utility functions for validating, converting, and managing IP addresses, 
both IPv4 and IPv6.
"""

from typing import Final, Optional
from re import VERBOSE, IGNORECASE, Pattern, compile as pattern_compile


UNWANTED_IPV4_RANGES: Final[list] = [
    ('0.0.0.0', '0.255.255.255'),
    ('10.0.0.0', '10.255.255.255'),
    ('100.64.0.0', '100.127.255.255'),
    ('127.0.0.0', '127.255.255.255'),
    ('169.254.0.0', '169.254.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.0.0.0', '192.0.0.255'),
    ('192.0.2.0', '192.0.2.255'),
    ('192.88.99.0', '192.88.99.255'),
    ('192.168.0.0', '192.168.255.255'),
    ('198.18.0.0', '198.19.255.255'),
    ('198.51.100.0', '198.51.100.255'),
    ('203.0.113.0', '203.0.113.255'),
    ('224.0.0.0', '239.255.255.255'),
    ('233.252.0.0', '233.252.0.255'),
    ('240.0.0.0', '255.255.255.254'),
    ('255.255.255.255', '255.255.255.255')
]
UNWANTED_IPV6_RANGES: Final[list] = [
    ('::', '::'),
    ('::1', '::1'),
    ('::ffff:0:0', '::ffff:0:ffff:ffff'),
    ('64:ff9b::', '64:ff9b::ffff:ffff'),
    ('64:ff9b:1::', '64:ff9b:1:ffff:ffff:ffff:ffff'),
    ('100::', '100::ffff:ffff:ffff:ffff'),
    ('2001::', '2001:0:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('2001:20::', '2001:2f:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('2001:db8::', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('2002::', '2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('5f00::', '5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('fc00::', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('fe80::', 'fe80::ffff:ffff:ffff:ffff'),
    ('ff00::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
]
IPV4_PATTERN: Final[str] = r'^(\d{1,3}\.){3}\d{1,3}$'
IPV6_PATTERN: Final[str] = r"""
    ^(
        ([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4} |
        ([0-9a-fA-F]{1,4}:){1,7}: |
        :(:[0-9a-fA-F]{1,4}){1,7} |
        ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4} |
        ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2} |
        ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3} |
        ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4} |
        ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5} |
        [0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}) |
        :((:[0-9a-fA-F]{1,4}){1,7}|:) |
        ([0-9a-fA-F]{1,4}:){1,7}:
    )$
"""

COMPILED_IPV4_REGEX: Final[Pattern] = pattern_compile(IPV4_PATTERN, VERBOSE | IGNORECASE)
COMPILED_IPV6_REGEX: Final[Pattern] = pattern_compile(IPV6_PATTERN, VERBOSE | IGNORECASE)


def is_ipv4(ip_address: str) -> bool:
    """
    Checks whether the given IP address is version 4.

    Args:
        ip_address (str): The IP address to check.
    
    Returns:
        bool: True if the IP address is version 4, False otherwise.
    """

    if not isinstance(ip_address, str):
        return False

    return bool(COMPILED_IPV4_REGEX.match(ip_address))


def is_ipv6(ip_address: str) -> bool:
    """
    Checks whether the given IP address is version 6.

    Args:
        ip_address (str): The IP address to check.
    
    Returns:
        bool: True if the IP address is version 6, False otherwise.
    """

    if not isinstance(ip_address, str):
        return False

    return bool(COMPILED_IPV6_REGEX.match(ip_address))


def ipv4_to_int(ipv4_address: str) -> int:
    """
    Converts an IPv4 address to an integer.

    Args:
        ipv4_address (str): The IPv4 address to convert.
    
    Returns:
        int: The integer representation of the IPv4 address.
    """

    parts = map(int, ipv4_address.split('.'))
    return sum(part << (8 * (3 - i)) for i, part in enumerate(parts))


def ipv6_to_int(ipv6_address: str) -> int:
    """
    Converts an IPv6 address to an integer.

    Args:
        ipv6_address (str): The IPv6 address to convert.
    
    Returns:
        int: The integer representation of the IPv6 address.
    """

    parts = ipv6_address.split(':')
    parts = [int(part, 16) if part else 0 for part in parts]

    ip_int = 0
    for i, part in enumerate(parts):
        ip_int += part << (16 * (7 - i))

    return ip_int


def is_unwanted_ipv4(ipv4_address: Optional[str] = None) -> bool:
    """
    Checks whether the given IPv4 address is unwanted.

    Args:
        ipv4_address (str): The IPv4 address to check.

    Returns:
        bool: True if the IPv4 address is unwanted, False otherwise.
    """

    if not isinstance(ipv4_address, str):
        return False

    ipv4_address_int = ipv4_to_int(ipv4_address)

    for start_ip, end_ip in UNWANTED_IPV4_RANGES:
        start_ipv4_int = ipv4_to_int(start_ip)
        end_ipv4_int = ipv4_to_int(end_ip)

        if start_ipv4_int <= ipv4_address_int <= end_ipv4_int:
            return True

    return False


def is_unwanted_ipv6(ipv6_address: Optional[str] = None) -> bool:
    """
    Checks whether the given IPv6 address is unwanted.

    Args:
        ipv6_address (str): The IPv6 address to check.
    
    Returns:
        bool: True if the IPv6 address is unwanted, False otherwise.
    """

    if not isinstance(ipv6_address, str):
        return False

    ipv6_address_int = ipv6_to_int(ipv6_address)

    for start_ipv6, end_ipv6 in UNWANTED_IPV6_RANGES:
        start_ipv6_int = ipv6_to_int(start_ipv6)
        end_ipv6_int = ipv6_to_int(end_ipv6)

        if start_ipv6_int <= ipv6_address_int <= end_ipv6_int:
            return True

    return False


def is_valid_ip(ip_address: Optional[str] = None,
                without_filter: bool = False) -> bool:
    """
    Checks whether the given IP address is valid.

    Args:
        ip_address (str): The IP address to check.
        without_filter (bool): If True, the input IP address will not be filtered
    
    Returns:
        bool: True if the IP address is valid, False otherwise.
    """

    if not isinstance(ip_address, str):
        return False

    if ip_address == "127.0.0.1":
        return False

    if not without_filter:
        is_ipv4_address = is_ipv4(ip_address)
        is_ipv6_address = is_ipv6(ip_address)

        if not is_ipv4_address and not is_ipv6_address:
            return False

        if (is_ipv4_address and is_unwanted_ipv4(ip_address)) or\
            (is_ipv6_address and is_unwanted_ipv6(ip_address)):

            return False

    if is_ipv4(ip_address):
        octets = ip_address.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True

    elif is_ipv6(ip_address):
        return True

    return False


def reverse_ip(ip_address: str) -> str:
    """
    Reverse the IP address for DNS lookup.

    Args:
        ip_address (str): The IP address to reverse.

    Returns:
        str: The reversed IP address.
    """

    symbol = ':' if ':' in ip_address else '.'
    return symbol.join(reversed(ip_address.split(symbol)))
