"""
src/internet_protocol.py

This module provides utility functions for validating, converting, and managing IP addresses, 
both IPv4 and IPv6.
"""

from typing import Final
from re import VERBOSE, IGNORECASE, Pattern, compile as pattern_compile


IPV4_PATTERN: Final[str] = r'^(\d{1,3}\.){3}\d{1,3}$'
COMPILED_IPV4_REGEX: Final[Pattern] = pattern_compile(IPV4_PATTERN, VERBOSE | IGNORECASE)


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
