"""
src/request.py

This module provides utility functions for handling HTTP requests in a web application.
"""

from urllib.parse import urlparse

from flask import Request


def is_post(request: Request) -> bool:
    """
    Check if the request method is POST.

    Args:
        request (Request): The request object to be checked.

    Returns:
        bool: True if the request method is "POST", False otherwise.
    """

    return request.method.lower() == "post"


def is_get(request: Request) -> bool:
    """
    Check if the request method is GET.

    Args:
        request (Request): The request object to be checked.

    Returns:
        bool: True if the request method is "GET", False otherwise.
    """

    return request.method.lower() == "get"


def get_scheme(request: Request) -> str:
    """
    Determines the scheme (http or https) of the incoming request.

    Args:
        request (Request): The request object containing headers and 
            security information.

    Returns:
        str: The scheme of the request, either 'http' or 'https'.
    """

    scheme = request.headers.get('X-Forwarded-Proto', '')
    if scheme not in ['https', 'http']:
        if request.is_secure:
            scheme = 'https'
        else:
            scheme = 'http'

    return scheme


def get_user_agent(request: Request) -> str:
    """
    Retrieves the user agent string from the request.

    Args:
        request (Request): The request object containing user agent information.

    Returns:
        str: The user agent string of the client making the request.
    """

    return request.user_agent.string


def get_ip_address(request: Request) -> str:
    """
    Retrieves the IP address of the client making the request.

    Args:
        request (Request): The request object containing remote address information.

    Returns:
        str: The IP address of the client, or '127.0.0.1' if the address is not available.
    """

    return request.remote_addr or "127.0.0.1"


def get_domain_host(request: Request):
    """
    Extract the domain host from a Flask request object.
    
    Args:
        request (Request): The current Flask request object
    
    Returns:
        str: The domain host, with long subdomains truncated
    """

    host = request.headers.get('Host', '')

    if ':' in host:
        host = host.split(':')[0]

    if not host or host == 'localhost':
        try:
            parsed_url = urlparse(request.url)
            host = parsed_url.netloc.split(':')[0]
        except Exception:
            host = 'localhost'

    if not host:
        host = 'localhost'

    parts = host.split('.')

    if len(host) > 20 or any(len(part) > 10 for part in parts):
        host = '.'.join(parts[-2:])

    return host
