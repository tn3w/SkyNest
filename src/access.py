"""
src/access.py

This module provides functionality for managing access tokens in a Flask application.
"""

from typing import Final, Optional

from flask import Request, g

try:
    from src.crypto import SHA256
    from src.request import is_post
    from src.render import render_template
    from src.errors import HASHING_FAILED_ERROR, NOT_RIGHT_ERROR
except (ModuleNotFoundError, ImportError):
    from crypto import SHA256
    from request import is_post
    from render import render_template
    from errors import HASHING_FAILED_ERROR, NOT_RIGHT_ERROR


ACCESS_TOKEN_SHA: Final[SHA256] = SHA256(use_encoding = True)


def verify_access_token_cookie(request: Request, access_token: str) -> bool:
    """
    Verifies if the given access token matches the one stored in the request cookies.

    Args:
        request (Request): The HTTP request object containing cookies.
        access_token (str): The access token to verify.

    Returns:
        bool: True if the token matches; False otherwise.
    """

    stored_access_token = request.cookies.get("access_token")
    if not isinstance(stored_access_token, str):
        return False

    return ACCESS_TOKEN_SHA.compare(access_token, stored_access_token)


def create_access_token_hash(access_token: str) -> Optional[str]:
    """
    Hashes the provided access token for secure storage.

    Args:
        access_token (str): The access token to hash.

    Returns:
        Optional[str]: The hashed access token, or None if hashing fails.
    """

    hashed_access_token = ACCESS_TOKEN_SHA.hash(access_token)
    if isinstance(hashed_access_token, str):
        return hashed_access_token

    return None


def get_send_access_token(request: Request) -> Optional[str]:
    """
    Extracts the access token from a POST request's form data.

    Args:
        request (Request): The HTTP request object containing form data.

    Returns:
        Optional[str]: The access token if found; None otherwise.
    """

    access_token_arg = request.args.get("access_token", None)
    if access_token_arg:
        return access_token_arg

    if not is_post(request):
        return None

    access_token = request.form.get("access_token", None)
    return access_token


def verify_access(request: Request, access_token: str) -> Optional[str]:
    """
    Verifies access by comparing the provided access token against stored or sent tokens.

    Args:
        request (Request): The HTTP request object containing cookies or form data.
        access_token (str): The access token to verify.

    Returns:
        Optional[str]: A rendered template with an error message if verification fails; 
            None if access is granted.
    """

    if verify_access_token_cookie(request, access_token):
        g.access_verified = True
        return None

    error = None

    send_access_token = get_send_access_token(request)
    if send_access_token:
        if send_access_token == access_token:
            hashed_access_token = create_access_token_hash(access_token)
            if not hashed_access_token:
                error = HASHING_FAILED_ERROR
            else:
                g.access_verified = True

                cookies = getattr(g, "cookies", {})
                cookies["access_token"] = hashed_access_token
                g.cookies = cookies
                return None

        else:
            error = NOT_RIGHT_ERROR

    return render_template("grant_access", error = error)
