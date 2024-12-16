"""
src/user_agent.py

This module provides functionality for parsing user-agent strings to identify the 
operating system and browser being used by a client.
"""

from re import search
from typing import Final, Tuple, Optional


OS_PATTERNS: Final[list[tuple]] = [
    (r"Windows Phone", "Windows Phone"),
    (r"Windows", "Windows"),
    (r"iPhone", "iOS"),
    (r"Mac OS", "MacOS"),
    (r"Android", "Android"),
    (r"Linux", "Linux"),
    (r"CrOS", "Chrome OS"),
    (r"Ubuntu", "Linux"),
    (r"Fedora", "Linux"),
    (r"CentOS", "Linux"),
    (r"OpenBSD", "OpenBSD"),
    (r"FreeBSD", "FreeBSD"),
    (r"BlackBerry", "BlackBerry"),
    (r"BB10", "BlackBerry"),
    (r"bot", "Bot")
]


BROWSER_PATTERNS: Final[list[tuple]] = [
    (r"Chrome", "Chrome"),
    (r"Chromium", "Chrome"),
    (r"Firefox", "Firefox"),
    (r"FxiOS", "Firefox"),
    (r"Safari", "Safari"),
    (r"MSIE", "Internet Explorer"),
    (r"Edg", "Edge"),
    (r"OPR", "Opera"),
    (r"Opera", "Opera"),
    (r"Vivaldi", "Vivaldi"),
    (r"Android WebView", "WebView"),
    (r"Facebook", "AppView"),
    (r"Instagram", "AppView"),
    (r"Twitter", "AppView"),
    (r"QQBrowser", "QQ"),
    (r"UC", "UC"),
    (r"Puffin", "Puffin")
]


def get_os_and_browser(user_agent: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parses a user-agent string to identify the operating system and browser.

    Args:
        user_agent (str): The user-agent string to be analyzed.

    Returns:
        Tuple[Optional[str], Optional[str]]: A tuple containing operating system and browser.
    """

    operating_system = None
    for pattern, name in OS_PATTERNS:
        if search(pattern, user_agent):
            operating_system = name
            break

    browser = None
    for pattern, name in BROWSER_PATTERNS:
        if search(pattern, user_agent):
            browser = name
            break

    return operating_system, browser


def is_mobile(operating_system: str) -> bool:
    """
    Determines whether the given operating system corresponds to a mobile device.

    Args:
        operating_system (str): The name of the operating system.

    Returns:
        bool: `True` if the operating system is associated with mobile devices, otherwise `False`.
    """

    if not operating_system:
        return False

    return operating_system in [
        "Android", "iOS",
        "Windows Phone", "BlackBerry"
    ]
