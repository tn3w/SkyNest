"""
src/ddos_mitigation.py

This module provides functionality for mitigating Distributed Denial of Service (DDoS) attacks 
by implementing a rate limiting mechanism based on IP addresses. 
"""

from time import time
from typing import Final, Optional, Any
from datetime import datetime, timedelta
from socket import gethostbyname, gaierror
from socket import timeout as socket_timeout
from json import JSONDecodeError, loads as json_loads
from http.client import RemoteDisconnected, IncompleteRead, HTTPException

from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

try:
    from src.logger import log
    from src.crypto import sha256_hash_text
    from src.utils import REDIS_CLIENT, matches_rules
    from src.internet_protocol import is_valid_ip, reverse_ip, is_ipv4
except (ModuleNotFoundError, ImportError):
    from logger import log
    from crypto import sha256_hash_text
    from utils import REDIS_CLIENT, matches_rules
    from internet_protocol import is_valid_ip, reverse_ip, is_ipv4


DEFAULT_IP_HASH: Final[str] = "eCpiLALcButgO5xE90Xbt3Oa8Hd5WvScPomOSoP8bts"


def rate_limit(ip_address: str) -> bool:
    """
    Rate limit an IP address: max 15 requests/second with a max of 17 timestamps stored.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        bool: True if the IP is rate-limited, False otherwise.
    """

    hashed_ip = sha256_hash_text(ip_address)
    if not isinstance(hashed_ip, str):
        hashed_ip = DEFAULT_IP_HASH

    namespace_key = f"rate_limit:{hashed_ip}"
    current_time = int(time())

    with REDIS_CLIENT.pipeline() as pipe:
        pipe.rpush(namespace_key, current_time)
        pipe.ltrim(namespace_key, -17, -1)
        pipe.lrange(namespace_key, 0, -1)
        pipe.expire(namespace_key, 10)

        result = pipe.execute()
        timestamps = result[2]

    recent_requests = sum(1 for t in timestamps if current_time - int(t) <= 10)

    return recent_requests > 15


def http_request(url: str, method: str = "GET", timeout: int = 2,
                 is_json: bool = False, default: Optional[Any] = None) -> Optional[Any]:
    """
    Sends an HTTP request to the specified URL and returns the response content.

    Args:
        url (str): The URL to which the request is sent.
        method (str, optional): The HTTP method to use for the request. 
                                Defaults to "GET".
        timeout (int, optional): The maximum time (in seconds) to wait 
                                 for a response. Defaults to 2 seconds.
        is_json (bool, optional): If True, the response content is parsed 
                                  as JSON and returned as a Python object. 
                                  If False, the raw response content is 
                                  returned as bytes. Defaults to False.
        default (Optional[Any], optional): The value to return if an 
                                            exception occurs during the 
                                            request. Defaults to None.

    Returns:
        Optional[Any]: The response content, either as a parsed JSON 
                        object or as bytes. Returns None if an exception 
                        occurs during the request.
    """

    try:
        req = Request(
            url, headers = {"User-Agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.3"
            }, method = method
        )

        with urlopen(req, timeout = timeout) as response:
            if response.getcode() != 200:
                return default

            content = response.read().decode("utf-8")

        if is_json:
            return json_loads(content)

        return content
    except (HTTPError, URLError, socket_timeout, TimeoutError, JSONDecodeError,
            RemoteDisconnected, IncompleteRead, HTTPException, UnicodeEncodeError,
            ConnectionResetError, ConnectionAbortedError, ConnectionRefusedError, ConnectionError):
        log(f"{url} could not be requested", level = 4)

    return default


MALICIOUS_ASNS: Final[list[str]] = [
    "Fastly", "Incapsula", "Akamai", "AkamaiGslb", "Google", "Datacamp Limited",
    "Bing", "Censys", "Hetzner", "Linode", "Amazon", "AWS", "DigitalOcean", "Vultr",
    "Azure", "Alibaba", "Netlify", "IBM", "Oracle", "Scaleway", "Cloud", "VPN"
]


def is_asn_malicious(asn: str) -> bool:
    """
    Determines if a given Autonomous System Number (ASN) is considered malicious.

    Args:
        asn (str): The Autonomous System Number to check.

    Returns:
        bool: True if the ASN is not malicious, False if it is malicious.
    """

    normalized_asn = asn.lower().strip()

    for malicious_asn in MALICIOUS_ASNS:
        if malicious_asn.lower() in normalized_asn:
            return True

    return False


def is_ip_malicious_geoip(ip_address: str, rules: Optional[tuple]) -> Optional[bool]:
    """
    Checks the reputation of the given IP address using GeoIP databases.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        Optional[bool]: True if the IP address is found to be malicious.
    """

    geoip = get_geoip()

    some_database_available = False
    for db_name in ["city", "asn"]:
        database: Optional[GeoIP] = geoip.get(db_name, None)
        if database is None:
            log(f"{db_name} is not available.", level = 3)
            continue

        some_database_available = True

        ip_address_info = database.get(ip_address)
        if db_name == "asn":
            if is_asn_malicious(ip_address_info.get("asorg", "")):
                return True

        if not rules:
            continue

        if matches_rules(rules, ip_address_info):
            return True

    if not some_database_available:
        return None

    return False


def add_to_cache(key: str, ip_address: str, value: Optional[bool], short: bool = False) -> None:
    """
    Caches the result of an IP address check in Redis using a hashed IP.
    
    Args:
        key (str): The cache key prefix to use.
        ip_address (str): The IP address to cache results for.
        value (Optional[bool]): The boolean result to cache.
        short (bool, optional): If True, sets a 30 second TTL.
            If False, sets an 8 hour TTL. Defaults to False.
    
    Returns:
        None
    """

    if value is None:
        return

    hashed_ip_address = sha256_hash_text(ip_address)
    if not hashed_ip_address:
        return

    REDIS_CLIENT.setex(
        name=key + ":" + hashed_ip_address,
        time=30 if short else 28800,
        value="1" if value else "0"
    )


def get_cache(key: str, ip_address: str) -> Optional[bool]:
    """
    Retrieves a cached IP address check result from Redis.
    
    Args:
        key (str): The cache key prefix to look up.
        ip_address (str): The IP address to get cached results for.
        
    Returns:
        Optional[bool]: The cached result if found (True/False),
            or None if no cache entry exists.
    """

    hashed_ip_address = sha256_hash_text(ip_address)
    if not hashed_ip_address:
        return None

    result = REDIS_CLIENT.get(key + ":" + hashed_ip_address)
    if result:
        return result == "1"

    return None


def is_ip_malicious_ipapi(ip_address: str) -> Optional[bool]:
    """
    Uses the IPApi.com API to check the reputation of the given IP address.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        Optional[bool]: True if the IP address is malicious, False if it is not, or None
            if an error occurs.
    """

    cached_result = get_cache("ipapi", ip_address)
    if isinstance(cached_result, bool):
        return cached_result

    url = f"http://ip-api.com/json/{ip_address}?fields=proxy,hosting"

    data = http_request(url, is_json = True, default = {})
    if not isinstance(data, dict):
        return None

    for key in ["proxy", "hosting"]:
        value = data.get(key, None)
        if value is True:
            add_to_cache("ipapi", ip_address, True)
            return True

    if "proxy" not in data and "hosting" not in data:
        return None

    add_to_cache("ipapi", ip_address, False)
    return False


def is_ip_tor_exonerator(ip_address: str) -> Optional[bool]:
    """
    Checks if an IP address is a Tor exit node using the Tor Project's ExoneraTor service.
    
    Args:
        ip_address (str): The IP address to check.
        
    Returns:
        Optional[bool]: True if IP is a Tor exit node, False if not.
    """

    cached_result = get_cache("tor_exonerator", ip_address)
    if isinstance(cached_result, bool):
        return cached_result

    today = (datetime.now() - timedelta(days = 2)).strftime('%Y-%m-%d')

    base_url = "https://metrics.torproject.org/exonerator.html"
    query_params = {
        "ip": ip_address,
        "timestamp": today,
        "lang": "en"
    }
    url = f"{base_url}?{urlencode(query_params)}"

    req = Request(
        url, headers = {'Range': 'bytes=0-', "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.3"
        }
    )
    try:
        with urlopen(req, timeout = 3) as response:
            html = ''
            while True:
                chunk = response.read(128).decode('utf-8')
                if not chunk:
                    break

                html += chunk
                if "Result is positive" in html:
                    add_to_cache("tor_exonerator", ip_address, True)
                    return True

    except (HTTPError, URLError, TimeoutError):
        log("Tor exonerator failed.")

        add_to_cache("tor_exonerator", ip_address, True, True)
        return True

    add_to_cache("tor_exonerator", ip_address, False)
    return False


def is_ipv4_tor(ip_address: str) -> Optional[bool]:
    """
    Checks if an IPv4 address is a Tor exit node using DNS-based detection.
    
    Args:
        ip_address (str): The IPv4 address to check.
        
    Returns:
        Optional[bool]: True if IP is a Tor exit node,
            False if not, None if IP is invalid.
    """

    cached_result = get_cache("tor_hostname", ip_address)
    if isinstance(cached_result, bool):
        return cached_result

    if not ip_address:
        return None

    query = reverse_ip(ip_address)

    try:
        resolved_ip = gethostbyname(query)

        if resolved_ip == '127.0.0.2':
            add_to_cache("tor_hostname", ip_address, True)
            return True

    except gaierror:
        log("Tor hostname failed.")

        add_to_cache("tor_hostname", ip_address, True, True)
        return True

    add_to_cache("tor_hostname", ip_address, False)
    return False


def is_ip_malicious(ip_address: str) -> Optional[str]:
    """
    Performs comprehensive malicious IP detection using multiple methods.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        Optional[str]: String indicating detection source if malicious, None if not malicious.
    """

    if not is_valid_ip(ip_address):
        return "Invalid"

    is_malicious = is_ip_malicious_ipapi(ip_address)
    is_tor_exonerator = is_ip_tor_exonerator(ip_address)

    is_tor_v4 = False
    if is_ipv4(ip_address):
        is_tor_v4 = is_ipv4_tor(ip_address)

    for (third_party_name, third_party_result) in [
        ("Malicious", is_malicious),
        ("TOR", is_tor_exonerator),
        ("TORv4", is_tor_v4)
    ]:
        if third_party_result is True:
            return third_party_name

    return None
