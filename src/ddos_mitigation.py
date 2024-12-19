"""
src/ddos_mitigation.py

This module provides functionality for mitigating Distributed Denial of Service (DDoS) attacks 
by implementing a rate limiting mechanism based on IP addresses. 
"""

from time import time
from random import choice, randint
from typing import Final, Optional
from datetime import datetime, timedelta
from socket import gethostbyname, gaierror

from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

try:
    from src.logger import log
    from src.crypto import sha256_hash_text
    from src.internet_protocol import reverse_ip, is_ipv4
    from src.utils import REDIS_CLIENT, cache_with_ttl, str_to_float, matches_rules
except (ModuleNotFoundError, ImportError):
    from logger import log
    from crypto import sha256_hash_text
    from internet_protocol import reverse_ip, is_ipv4
    from utils import REDIS_CLIENT, cache_with_ttl, str_to_float, matches_rules


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


MALICIOUS_ASNS: Final[str] = [
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


@cache_with_ttl(28800)
def is_ip_malicious_ipapi(ip_address: str) -> Optional[bool]:
    """
    Uses the IPApi.com API to check the reputation of the given IP address.

    Args:
        ip_address (str): The IP address to check.
        api_key (Optional[str]): The API key for authenticating with the IPApi.com API.
                                 If provided, it will be included in the request.

    Returns:
        Optional[bool]: True if the IP address is malicious, False if it is not, or None
                        if an error occurs.
    """

    url = f"http://ip-api.com/json/{ip_address}?fields=proxy,hosting"

    data = http_request(url, is_json = True, default = {})
    if not isinstance(data, dict):
        return None

    some_data_provided = False
    for key in ["proxy", "hosting"]:
        value = data.get(key, None)
        if value is True:
            return True

        if value is not None:
            some_data_provided = True

    if not some_data_provided:
        return None

    return False


@cache_with_ttl(28800)
def is_ip_malicious_ipintel(ip_address: str, _: Optional[str] = None) -> Optional[bool]:
    """
    Uses the getipintel.net API to check the reputation of the given IP address.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        Optional[bool]: True if the IP address is malicious, False otherwise.
    """

    random_email = ''.join(
        choice(
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        ) for _ in range(randint(4, 9))
    ) + choice(["@outlook.com", "gmail.com", "icloud.com", "aol.com"])

    url = f"https://check.getipintel.net/check.php?ip={ip_address}&contact={random_email}"

    data = http_request(url, default = "")
    score = str_to_float(data)
    if not score:
        return None

    if score > 0.90:
        return True

    return False


@cache_with_ttl(28800)
def is_ip_malicious_stopforumspam(ip_address: str) -> bool:
    """
    Uses the stopforumspam.org API to check the reputation of the given IP address.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        Optional[bool]: True if the IP address is malicious, False otherwise.
    """

    url = f'https://api.stopforumspam.org/api?ip={ip_address}&json'

    response_json = http_request(url, is_json = True, default = {})
    if not isinstance(response_json, dict):
        return False

    if not response_json.get('success') == 1:
        return False

    ip_info = response_json.get("ip", {})
    appears = ip_info.get("appears", 0)
    frequency = ip_info.get("frequency", 0)

    return appears >= 1 and frequency >= 2


@cache_with_ttl(28800)
def is_ip_malicious_geoip(ip_address: str, rules: Optional[tuple]) -> bool:
    """
    Checks the reputation of the given IP address using GeoIP databases.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        bool: True if the IP address is found to be malicious.
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


def is_ip_malicious(ip_address: str, third_parties: Optional[list] = None) -> bool:
    """
    Checks whether the given IP address is malicious.

    Args:
        ip_address (str): The IP address to check.
        third_parties (Optional[list]): A list of third-party services to use for the check.

    Returns:
        bool: True if the IP address is malicious, False otherwise.
    """

    if not isinstance(ip_address, str):
        return False

    if third_parties is None:
        third_parties = ["ipapi", "ipintel", "stopforumspam", "geoip"]

    for third_party, third_party_function in {
            "ipapi": is_ip_malicious_ipapi,
            "ipintel": is_ip_malicious_ipintel,
            "stopforumspam": is_ip_malicious_stopforumspam,
        }.items():

        is_allowed = False
        for allowed_third_party in third_parties:
            if allowed_third_party.lower().startswith(third_party):
                is_allowed = True

        if not is_allowed:
            continue

        api_key = None
        if ":" in third_party:
            found_api_key = third_party.split(":")[1].strip()
            if len(found_api_key) > 1:
                api_key = found_api_key

        is_malicious = third_party_function(ip_address, api_key)
        if is_malicious is True:
            return True

    if "geoip" in third_parties:
        if is_ip_malicious_geoip(ip_address):
            return True

    return False


@cache_with_ttl(28800)
def is_ipv4_tor(ipv4_address: Optional[str] = None) -> bool:
    """
    Checks whether the given IPv4 address is Tor.

    Args:
        ipv4_address (str): The IPv4 address to check.

    Returns:
        bool: True if the IPv4 address is Tor, False otherwise.
    """

    query = reverse_ip(ipv4_address)

    try:
        resolved_ip = gethostbyname(query)

        if resolved_ip == '127.0.0.2':
            return True

    except gaierror:
        log(f"{ipv4_address} connection could not be established", level = 4)

    return False


@cache_with_ttl(28800)
def is_ip_tor_exonerator(ip_address: Optional[str] = None) -> bool:
    """
    Checks whether the given IP address is Tor using the Exonerator service.

    Args:
        ip_address (str): The IPv6 address to check.

    Returns:
        bool: True if the IPv6 address is Tor, False otherwise.
    """

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
                    return True

    except (HTTPError, URLError, TimeoutError):
        log(f"{ip_address} connection could not be looked up on Exonerator", level = 4)

    return False


def is_ip_tor(ip_address: str, third_parties: Optional[list] = None) -> bool:
    """
    Checks whether the given IP address is Tor.

    Args:
        ip_address (str): The IP address to check.
        third_parties (Optional[list]): A list of third-party services to use for the check.
    Returns:
        bool: True if the IP address is Tor, False otherwise.
    """

    if not isinstance(ip_address, str):
        return False

    if third_parties is None:
        third_parties = ["tor_hostname", "tor_exonerator"]

    if "tor_hostname" in third_parties and is_ipv4(ip_address):
        if is_ipv4_tor(ip_address):
            return True

    if "tor_exonerator" in third_parties:
        if is_ip_tor_exonerator(ip_address):
            return True

    return False
