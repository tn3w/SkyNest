"""
src/ddos_mitigation.py

This module provides functionality for mitigating Distributed Denial of Service (DDoS) attacks 
by implementing a rate limiting mechanism based on IP addresses. 
"""

from time import time
from typing import Final

try:
    from src.utils import REDIS_CLIENT
    from src.crypto import sha256_hash_text
except (ModuleNotFoundError, ImportError):
    from utils import REDIS_CLIENT
    from crypto import sha256_hash_text


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
