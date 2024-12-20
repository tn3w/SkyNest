"""
src/state.py

This module provides functionality for managing state strings in a web application, 
including creating, validating, and retrieving state data.
"""

from typing import Final, Tuple, Optional
from re import Pattern, compile as pattern_compile, match
from json import loads as json_loads, dumps as json_dumps

try:
    from src.logger import log
    from src.crypto import SHA256, Base62
    from src.utils import REDIS_CLIENT, generate_random_string
except (ModuleNotFoundError, ImportError):
    from logger import log
    from crypto import SHA256, Base62
    from utils import REDIS_CLIENT, generate_random_string


STATE_LENGTH: Final[int] = 32
STATE_BASE62_PATTERN: Final[Pattern] = pattern_compile(r"^[0-9A-Za-z]+$")

SHA256_BEAM: Final[SHA256] = SHA256(
    10000, hash_length = 15, salt_length = 0
)

DEFAULT_TIME_TO_LIVE: Final[int] = 600 # 10 minutes in seconds
TIME_TO_LIVE: Final[dict[str, int]] = {
    "pow": 180, # 3 minutes
    "browser_checked": 3600, # 1 hour
    "session": 31536000  # 1 year
}


def get_time_to_live(state_name: str) -> int:
    """
    Retrieve the time to live (TTL) for a given state name.

    Args:
        state_name (str): The name of the state for which to retrieve the TTL.

    Returns:
        int: The time to live associated with the specified state name.
            If the state name is not found, returns the default time to live.
    """
    return TIME_TO_LIVE.get(state_name, DEFAULT_TIME_TO_LIVE)


def is_valid_state(state: str) -> bool:
    """
    Validates a given state string based on its length and pattern.

    Args:
        state (str): The state string to validate.

    Returns:
        bool: True if the state string is valid; otherwise, False.
    """

    if len(state) != STATE_LENGTH:
        return False

    return bool(match(STATE_BASE62_PATTERN, state))


def create_state(state_name: str, data: dict) -> str:
    """
    Creates an encrypted state string with improved atomicity.
    """

    data["state"] = state_name
    serialized_data = json_dumps(data)

    pipeline = REDIS_CLIENT.pipeline()

    while True:
        state_key = generate_random_string(STATE_LENGTH, "aA0")

        pipeline.watch(f"state:{state_key}")

        if not REDIS_CLIENT.exists(f"state:{state_key}"):
            ttl = get_time_to_live(state_name)

            pipeline.multi()
            pipeline.setex(f"state:{state_key}", ttl, serialized_data)

            try:
                pipeline.execute()
                return state_key
            except Exception as e:
                log(f"State creation transaction failed: {e}", level=4)

        pipeline.reset()


def get_state(state: str, single_use: bool = False) -> Tuple[Optional[str], dict]:
    """
    Retrieves data from a state string.

    Args:
        state (str): The state string.
        single_use (bool): Whether to treat the state as single-use.

    Returns:
        Tuple[Optional[str], dict]: A tuple containing the state name and decoded data.
    """

    if not is_valid_state(state):
        return None, {}

    try:
        redis_data = REDIS_CLIENT.get(f"state:{state}")

        if not redis_data:
            return None, {}

        decoded_data = json_loads(redis_data)
    except Exception:
        log("Error while getting and loading state data in get_state.", level = 4)
        return None, {}

    state_name = decoded_data.get("state", None)

    if single_use:
        REDIS_CLIENT.delete(f"state:{state}")

    for key in ["state", "single_use", "time"]:
        if key in decoded_data:
            decoded_data.pop(key)

    return state_name, decoded_data


def get_beam_id(identifiable_information: list) -> Optional[str]:
    """
    Generate a Beam ID from a list of identifiable information.

    Args:
        identifiable_information (list): A list of strings containing identifiable
            information that will be concatenated and hashed.

    Returns:
        Optional[str]: A Beam ID that is 20 characters long, padded with "=" if necessary.
    """

    identifiable_information_str = ""
    for information in identifiable_information:
        if isinstance(information, str):
            identifiable_information_str += information

    beam_id_hash = SHA256_BEAM.hash(identifiable_information_str)
    if not isinstance(beam_id_hash, bytes):
        return None

    beam_id = Base62.encode(beam_id_hash)
    if not beam_id:
        return None

    beam_id = beam_id[:20]
    while len(beam_id) < 20:
        beam_id += "="

    return beam_id
