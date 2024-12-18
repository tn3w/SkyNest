"""
src/user.py

A module for managing user authentication, session handling, and security features
including username and password validation, two-factor authentication, and session creation.
"""

from os import path
from math import log2
from time import time
from typing import Final, Optional, Tuple
from re import Pattern, compile as reg_compile, match

try:
    from src.user_agent import get_os_and_browser
    from src.crypto import TOTP, SHA256, generate_base32_secret
    from src.utils import PICKLE, DATA_DIRECTORY_PATH, Error, generate_random_string
    from src.errors import ENTER_UN_ERROR, ENTER_PWD_ERROR, UN_OR_PWD_NOT_RIGHT_ERROR
except (ModuleNotFoundError, ImportError):
    from user_agent import get_os_and_browser
    from crypto import TOTP, SHA256, generate_base32_secret
    from utils import PICKLE, DATA_DIRECTORY_PATH, Error, generate_random_string
    from errors import ENTER_UN_ERROR, ENTER_PWD_ERROR, UN_OR_PWD_NOT_RIGHT_ERROR


USER_NAME_MIN_LENGTH: Final[int] = 4
USER_NAME_MAX_LENGTH: Final[int] = 16
USER_NAME_CHARSET: Final[Pattern] = reg_compile(r"^[A-Za-z0-9_]+$")

PASSWORD_MIN_LENGTH: Final[int] = 10
PASSWORD_MAX_LENGTH: Final[int] = 128
PASSWORD_CHARSET: Final[Pattern] = reg_compile(
    r"^[A-Za-z0-9!@#$%^&*()\-_=+[\]{};:'\"|\\,.<>/?`~]+$"
)
PASSWORD_MIN_QUALITY: Final[str] = 2
PASSWORD_QUALITIES: Final[dict] = {
    (0, 60): "Weak",
    (60, 100): "Fair",
    (100, 140): "Strong",
    (140, float('inf')): "Excellent",
}

PASSWORD_SHA: Final[SHA256] = SHA256(
    iterations = 100000, salt_length = 32
)
USER_NAME_SHA: Final[SHA256] = SHA256()
SESSION_ID_SHA: Final[SHA256] = SHA256()
SESSION_TOKEN_SHA: Final[SHA256] = SHA256(
    iterations = 50000, salt_length = 16
)

USERS_FILE_PATH: Final[str] = path.join(
    DATA_DIRECTORY_PATH, "users.pkl"
)


def is_user_name_length_valid(user_name: str) -> bool:
    """
    Checks if the length of a given username is valid.

    Args:
        user_name (str): The username to validate.

    Returns:
        bool: True if the username length is within the defined range, False otherwise.
    """

    return USER_NAME_MIN_LENGTH <= len(user_name) <= USER_NAME_MAX_LENGTH


def is_user_name_characters_valid(user_name: str) -> bool:
    """
    Checks if a username contains only valid characters.

    Args:
        user_name (str): The username to validate.

    Returns:
        bool: True if the username matches the allowed character set, False otherwise.
    """

    return match(USER_NAME_CHARSET, user_name)


def is_password_length_valid(password: str) -> bool:
    """
    Checks if the length of a given password is valid.

    Args:
        password (str): The password to validate.

    Returns:
        bool: True if the password length is within the defined range, False otherwise.
    """

    return PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH


def is_password_characters_valid(password: str) -> bool:
    """
    Checks if a password contains only valid characters.

    Args:
        password (str): The password to validate.

    Returns:
        bool: True if the password matches the allowed character set, False otherwise.
    """

    return match(PASSWORD_CHARSET, password)


def calculate_password_entropy(password: str) -> float:
    """
    Calculates the entropy of a password based on its character set and length.

    Args:
        password (str): The password to analyze.

    Returns:
        float: The calculated entropy value of the password.
    """

    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password):
        charset_size += 32

    entropy = len(password) * log2(charset_size)
    return entropy


def get_password_quality(entropy: float) -> int:
    """
    Determines the quality rating of a password based on its entropy.

    Args:
        entropy (float): The entropy value of the password.

    Returns:
        int: An integer representing the quality level (1-4) based on predefined thresholds.
    """

    for i, (lower, upper) in enumerate(PASSWORD_QUALITIES.keys()):
        if lower <= entropy < upper:
            return i + 1

    return 1


def is_password_quality_valid(quality: int) -> bool:
    """
    Checks if a password's quality meets the minimum required threshold.

    Args:
        quality (int): The quality level of the password.

    Returns:
        bool: True if the password quality meets or exceeds the minimum, False otherwise.
    """

    return quality >= PASSWORD_MIN_QUALITY


def get_signin_error(user_name: str, password: str) -> Tuple[Optional["User"], Optional[Error]]:
    """
    Validates user sign-in credentials and returns errors if validation fails.

    Args:
        user_name (str): The user's username.
        password (str): The user's password.

    Returns:
        Tuple[Optional["User"], Optional[Error]]:
            - The authenticated user object if credentials are valid, otherwise `None`.
            - An error object describing the validation failure, otherwise `None`.
    """

    if not user_name:
        return None, ENTER_UN_ERROR

    if not is_user_name_length_valid(user_name):
        return None, UN_OR_PWD_NOT_RIGHT_ERROR

    if not is_user_name_characters_valid(user_name):
        return None, UN_OR_PWD_NOT_RIGHT_ERROR

    user = get_user_based_on_user_name(user_name)
    if not user:
        return None, UN_OR_PWD_NOT_RIGHT_ERROR

    if not password:
        return None, ENTER_PWD_ERROR

    if not is_password_length_valid(password) or not is_password_characters_valid(password):
        return None, UN_OR_PWD_NOT_RIGHT_ERROR

    password_entropy = calculate_password_entropy(password)
    password_quality = get_password_quality(password_entropy)
    if not is_password_quality_valid(password_quality):
        return None, UN_OR_PWD_NOT_RIGHT_ERROR

    return user, None


class Users(dict):
    """
    A class to manage user data stored in a file.

    Attributes:
        file_path (str): The path to the file where user data is stored.
        users (Optional[dict]): A dictionary containing user data.
    """


    def __init__(self, file_path: Optional[str] = None) -> None:
        """
        Initializes the Users class with a specified file path.

        Args:
            file_path (Optional[str]): The path to the file containing user data. 
                Defaults to None.
        """

        if not file_path:
            file_path = USERS_FILE_PATH

        self.file_path = file_path
        self.users: Optional[dict] = None

        self.load()


    def load(self) -> dict:
        """
        Loads user data from the specified file.

        This method reads the user data from the file using the 
        PICKLE module and stores it in the users attribute.

        Returns:
            dict: A dictionary containing the loaded user data.
        """

        users = PICKLE.load(self.file_path, {})
        self.users = users

        return users


    def dump(self) -> None:
        """
        Saves the current user data to the specified file.
        """

        return PICKLE.dump(self.users, self.file_path)


    def __setitem__(self, key: str, value: dict) -> None:
        """
        Sets a user entry in the users dictionary and saves it to the file.

        Args:
            key (str): The key representing the user (e.g., username or ID).
            value (dict): A dictionary containing user information.
        """

        self.users[key] = value
        self.dump()


    def __getitem__(self, key: str) -> Optional[dict]:
        """
        Retrieves a user entry from the users dictionary.

        Args:
            key (str): The key representing the user to retrieve.

        Returns:
            Optional[dict]: A dictionary containing user information if found, 
                or None if the key does not exist.
        """

        return self.users.get(key, None)


USERS = Users()


class User:
    """
    Represents a user in the system.

    Attributes:
        user_name (str): The username of the user.
        stored_key (str): The hashed key associated with the user.
        hashed_password (str): The hashed password of the user.
        avatar (Optional[bytes]): The user's avatar image.
        display_name (Optional[str]): The user's display name.
        twofa_token (Optional[str]): The user's two-factor authentication token.
        sessions (dict): A dictionary of the user's sessions.
    """

    def __init__(self, user_name: str, stored_key: str, user_data: dict):
        self.user_name = user_name
        self.stored_key = stored_key
        self.hashed_password = user_data["password"]

        self.avatar = user_data.get("avatar", None)
        self.display_name = user_data.get("display_name", None)
        self.twofa_token = user_data.get("twofa_token", None)
        self.sessions = user_data.get("sessions", {})


    def is_valid_password(self, password: str) -> bool:
        """
        Verifies if a provided password matches the user's stored hashed password.

        Args:
            password (str): The password to verify.

        Returns:
            bool: True if the password is valid, otherwise False.
        """

        return PASSWORD_SHA.compare(password, self.hashed_password)


class Session:
    """
    Represents a user session.

    Attributes:
        user (User): The associated user.
        session_id (str): The session ID.
        session_token (Optional[bytes]): The session token in plain text.
        stored_key (str): The hashed key associated with the session.
        hashed_session_token (str): The hashed session token.
        os (str): The operating system of the user during the session.
        browser (str): The browser used during the session.
        ip (str): The IP address of the user during the session.
    """

    def __init__(self, user: User, session_id: str,
                 stored_key: str, session_data: dict,
                 session_token: Optional[bytes] = None) -> None:
        self.user = user
        self.session_id = session_id
        self.session_token = session_token
        self.stored_key = stored_key

        self.hashed_session_token = session_data["token"]
        self.os = session_data["os"]
        self.browser = session_data["browser"]
        self.ip = session_data["ip"]


    def is_valid_token(self, session_token: str) -> bool:
        """
        Verifies if a provided session token matches the stored hashed token.

        Args:
            session_token (str): The session token to verify.

        Returns:
            bool: True if the token is valid, otherwise False.
        """

        if self.session_token:
            return session_token == self.session_token

        return SESSION_TOKEN_SHA.compare(session_token, self.hashed_session_token)


def get_user_based_on_user_name(user_name: str) -> Optional["User"]:
    """
    Retrieves a user object by username.

    Args:
        user_name (str): The user's username.

    Returns:
        Optional[User]: The user object if found, otherwise `None`.
    """

    for hashed_user_name, user_data in USERS.users.items():
        if not USER_NAME_SHA.compare(user_name, hashed_user_name):
            continue

        return User(user_name, hashed_user_name, user_data)

    return None


def create_user(user_name: str, password: str,
                display_name: Optional[str] = None,
                avatar: Optional[bytes] = None,
                twofa_token: Optional[str] = None) -> Optional["User"]:
    """
    Creates a new user.

    Args:
        user_name (str): The username for the new user.
        password (str): The password for the new user.
        display_name (Optional[str]): The display name of the user.
        avatar (Optional[bytes]): The user's avatar image.
        twofa_token (Optional[str]): The user's two-factor authentication token.

    Returns:
        Optional[User]: The created user object, or `None` if the username already exists.
    """

    if get_user_based_on_user_name(user_name):
        return None

    password_hash = PASSWORD_SHA.hash(password)
    if not password_hash:
        return None

    user_data = {
        "password": password_hash,
    }

    additional_data = [
        ("display_name", display_name),
        ("avatar", avatar),
        ("twofa_token", twofa_token),
    ]

    for key, value in additional_data:
        if value is not None:
            user_data[key] = value

    hashed_user_name = USER_NAME_SHA.hash(user_name)
    if not hashed_user_name:
        return None

    USERS[hashed_user_name] = user_data

    user = User(
        user_name, hashed_user_name,
        user_data
    )

    return user


def create_session(user: User, user_agent: str, ip_address: str) -> Optional["Session"]:
    """
    Creates a new session for a user.

    Args:
        user (User): The user object for whom the session is created.
        user_agent (str): The user agent string of the session.
        ip_address (str): The IP address of the session.

    Returns:
        Session: The newly created session object.
    """

    operating_system, browser = get_os_and_browser(user_agent)

    session_token = generate_random_string(32, "aA0")
    hashed_session_token = SESSION_TOKEN_SHA.hash(session_token)
    if not hashed_session_token:
        return None

    session_data = {
        "token": hashed_session_token,
        "os": operating_system,
        "browser": browser,
        "ip": ip_address,
        "time": int(time())
    }

    user_data = USERS[user.stored_key]
    if not user_data:
        return None

    sessions = user_data.get("sessions", {})

    session_id = None
    while not session_id or any(
            SESSION_ID_SHA.compare(session_id, current_session_id)
            for current_session_id in sessions
        ):

        session_id = generate_random_string(6, "aA0")

    hashed_session_id = SESSION_ID_SHA.hash(session_id)
    if not hashed_session_id:
        return None

    sessions[hashed_session_id] = session_data
    user_data["sessions"] = sessions

    USERS[user.stored_key] = user_data

    return Session(
        user, session_id,
        hashed_session_id, session_data,
        session_token
    )


def verify_twofa(user_name: str, token: str) -> bool:
    """
    Verifies a two-factor authentication (2FA) token.

    Args:
        user_name (str): The username of the user.
        token (str): The 2FA token to verify.

    Returns:
        bool: True if the token is valid, otherwise False.
    """

    user = get_user_based_on_user_name(user_name)
    if not user:
        return False

    if token is None or len(token) != 6:
        return False

    if not token.isdigit():
        return False

    twofa_token = user.twofa_token
    return TOTP(twofa_token).verify_token(token)


def create_test_user() -> None:
    """
    Creates a test user if one does not already exist.

    Returns:
        None: This function does not return a value.
    """

    if user := get_user_based_on_user_name("test"):
        print("User test already exists.")
        print(user.twofa_token)
        return

    totp_secret = generate_base32_secret(16)
    print(totp_secret)

    created_successfully = create_user("test", "fancypassword", "Test", twofa_token = totp_secret)
    print(f"User test was{'' if created_successfully else ' not'} created successfully.")
