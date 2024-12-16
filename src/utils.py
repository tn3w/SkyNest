"""
src/utils.py

A utility module providing file handling, security, and system utility functions
including random string generation, file read/write operations, environment variable
loading, and specialized file serialization classes.
"""

from threading import Lock
from base64 import b64encode
from io import TextIOWrapper
from shutil import copy2, move
from typing import Final, Optional, Any
from secrets import choice, randbelow, token_hex
from os import unlink, fsync, makedirs, path, environ
from json import load as json_load, dump as json_dump
from pickle import load as pickle_load, dump as pickle_dump

from redis import StrictRedis
from flask import Response

try:
    from src.logger import log
except ModuleNotFoundError:
    from logger import log


REDIS_CLIENT: Final[StrictRedis] = StrictRedis(host='127.0.0.1', port=6379, decode_responses=True)

CURRENT_DIRECTORY_PATH: Final[str] = path.dirname(path.abspath(__file__)) \
    .replace("\\", "/").replace("//", "/").replace("src", "").replace("//", "/")
SOURCE_DIRECTORY_PATH: Final[str] = path.join(CURRENT_DIRECTORY_PATH, "src")
TEMPLATES_DIRECTORY_PATH: Final[str] = path.join(SOURCE_DIRECTORY_PATH, "templates")
ASSETS_DIRECTORY_PATH: Final[str] = path.join(SOURCE_DIRECTORY_PATH, "assets")
DATA_DIRECTORY_PATH: Final[str] = path.join(SOURCE_DIRECTORY_PATH, "data")

CHARACTER_CATEGORIES: Final[list] = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    "!\'#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
]

FILE_LOCKS: dict[str, Lock] = {}


for directory_path in [ASSETS_DIRECTORY_PATH, DATA_DIRECTORY_PATH]:
    if path.exists(directory_path):
        continue

    makedirs(directory_path, exist_ok = True)


def generate_random_string(length: int, characters: str = "aA0!"):
    """
    Generate a random string of a specified length using a set of characters.

    Args:
        length (int): The length of the string to be generated.
        characters (str): A string specifying the character sets to include in the generated string. 

    Returns:
        str: A randomly generated string of the specified length
            composed of the selected characters.
    """

    full_characters = ""
    for characters_category in CHARACTER_CATEGORIES:
        for character in characters:
            if not character in characters_category:
                continue

            full_characters += characters_category
            break

    return "".join(choice(full_characters) for _ in range(length))


def secure_shuffle(original_list: list) -> list:
    """
    Shuffle a list in a secure manner using the Fisher-Yates algorithm.

    Args:
        original_list (list): The list to be shuffled.

    Returns:
        list: A new list containing the elements of the original list 
        in a shuffled order.
    """

    shuffled_list = original_list[:]
    list_length = len(shuffled_list)

    for current_index in range(list_length - 1, 0, -1):
        random_index = randbelow(current_index + 1)
        shuffled_list[current_index], shuffled_list[random_index] = \
            shuffled_list[random_index], shuffled_list[current_index]

    return shuffled_list


def get_lock(file_path: str) -> Lock:
    """
    Retrieve a lock for the specified file path.

    Args:
        file_path (str): The path to the file for which to get a lock.

    Returns:
        Lock: A threading lock object associated with the specified file path.
    """

    file_lock = FILE_LOCKS.get(file_path, None)
    if file_lock:
        return file_lock

    new_file_lock = Lock()
    FILE_LOCKS[file_path] = new_file_lock

    return new_file_lock


def read_text(file_path: str, default: Optional[str] = None) -> Optional[str]:
    """
    Read the contents of a text file and return it as a string.

    Args:
        file_path (str): The path to the text file to be read.
        default (Optional[str]): The value to return if the file cannot be read. 

    Returns:
        Optional[str]: The contents of the file as a string if successful, 
            or the `default` value if an error occurs.
    """

    try:
        with open(file_path, "r", encoding = "utf-8") as file_stream:
            return file_stream.read()

    except (FileNotFoundError, IsADirectoryError, OSError, IOError,
            PermissionError, ValueError, TypeError, UnicodeDecodeError):
        log(f"`{file_path}` could not be read.", level = 4)

    return default


def read_bytes(file_path: str, default: Optional[bytes] = None) -> Optional[bytes]:
    """
    Read the contents of a file and return it as bytes.

    Args:
        file_path (str): The path to the file to be read.
        default (Optional[bytes]): The value to return if the file cannot be read. 

    Returns:
        Optional[bytes]: The contents of the file as bytes if successful, 
            or the `default` value if an error occurs.
    """

    try:
        with open(file_path, "rb") as file_stream:
            return file_stream.read()

    except (FileNotFoundError, IsADirectoryError, OSError, IOError,
            PermissionError, ValueError, TypeError, UnicodeDecodeError):
        log(f"`{file_path}` could not be read.", level = 4)

    return default


def write_text(text: str, file_path: str) -> bool:
    """
    Write text to a file at the specified file path.

    Args:
        data (bytes): The bytes to be written to the file.
        file_path (str): The path to the file where the bytes will be written.

    Returns:
        bool: True if the bytes were successfully written, False otherwise.
    """

    try:
        with get_lock(file_path):
            with open(file_path, "w", encoding = "utf-8") as file_stream:
                file_stream.write(text)

                return True

    except (FileNotFoundError, IsADirectoryError, IOError,
            PermissionError, ValueError, TypeError, OSError):
        log(f"`{file_path}` could not be written.", level = 4)

    return False


def write_bytes(data: bytes, file_path: str) -> bool:
    """
    Write bytes to a file at the specified file path.

    Args:
        data (bytes): The bytes to be written to the file.
        file_path (str): The path to the file where the bytes will be written.

    Returns:
        bool: True if the bytes were successfully written, False otherwise.
    """

    try:
        with get_lock(file_path):
            with open(file_path, "wb") as file_stream:
                file_stream.write(data)

                return True

    except (FileNotFoundError, IsADirectoryError, IOError,
            PermissionError, ValueError, TypeError, OSError):
        log(f"`{file_path}` could not be written.", level = 4)

    return False


def load_dotenv(file_name: str = ".env") -> None:
    """
    Load environment variables from a .env file into the system environment.

    Args:
        file_name (str): Name of the env file. Defaults to ".env" in the current directory.
    """

    file_path = path.join(CURRENT_DIRECTORY_PATH, file_name)

    if not path.isfile(file_path):
        return

    dotenv_content = read_text(file_path)
    if not dotenv_content:
        return

    for line in dotenv_content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)

            environ[key.strip()] = value


def text_response(text: str) -> Response:
    """
    Create a plain text response.

    Args:
        text (str): The text content to be included in the response.

    Returns:
        Response: A Response object containing the provided text and
            a MIME type of "text/plain".
    """

    return Response(text, mimetype = "text/plain")


def convert_image_to_base64(image_data: bytes) -> str:
    """
    Converts an image into Base64 Web Format.

    Args:
        image_data (bytes): The data of an image file in png format.

    Returns:
        str: A data URL representing the image in Base64 Web Format.
    """

    encoded_image = b64encode(image_data)
    return (b'data:image/webp;base64,' + encoded_image).decode('utf-8')


def get_shadow_copy_temp_path(file_path: str) -> str:
    """
    Generate a temporary file path for a shadow copy of the specified file.

    Args:
        file_path (str): The path to the original file for which a shadow 
            copy path is to be generated.

    Returns:
        str: The path to the temporary shadow copy file.
    """

    directory, file = path.split(file_path)

    random_hex = token_hex(16)
    temp_file_name = random_hex + "_" + file

    return path.join(directory, temp_file_name)


class Error:
    """
    Represents an error with a message and associated fields.

    Attributes:
        message (str): The error message.
        fields (list): A list of fields associated with the error.
    """

    def __init__(self, message: str, fields: list) -> None:
        self.message = message
        self.fields = fields


class File:
    """
    A base class for file handling operations with support for loading and dumping data.
    
    Attributes:
        as_bytes (bool): Flag to determine whether to read/write files in binary mode. 
            Defaults to False (text mode).
    """


    def __init__(self):
        """
        Initialize the File object with text mode by default.
        """

        self.as_bytes = False


    def _load(self, file_stream: TextIOWrapper) -> str:
        """
        Internal method to read data from a file stream.

        Args:
            file_stream (TextIOWrapper): The file stream to read from.

        Returns:
            str: The contents of the file stream.
        """

        return file_stream.read()


    def _dump(self, data: str, file_stream: TextIOWrapper) -> None:
        """
        Internal method to write data to a file stream.

        Args:
            data (str): The data to write to the file.
            file_stream (TextIOWrapper): The file stream to write to.
        """

        file_stream.write(data)


    def load(self, file_path: str, default: Any = None) -> Any:
        """
        Loads the file.

        Args:
            file_path (str): The path to the file to load.
            default (Any, optional): The default value to return if the file
                does not exist. Defaults to None.

        Returns:
            Any: The loaded file.
        """

        if not path.isfile(file_path):
            return default

        read_file_path = get_shadow_copy_temp_path(file_path)

        mode = "rb" if self.as_bytes else "r"
        encoding = None if self.as_bytes else "utf-8"

        try:
            copy2(file_path, read_file_path)

            with open(file_path, mode, encoding = encoding) as file_stream:
                data = self._load(file_stream)
                if data is not None:
                    return data

        except Exception:
            log(f"`{file_path}` could not be loaded.", level = 4)

        finally:
            unlink(read_file_path)

        return default


    def dump(self, data: Any, file_path: str) -> bool:
        """
        Dumps the data to the file.

        Args:
            data (Any): The data to dump to the file.
            file_path (str): The path to the file to dump the data to.
        
        Returns:
            bool: True if the data was dumped successfully, False otherwise.
        """

        write_file_path = get_shadow_copy_temp_path(file_path)

        mode = "wb" if self.as_bytes else "w"
        encoding = None if self.as_bytes else "utf-8"

        try:
            with open(write_file_path, mode, encoding = encoding) as file_stream:
                self._dump(data, file_stream)

                file_stream.flush()
                fsync(file_stream.fileno())

                return True

        except Exception:
            log(f"`{file_path}` could not be dumped.", level = 4)

        finally:
            move(write_file_path, file_path)

        return False


class JSONFile(File):
    """
    A specialized File class for handling JSON file operations.
    """


    def _load(self, file_stream: TextIOWrapper) -> Any:
        """
        Load JSON data from a file stream.

        Args:
            file_stream (TextIOWrapper): The file stream containing JSON data.

        Returns:
            Any: The deserialized JSON data.
        """

        return json_load(file_stream)


    def _dump(self, data: Any, file_stream: TextIOWrapper) -> None:
        """
        Dump data to a file stream in JSON format.

        Args:
            data (Any): The data to serialize to JSON.
            file_stream (TextIOWrapper): The file stream to write JSON data to.
        """

        json_dump(data, file_stream)


class PickleFile(File):
    """
    A specialized File class for handling Pickle file operations.
    """


    def __init__(self):
        """
        Initialize the PickleFile object.
        
        Sets the as_bytes flag to True to ensure binary mode for Pickle operations.
        """

        super().__init__()
        self.as_bytes = True


    def _load(self, file_stream: TextIOWrapper) -> Any:
        """
        Load serialized Python object from a file stream using Pickle.

        Args:
            file_stream (TextIOWrapper): The file stream containing pickled data.

        Returns:
            Any: The deserialized Python object.
        """

        return pickle_load(file_stream)


    def _dump(self, data: Any, file_stream: TextIOWrapper) -> None:
        """
        Dump a Python object to a file stream using Pickle.

        Args:
            data (Any): The Python object to serialize.
            file_stream (TextIOWrapper): The file stream to write pickled data to.
        """

        pickle_dump(data, file_stream)


JSON: Final[JSONFile] = JSONFile()
PICKLE: Final[PickleFile] = PickleFile()