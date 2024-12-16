"""
scripts/json_to_pickle/main.py

This module provides functionality to load data from a JSON file and 
save it to a Pickle file format.

Usage:
    Run this script directly to convert the specified JSON file into 
    a Pickle file.
"""

from os import path
from typing import Final, Union
from json import load as json_load
from pickle import dump as pickle_dump


CURRENT_DIRECTORY_PATH: Final[str] = path.dirname(path.abspath(__file__))

JSON_FILE_NAME: Final[str] = "translations"
JSON_FILE_PATH: Final[str] = path.join(CURRENT_DIRECTORY_PATH, JSON_FILE_NAME + ".json")

PICKLE_FILE_NAME: Final[str] = "translations"
PICKLE_FILE_PATH: Final[str] = path.join(CURRENT_DIRECTORY_PATH, PICKLE_FILE_NAME + ".pkl")


def load_json_file(file_path: str) -> Union[dict, list]:
    """
    Load a JSON file and return its contents.

    Args:
        file_path (str): The path to the JSON file to be loaded.

    Returns:
        Union[dict, list]: The contents of the JSON file as a Python 
            dictionary or list.
    """

    with open(file_path, "r", encoding = "utf-8") as file_stream:
        return json_load(file_stream)


def write_pickle_file(data: Union[dict, list], file_path: str) -> None:
    """
    Write data to a file in pickle format.

    Args:
        data (Union[dict, list]): The data to be serialized and written 
            to the file.
        file_path (str): The path to the file where the data will be 
            saved.

    Raises:
        IOError: If there is an issue writing to the specified file.
    """

    with open(file_path, "wb") as file_stream:
        return pickle_dump(data, file_stream)


def main() -> None:
    """
    Main function to load JSON data and save it as a pickle file.
    """

    content = load_json_file(JSON_FILE_PATH)
    write_pickle_file(content, PICKLE_FILE_PATH)


if __name__ == "__main__":
    main()
