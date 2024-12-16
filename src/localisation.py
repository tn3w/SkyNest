"""
src/localisation.py

This module provides functionality for managing translations in a web application.
"""

from os import path, environ
from typing import Final, Optional

from flask import Request

try:
    from src.utils import JSON, ASSETS_DIRECTORY_PATH, load_dotenv
except (ModuleNotFoundError, ImportError):
    from utils import JSON, ASSETS_DIRECTORY_PATH, load_dotenv


TRANSLATIONS_FILE_PATH: Final[str] = path.join(ASSETS_DIRECTORY_PATH, "translations.json")
TRANSLATIONS: Final[dict[str, dict]] = JSON.load(TRANSLATIONS_FILE_PATH)

LANGUAGES: Final[list[str]] = [
    "af", "sq", "am", "ar", "hy", "az", "eu", "be", "bn", "bs", "bg", "ca", "ceb", "ny",
    "zh-cn", "zh-tw", "co", "hr", "cs", "da", "nl", "en", "eo", "et", "tl", "fi", "fr",
    "fy", "gl", "ka", "de", "el", "gu", "ht", "ha", "haw", "iw", "he", "hi", "hmn", "hu",
    "is", "ig", "id", "ga", "it", "ja", "jw", "kn", "kk", "km", "ko", "ku", "ky", "lo",
    "la", "lv", "lt", "lb", "mk", "mg", "ms", "ml", "mt", "mi", "mr", "mn", "my", "ne",
    "no", "or", "ps", "fa", "pl", "pt", "pa", "ro", "ru", "sm", "gd", "sr", "st", "sn",
    "sd", "si", "sk", "sl", "so", "es", "su", "sw", "sv", "tg", "ta", "te", "th", "tr",
    "uk", "ur", "ug", "uz", "vi", "cy", "xh", "yi", "yo", "zu"
]

load_dotenv()
CREATOR: Final[Optional[str]] = environ.get("CREATOR", None)

REQUIRED_LANGUAGE: Optional[str] = environ.get("REQUIRED_LANGUAGE", None)
if REQUIRED_LANGUAGE not in LANGUAGES:
    REQUIRED_LANGUAGE = None

DEFAULT_LANGUAGE: Optional[str] = environ.get("DEFAULT_LANGUAGE", "en")
if DEFAULT_LANGUAGE not in LANGUAGES:
    REQUIRED_LANGUAGE = "en"


def get_language(request: Request, default: str = "en") -> str:
    """
    Determines the best matching language for the request.
    Args:
        request (Request): The request object containing language preference information.
        default (str, optional): The default language to return if no match is found. 
            Defaults to "en".

    Returns:
        str: The best matching language from the request or
            the default language if no match is found.
    """

    language = request.accept_languages.best_match(LANGUAGES)
    if language in LANGUAGES:
        return language

    return default


def get_translations(language: str) -> dict:
    """
    Extract translations for a specific language.
    
    Args:
        language (str): The target language code (e.g., 'en', 'bs')
    
    Returns:
        dict: Translations for the specified language with English key and translated value
    """

    language_translations = {}

    for english_key, translations in TRANSLATIONS.items():
        if language in translations:
            language_translations[english_key] = translations[language]

        else:
            language_translations[english_key] = english_key

    return language_translations
