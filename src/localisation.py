"""
src/localisation.py

This module provides functionality for managing translations in a web application.
"""

from os import path, environ
from typing import Final, Optional

from flask import Request

try:
    from src.utils import JSON, ASSETS_DIRECTORY_PATH, Error, load_dotenv
except (ModuleNotFoundError, ImportError):
    from utils import JSON, ASSETS_DIRECTORY_PATH, Error, load_dotenv


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


def translate_text(text: str, language: str) -> Optional[str]:
    """
    Translates the given text into the specified language.

    Args:
        text (str): The text to be translated.
        language (str): The target language code for the translation.

    Returns:
        Optional[str]: The translated text if available, otherwise None. 
            If the language is 'en', the original text is returned.
    """

    translations = TRANSLATIONS.get(text, None)
    if not isinstance(translations, dict):
        return None

    if language == "en":
        return text

    translated_text = translations.get(language, None)
    if not isinstance(translated_text, str):
        return None

    return translated_text


def get_translations(language: str) -> dict:
    """
    Extract translations for a specific language.
    
    Args:
        language (str): The target language code.
    
    Returns:
        dict: Translations for the specified language with English
            key and translated value.
    """

    language_translations = {}

    for english_key, translations in TRANSLATIONS.items():
        if language in translations:
            language_translations[english_key] = translations[language]

        else:
            language_translations[english_key] = english_key

    return language_translations


def translate_error(error: Error, language: str) -> Error:
    """
    Translates the message of the given error into the specified language.

    Args:
        error (Error): The error object containing the message
            to be translated and any associated fields.
        language (str): The target language code for the translation

    Returns:
        Error: A new Error object with the translated message if successful, 
            or the original error if translation fails.
    """

    translated_message = translate_text(error.message, language)
    if not translated_message:
        return error

    return Error(
        translated_message,
        error.fields
    )
