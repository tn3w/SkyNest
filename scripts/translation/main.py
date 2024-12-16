"""
scripts/translation/main.py

This module provides functionality for translating text into multiple 
languages using the Google Translate API and tracking the progress of 
the translation process.

Usage:
    Run `pip install -r requirements.txt` first.
    Run this script directly to translate the required texts and 
    generate a translations JSON file.
"""

from math import ceil
from time import time
from os import path, name
from json import load, dump
from sys import exc_info, stdout
from traceback import format_exc
from typing import Final, Optional, Union, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from googletrans import Translator as GoogleTranslator


LOGO: Final[str] = """
┏━━━┓┏┓━━━━━━━┏━━━━┓━━━━━━━━━━━━━━━━┏┓━━━━━━━┏┓━━━━━
┃┏━┓┃┃┃━━━━━━━┃┏┓┏┓┃━━━━━━━━━━━━━━━━┃┃━━━━━━┏┛┗┓━━━━
┃┗━━┓┃┃┏┓┏┓━┏┓┗┛┃┃┗┛┏━┓┏━━┓━┏━┓━┏━━┓┃┃━┏━━┓━┗┓┏┛┏━━┓
┗━━┓┃┃┗┛┛┃┃━┃┃━━┃┃━━┃┏┛┗━┓┃━┃┏┓┓┃━━┫┃┃━┗━┓┃━━┃┃━┃┏┓┃
┃┗━┛┃┃┏┓┓┃┗━┛┃━┏┛┗┓━┃┃━┃┗┛┗┓┃┃┃┃┣━━┃┃┗┓┃┗┛┗┓━┃┗┓┃┃━┫
┗━━━┛┗┛┗┛┗━┓┏┛━┗━━┛━┗┛━┗━━━┛┗┛┗┛┗━━┛┗━┛┗━━━┛━┗━┛┗━━┛
━━━━━━━━━┏━┛┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
━━━━━━━━━┗━━┛━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""


GOOGLE_TRANSLATOR: Final[GoogleTranslator] = GoogleTranslator()

IS_WINDOWS: Final[bool] = name == 'nt'

CURRENT_DIRECTORY_PATH: Final[str] = path.dirname(path.abspath(__file__))
REQUIRED_TRANSLATIONS_FILE_PATH: Final[str] = path.join(
    CURRENT_DIRECTORY_PATH, "required_translations.json"
)
TRANSLATIONS_FILE_PATH: Final[str] = path.join(
    CURRENT_DIRECTORY_PATH, "translations.json"
)

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
        return load(file_stream)


def write_json_file(data: Union[dict, list], file_path: str) -> None:
    """
    Write data to a file in JSON format.

    Args:
        data (Union[dict, list]): The data to be serialized and written 
            to the file.
        file_path (str): The path to the file where the data will be 
            saved.
    """

    with open(file_path, "w", encoding = "utf-8") as file_stream:
        return dump(data, file_stream, separators = (',', ':'))


def translate(text: str, from_lang: str, to_lang: str) -> str:
    """
    Translate text from one language to another.

    Args:
        text (str): The text to be translated.
        from_lang (str): The language code of the source language.
        to_lang (str): The language code of the destination language.

    Returns:
        str: The translated text.
    """

    if from_lang == to_lang:
        return text

    return GOOGLE_TRANSLATOR.translate(text, src=from_lang, dest=to_lang).text


def process_translations(input_list: list, translations: dict) -> dict:
    """
    Process translations with dynamic placeholder replacement.
    
    Args:
        input_list (list): Original list of strings with <{}> placeholders
        translations (dict): Nested dictionary of translations for each string
    
    Returns:
        dict: Processed translations with placeholders replaced
    """

    working_list = input_list.copy()

    result = {}
    while working_list:
        current_text = working_list[0]

        if '<{}>' in current_text:
            if len(working_list) > 1:
                replacement_item = working_list[1]

                processed_translations = {}
                for lang, translation in translations[current_text].items():
                    if lang != 'en':
                        processed_text = translation.replace(
                            '<{}>',
                            f'&nbsp;<b>{translations[replacement_item][lang]}</b>'
                        )
                        processed_translations[lang] = processed_text

                updated_key = translations[current_text]['en'].replace(
                    '<{}>',
                    f'&nbsp;<b>{translations[replacement_item]["en"]}</b>'
                )

                result[updated_key] = processed_translations

                working_list.pop(0)
                working_list.pop(0)
            else:
                result[current_text] = {
                    lang: trans
                    for lang, trans in translations[current_text].items()
                    if lang != 'en'
                }
                break

        else:
            result[current_text] = {
                lang: trans
                for lang, trans in translations[current_text].items()
                if lang != 'en'
            }
            working_list.pop(0)

    return result


class Progress:
    """
    A class to represent a progress tracker for a task.

    Attributes:
        message (str): A message describing the task being tracked.
        messages (list): A list of additional messages to display with the progress.
        total (int): The total number of tasks to complete.
        finished (int): The number of tasks that have been completed.
        start_time (float): The time when the progress tracking started.
        last_remaining_time (float or None): The last calculated remaining time.
    """


    def __init__(self, message: str, total: int) -> None:
        """
        Initializes the Progress tracker.

        Args:
            message (str): A message describing the task being tracked.
            total (int): The total number of tasks to complete.

        Returns:
            None: This method does not return a value.
        """

        self.message = message
        self.messages = []
        self.total = total

        self.finished = 0
        self.start_time = time()
        self.last_remaining_time = None


    def plus_one(self) -> None:
        """
        Increment the finished task count by one.

        Returns:
            None: This method does not return a value.
        """

        self.update(self.finished + 1)


    def update(self, finished: Optional[int] = None) -> None:
        """
        Updates the progress with the number of finished tasks.

        Args:
            finished (Optional[int]): The number of tasks that have been completed.

        Returns:
            None: This method does not return a value.
        """

        if finished is not None:
            if finished <= self.finished:
                return

            self.finished = finished

        is_finished = False
        if self.finished >= self.total:
            self.total = self.finished
            is_finished = True

        elapsed_time = time() - self.start_time
        progress_speed = self.finished / elapsed_time if elapsed_time > 0 else 0

        remaining = self.total - self.finished
        remaining_time = max(0, remaining / progress_speed if progress_speed > 0 else float('inf'))
        if remaining_time == 0:
            remaining_time_str = "0"
        else:
            remaining_time_str = f"{remaining_time:.1f}"\
                if remaining_time < float('inf') else "unknown"

        total = str(self.total)
        finished = str(self.finished)

        progress = ceil((self.finished / self.total) * 30)
        progress_bar = '[' + '#' * progress + ' ' * (30 - progress) + ']'

        status = ""
        for message in self.messages:
            status += message + "\n"

        if len(self.messages) != 0:
            status += "\n"

        status += f'{self.message} [{finished} of {total}] ' \
            + progress_bar + f" ({remaining_time_str} s) "

        if is_finished:
            status += 'Done\n'

        if IS_WINDOWS:
            stdout.write('\r' + status)
            stdout.flush()
            return

        print('\r' + status, end='', flush=True)


def main() -> None:
    """
    Main function to load required translations and perform language translations.
    """

    required_translations = load_json_file(REQUIRED_TRANSLATIONS_FILE_PATH)

    print(LOGO)

    existing_translations = {}
    if path.exists(TRANSLATIONS_FILE_PATH):
        try:
            existing_translations = load_json_file(TRANSLATIONS_FILE_PATH)
        except Exception as e:
            print(f"Warning: Could not load existing translations: {e}")

    existing_translations_len = len(existing_translations)
    for key in existing_translations:
        if "<b>" in key:
            existing_translations_len += 1

    texts_to_translate = required_translations[existing_translations_len:]

    if len(texts_to_translate) == 0:
        print("Nothing to translate. Done.")
        return

    print(f"Translating {len(texts_to_translate)} Texts into {len(LANGUAGES)} languages.")

    progress = Progress("Translating...", len(texts_to_translate) * len(LANGUAGES))

    errors = ""
    def add_to_errors(error_message: str) -> None:
        """
        Adds an error message to a cumulative error log.

        Args:
            error_message (str): The error message to be added to the error log.
        """

        nonlocal errors
        if errors != "":
            errors += "\n"

        print(exc_info())
        if exc_info()[0] is not None:
            error_message += "\n" + format_exc()

        errors += error_message

    translations = {}
    def translate_with_error_handling(text: str, to_language: str) -> Tuple[str, str]:
        for i in range(3):
            try:
                translation = translate(text, "en", to_language)
            except Exception:
                if i == 2:
                    add_to_errors(
                        f"`{text}` could not be translated into language `{to_language}`."
                    )
                    return to_language, text

            else:
                break

        if "<{}>" in text and "<{}>" not in translation:
            add_to_errors(f"Placeholder in `{text}` is missing for language `{to_language}`.")

        return to_language, translation

    with ThreadPoolExecutor() as executor:
        for text in texts_to_translate:
            translations_for_text = {}

            future_to_language = {
                executor.submit(translate_with_error_handling, text, language): 
                language for language in LANGUAGES
            }

            for future in as_completed(future_to_language):
                language, translation = future.result()
                translations_for_text[language] = translation
                progress.plus_one()

            translations[text] = translations_for_text

    def error_out() -> None:
        """
        Checks for any recorded errors and prints them to the console.
        """

        if errors != "":
            print("\n\n[Errors]")
            print(errors)

    print("Post processing translations...")
    try:
        processed_translations = process_translations(texts_to_translate, translations)

        final_translations = existing_translations.copy()
        for text, language_translations in processed_translations.items():
            final_translations[text] = language_translations
    except Exception:
        add_to_errors("[Critical Error] Could not process translations.")
        error_out()
        return

    print(f"Writing to `{TRANSLATIONS_FILE_PATH}`...")
    try:
        write_json_file(final_translations, TRANSLATIONS_FILE_PATH)
    except Exception:
        add_to_errors(f"[Critical Error] Could not write to file `{TRANSLATIONS_FILE_PATH}`.")
    else:
        print("Done.")

    error_out()


if __name__ == "__main__":
    main()
