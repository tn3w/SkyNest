"""
src/crypto.py

A collection of utility classes and functions for cryptographic operations,
including hashing, encryption, TOTP generation, and Base62 encoding.
"""

from time import time
from io import BytesIO
from base64 import b32decode
from hashlib import sha1, sha256
from hmac import new as new_hmac
from secrets import choice, token_bytes
from typing import Final, Union, Optional, Tuple

from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_H

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from src.logger import log
    from src.utils import convert_image_to_base64
except (ModuleNotFoundError, ImportError):
    from logger import log
    from utils import convert_image_to_base64


CHARACTERS: Final[str] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


class Base62:
    """
    A class for encoding and decoding data using Base62 encoding.
    """


    @staticmethod
    def encode(plain: bytes) -> Optional[str]:
        """
        Encodes a byte sequence into a Base62-encoded string.

        Args:
            plain (bytes): The byte sequence to be encoded.

        Returns:
            Optional[str]: The Base62-encoded string representation of the input bytes.
        """

        try:
            base = len(CHARACTERS)
            number = int.from_bytes(plain, byteorder='big')
            encoded = []

            while number > 0:
                number, remains = divmod(number, base)
                encoded.append(CHARACTERS[remains])

            return ''.join(reversed(encoded))

        except (TypeError, ValueError):
            log("Base62 Encoding Error.", level=4)

        return None


    @staticmethod
    def decode(serialized: str) -> Optional[bytes]:
        """
        Decodes a Base62-encoded string back into its original byte sequence.

        Args:
            serialized (str): The Base62-encoded string to decode.

        Returns:
            Optional[bytes]: The original byte sequence.
        """

        try:
            base = len(CHARACTERS)

            char_to_value = {char: index for index, char in enumerate(CHARACTERS)}

            num = 0
            for char in serialized:
                if char not in char_to_value:
                    raise ValueError(f"Invalid character '{char}' in input.")

                num = num * base + char_to_value[char]

            if num == 0:
                byte_length = 1
            else:
                byte_length = (num.bit_length() + 7) // 8

            return num.to_bytes(byte_length, byteorder='big')

        except (TypeError, ValueError, AttributeError):
            log("Base62 Decoding Error.", level=4)

        return None


def sha256_hash(text: Union[str, bytes]) -> Optional[bytes]:
    """
    Computes the SHA-256 hash of the given input.

    Args:
        text (Union[str, bytes]): The input text to be hashed. 
            It can be a string or bytes.

    Returns:
        bytes: The SHA-256 hash of the input as a byte string.
    """

    try:
        if isinstance(text, str):
            text = text.encode("utf-8")

        return sha256(text).digest()

    except (TypeError, ValueError, UnicodeEncodeError):
        log("sha256_hash Error.", level=4)

    return None


def sha256_hash_text(text: Union[str, bytes]) -> Optional[str]:
    """
    Computes the SHA-256 hash of the given input and encodes it in Base62.

    Args:
        text (Union[str, bytes]): The input text to be hashed. 
            It can be a string or bytes.

    Returns:
        Optional[str]: The Base62 encoded SHA-256 hash of the input.
    """

    hashed_text = sha256_hash(text)
    if not isinstance(hashed_text, bytes):
        return None

    return Base62.encode(hashed_text)


class SHA256:
    """
    A class to perform hashing operations with optional salting and serialization.
    """


    def __init__(self, iterations: int = 10000, hash_length: int = 8,
                 salt_length: int = 8, use_encoding: bool = False) -> None:
        """
        Initializes the Hashing class with specified parameters.

        Args:
            iterations (int, optional): The number of iterations for the hashing process.
            hash_length (int, optional): The length of the resulting hash in bytes.
            salt_length (int, optional): The length of the salt in bytes.
        """

        self.iterations = iterations
        self.hash_length = hash_length
        self.salt_length = salt_length
        self.use_encoding = use_encoding


    def _hash(self, plain_value: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA3_256(),
            length = self.hash_length,
            salt = salt,
            iterations = self.iterations,
            backend = default_backend()
        )

        hashed_value = kdf.derive(plain_value)

        return hashed_value


    def hash(self, plain_value: Union[str, bytes],
             salt: Optional[Union[str, bytes]] = None) -> Optional[Union[str, bytes]]:
        """
        Hashes the given plain value with an optional salt.

        Args:
            plain_value (Union[str, bytes]): The plain value to be hashed.
            salt (Optional[Union[str, bytes]]): An optional salt.
                If not provided, a new salt will be generated.

        Returns:
            Optional[Union[str, bytes]]: 
                The serialized hash, and optionally the salt if return_salt is True.
        """

        try:
            if isinstance(plain_value, str):
                plain_value = plain_value.encode('utf-8')

            use_salt = b""
            if self.salt_length > 0:
                if salt is None:
                    use_salt = token_bytes(self.salt_length)
                else:
                    if isinstance(salt, str):
                        use_salt = salt.encode("utf-8")
                    use_salt = use_salt[:self.salt_length]

            hashed = self._hash(plain_value, use_salt)
            combined_hash = use_salt + hashed

            if self.use_encoding:
                combined_hash = Base62.encode(combined_hash)

            return combined_hash

        except (TypeError, ValueError, AttributeError, OverflowError,
                MemoryError, RuntimeError, UnicodeEncodeError):
            log("SHA256 Hashing Error.", level=4)

        return None


    def compare(self, plain_value: Union[str, bytes],
                hashed_value: Union[str, bytes], salt: Optional[Union[str, bytes]] = None) -> bool:
        """
        Compares a plain value with a hashed value to check for equality.

        Args:
            plain_value (Union[str, bytes]): The plain value to compare.
            hashed_value (Union[str, bytes]): The hashed value to compare against.
            salt (Optional[Union[str, bytes]]): An optional salt. If not provided,
                the salt will be extracted from the hashed value.

        Returns:
            bool: True if the plain value matches the hashed value, False otherwise.
        """

        try:
            if isinstance(plain_value, str):
                plain_value = plain_value.encode('utf-8')

            if isinstance(hashed_value, str) and self.use_encoding:
                hashed_value = Base62.decode(hashed_value)
                if not hashed_value:
                    return False

            if not isinstance(hashed_value, bytes):
                return False

            use_salt = b""
            real_hash = hashed_value
            if self.salt_length > 0:
                if salt is not None:
                    if isinstance(salt, str):
                        use_salt = salt.encode("utf-8")
                    use_salt = use_salt[:self.salt_length]
                else:
                    use_salt = hashed_value[:self.salt_length]
                    real_hash = hashed_value[self.salt_length:]

            hashed = self._hash(plain_value, use_salt)

            return hashed == real_hash

        except (TypeError, ValueError, UnicodeDecodeError):
            log("SHA256 Comparing Error.", level=4)

        return False


def split_into_chunks(data: bytes, length: int) -> list[bytes]:
    """
    Split the input data into chunks of a specified length.
    The last chunk will be removed if it is not of the given length.

    Args:
        data (bytes): The input data to be split.
        length (int, optional): The length of each chunk.

    Returns:
        list[bytes]: A list containing the chunks of the specified length.
    """

    chunks = [data[i:i+length] for i in range(0, len(data), length)]

    if len(chunks) > 0 and len(chunks[-1]) != length:
        chunks.pop()

    return chunks


def derive_key(token: bytes, salt: Optional[bytes] = None,
                length: int = 32) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Derives a key using PBKDF2-HMAC-SHA256.

    Args:
        token (bytes): The token used for key derivation.
        salt (Optional[bytes]): The salt for key derivation. If None, a new salt is generated.
        length (int): The desired length of the derived key.

    Returns:
        Tuple[Optional[bytes], Optional[bytes]]: A tuple containing the salt and the derived key.
    """

    try:
        if salt is None:
            salt = token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=10_000,
            backend=default_backend(),
        )
        key = kdf.derive(token)
        return salt, key

    except (TypeError, ValueError, AttributeError, RuntimeError):
        log("SHA256 Comparing Error.", level=4)

    return None, None


class AES:
    """
    An interface to perform symmetric encryption
    and decryption using a token-based approach.
    """


    def __init__(self, token: Union[str, bytes],
                 iterations: int = 1, use_encoding: bool = False) -> None:
        """
        Initializes the SymmetricEncryption class with a token and serialization method.

        Args:
            token (Union[str, bytes]): The token used for encryption and decryption.
            iterations (int, optional): The number of iterations for the encryption process.
        """

        if isinstance(token, str):
            token = token.encode("utf-8")

        self.token = token
        self.iterations = iterations
        self.use_encoding = use_encoding


    def _encrypt(self, hashed_token: bytes, plain_value: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypts the given plain value using the hashed token.

        Args:
            hashed_token (bytes): The hashed token used for encryption.
            plain_value (bytes): The plain value to be encrypted.

        Returns:
            Tuple[bytes, bytes]: A tuple containing the initialization
                vector and the encrypted value.
        """

        iv = token_bytes(16)

        cipher = Cipher(algorithms.AES256(hashed_token), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES256.block_size).padder()
        padded_data = padder.update(plain_value) + padder.finalize()

        cipher_value = encryptor.update(padded_data) + encryptor.finalize()

        return iv, cipher_value


    def _decrypt(self, hashed_token: bytes, cipher_value: bytes, iv: bytes) -> bytes:
        """
        Decrypts the given cipher value using the hashed token and initialization vector.

        Args:
            hashed_token (bytes): The hashed token used for decryption.
            cipher_value (bytes): The encrypted value to be decrypted.
            iv (bytes): The initialization vector used for decryption.

        Returns:
            bytes: The decrypted plain value.
        """

        cipher = Cipher(
            algorithms.AES256(hashed_token),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(cipher_value) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return decrypted_data


    def encrypt(self, plain_value: Union[str, bytes]) -> Optional[Union[str, bytes]]:
        """
        Encrypts the given plain value.

        Args:
            plain_value (Union[str, bytes]): The plain value to be encrypted.

        Returns:
            Optional[Union[str, bytes]]: The encrypted value, potentially serialized.
        """

        try:
            if isinstance(plain_value, str):
                plain_value = plain_value.encode("utf-8")

            salt, hashed_token = derive_key(self.token, length = 32)
            if not salt or not hashed_token:
                return None

            cipher_value = plain_value

            iv, cipher_value = self._encrypt(hashed_token, cipher_value)

            return_data = salt + iv + cipher_value

            if self.use_encoding:
                return Base62.encode(return_data)

            return return_data

        except (TypeError, ValueError, AttributeError, RuntimeError):
            log("AES Encryption Error.", level=4)

        return None


    def decrypt(self, cipher_value: Union[str, bytes]) -> Optional[Union[str, bytes]]:
        """
        Decrypts the given cipher value.

        Args:
            cipher_value (Union[str, bytes]): The encrypted value to be decrypted.

        Returns:
            Union[str, bytes]: The decrypted plain value, potentially deserialized.
        """

        try:
            if self.use_encoding and isinstance(cipher_value, str):
                cipher_value = Base62.decode(cipher_value)
                if not cipher_value:
                    return None

            if not isinstance(cipher_value, bytes):
                return None

            salt = cipher_value[:16]

            iv = cipher_value[16:32]
            cipher_value = cipher_value[32:]

            _, hashed_token = derive_key(self.token, salt, length = 32)

            if not hashed_token:
                return None

            plain_value = self._decrypt(hashed_token, cipher_value, iv)
            return plain_value

        except (TypeError, ValueError, AttributeError, RuntimeError, UnicodeEncodeError):
            log("AES Decryption Error.", level=4)

        return None


def generate_base32_secret(length: int = 16) -> str:
    """
    Generate a secure random Base32-encoded string.

    Args:
        length (int): The length of the Base32 string.

    Returns:
        str: A Base32-encoded secure random string.
    """

    base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return ''.join(choice(base32_chars) for _ in range(length))


def generate_totp_qrcode(secret: str, company: str, user: str) -> QRCode:
    """
    Generate a QR code for a TOTP setup and return it as a base64 URL for a PNG image.

    Args:
        secret (str): Base32-encoded secret for the TOTP.
        company (str): Name of the company or service.
        user (str): Name of the user.

    Returns:
        str: A base64-encoded URL for the PNG QR code image.

    """

    otpauth_url = f"otpauth://totp/{company}:{user}?secret={secret}&issuer={company}"

    qr = QRCode(
        version = 1, error_correction = ERROR_CORRECT_H,
        box_size = 10, border = 4
    )
    qr.add_data(otpauth_url)
    qr.make(fit = True)

    return qr


def generate_image_url_from_qr(qr: QRCode, colors: Tuple[str, str]) -> str:
    """
    Generate a base64-encoded data URL for a QR code image.

    Args:
        qr (QRCode): An instance of the `qrcode.QRCode` class used to generate the QR code.
        colors (Tuple[str, str]): A tuple containing the background and fill colors.

    Returns:
        str: A base64-encoded data URL representing the QR code image, formatted as:
            "data:image/png;base64,<base64_encoded_image>"
    """

    img = qr.make_image(back_color = colors[0], fill_color = colors[1])

    buffered = BytesIO()
    img.save(buffered, format="WEBP")
    buffered.seek(0)

    return convert_image_to_base64(buffered.read())


class TOTP:
    """
    Implements a Time-based One-Time Password (TOTP) generator and verifier.
    """


    def __init__(self, secret: str, interval: int = 30, digits: int = 6):
        """
        Initializes the TOTP class with a secret key and optional settings.

        Args:
            secret (str): The Base32-encoded secret key for generating tokens.
            interval (int, optional): Time step in seconds (default is 30 seconds).
            digits (int, optional): Number of digits in the token (default is 6).
        """
        self.secret = secret
        self.interval = interval
        self.digits = digits


    def _time_counter(self, offset: int = 0) -> int:
        """
        Calculates the time counter based on the current time and an optional offset.

        Args:
            offset (int, optional): Number of intervals to adjust forward or backward.

        Returns:
            int: The current time counter.
        """
        return int(time() // self.interval) + offset


    def _generate_hmac(self, counter: int) -> bytes:
        """
        Generates an HMAC using the provided time counter.

        Args:
            counter (int): The time counter value.

        Returns:
            bytes: The resulting HMAC digest.
        """

        counter_bytes = counter.to_bytes(8, 'big')
        key = b32decode(self.secret, casefold=True)
        return new_hmac(key, counter_bytes, sha1).digest()


    def generate_token(self, offset: int = 0) -> str:
        """
        Generates a TOTP token for the current or adjusted time.

        Args:
            offset (int, optional): Number of intervals to adjust forward or backward.

        Returns:
            str: A TOTP token as a string of the specified number of digits.
        """

        counter = self._time_counter(offset)
        hmac_digest = self._generate_hmac(counter)

        dynamic_offset = hmac_digest[-1] & 0x0F
        code = int.from_bytes(hmac_digest[dynamic_offset:dynamic_offset + 4], 'big') & 0x7FFFFFFF
        return str(code % (10 ** self.digits)).zfill(self.digits)


    def verify_token(self, token: str) -> bool:
        """
        Verifies a TOTP token against the current and next time intervals.

        Args:
            token (str): The TOTP token to verify.

        Returns:
            bool: True if the token is valid; False otherwise.
        """

        return any(
            token == self.generate_token(offset)
            for offset in range(-1, 1)
        )
