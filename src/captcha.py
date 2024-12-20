"""
src/captcha.py

This module provides functionality for generating CAPTCHAs using images, verifying user responses, 
and processing images with distortion techniques.
"""

from os import path
from hashlib import sha256
from secrets import choice
from gzip import decompress
from typing import Final, Tuple
from functools import lru_cache

import cv2
import numpy as np
from flask import Request

try:
    from src.request import is_post
    from src.state import create_state, get_state
    from src.utils import (
        ASSETS_DIRECTORY_PATH, PICKLE,
        generate_random_string, convert_image_to_base64, secure_shuffle
    )
except ModuleNotFoundError:
    from request import is_post
    from state import create_state, get_state
    from utils import (
        ASSETS_DIRECTORY_PATH, PICKLE,
        generate_random_string, convert_image_to_base64, secure_shuffle
    )


DATASET_FILE_PATH: Final[str] = path.join(ASSETS_DIRECTORY_PATH, "ai-dogs.pkl")
DECOMPRESSED_DATASET_FILE_PATH: Final[str] = path.join(
    ASSETS_DIRECTORY_PATH, "ai-dogs-decompressed.pkl"
)


def generate_powbox_challenge() -> Tuple[str, str]:
    """
    Generate a Proof of Work (PoW) challenge and its associated state.

    Returns:
        Tuple[str, str]: A tuple containing the generated challenge and 
        the encoded state string.
    """

    challenge = generate_random_string(32, "aA0")

    state = create_state("pow", {"challenge": challenge})
    return challenge, state


def verify_pow_response(request: Request, difficulty: int = 5) -> bool:
    """
    Verify the Proof of Work (PoW) response from a client request.

    Args:
        request (Request): The incoming request object containing the 
            PoW solution and state.
        difficulty (int, optional): The difficulty level for the PoW. 
            The default value is 5, which means the solution hash must 
            start with at least 5 leading zeros.

    Returns:
        bool: True if the PoW response is valid, False otherwise.
    """

    if not is_post(request):
        return False

    powbox_solution = request.form.get("powbox_solution")
    powbox_state = request.form.get("powbox_state")
    if not powbox_solution or not powbox_state:
        return False

    state_name, decoded_data = get_state(powbox_state, True)
    challenge = decoded_data.get("challenge", None)
    if state_name != "pow" or not challenge:
        return False

    solution_hash = sha256(f"{challenge}{powbox_solution}".encode()).hexdigest()
    if not solution_hash.startswith("0" * difficulty):
        return False

    return True


@lru_cache()
def load_dataset() -> dict:
    """
    Load and decompress a dataset from a file.

    Returns:
        Dict[str, Any]: A dictionary containing the decompressed dataset 
            where keys are identifiers and values are lists of decompressed 
            images. If no dataset is found, an empty dictionary is returned.
    """

    if path.isfile(DECOMPRESSED_DATASET_FILE_PATH):
        return PICKLE.load(DECOMPRESSED_DATASET_FILE_PATH)

    if not path.isfile(DATASET_FILE_PATH):
        return {}

    dataset = PICKLE.load(DATASET_FILE_PATH, {})["keys"]

    decompressed_dataset = {}
    for key, images in dataset.items():
        decompressed_dataset[key] = [decompress(image) for image in images]

    PICKLE.dump(decompressed_dataset, DECOMPRESSED_DATASET_FILE_PATH)
    return decompressed_dataset


def distort_image(image_data: bytes) -> bytes:
    """
    Distort image using optimized techniques with OpenCV and NumPy for high performance.

    Args:
        image_data (bytes): The bytes representing the original image.

    Returns:
        bytes: The bytes of the distorted image in WebP format.
    """

    img = cv2.imdecode(np.frombuffer(image_data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Invalid image data")

    img = cv2.resize(img, (100, 100), interpolation=cv2.INTER_AREA)

    height, width, _ = img.shape
    max_shift = 3
    x_shifts = np.random.randint(-max_shift, max_shift + 1, (height, width))
    y_shifts = np.random.randint(-max_shift, max_shift + 1, (height, width))

    map_x, map_y = np.meshgrid(np.arange(width), np.arange(height))
    map_x = (map_x + x_shifts) % width
    map_y = (map_y + y_shifts) % height

    distorted_img = cv2.remap(
        img, map_x.astype(np.float32),
        map_y.astype(np.float32),
        interpolation=cv2.INTER_LINEAR
    )
    distorted_img = cv2.GaussianBlur(distorted_img, (3, 3), sigmaX=0.5)

    success, encoded_img = cv2.imencode('.webp', distorted_img, [cv2.IMWRITE_WEBP_QUALITY, 85])
    if not success:
        raise ValueError("Failed to encode image to WebP format")

    return encoded_img.tobytes()


def random_image(images: list) -> str:
    """
    Select a random image from a list and convert it to a base64-encoded format.

    Args:
        images (list): A list of images from which to select a random image.

    Returns:
        str: A base64-encoded byte string representation of the distorted image.
    """

    secure_random_image = choice(images)
    distorted_image = distort_image(secure_random_image)

    return convert_image_to_base64(distorted_image)


def create_captcha(data: dict, captcha_type: str = "oneclick") -> Tuple[list, str]:
    """
    Create a CAPTCHA consisting of a set of images, including one correct image.

    Args:
        data (dict): A dictionary to store the correct image indices and 
            any additional data related to the CAPTCHA.
        captcha_type (str, optional): The type of CAPTCHA to create. 
            Defaults to "oneclick".

    Returns:
        Tuple[list, str]: A tuple containing base64-encoded images and an associated state string.
    """

    dataset = load_dataset()
    keys = list(dataset.keys())

    captcha_images = []
    correct_image_indexs = []
    if captcha_type == "oneclick":
        random_correct_image = random_image(dataset[keys[0]])
        captcha_images.append(random_correct_image)

        for _ in range(5):
            random_key = None
            while not random_key or random_key == keys[0]:
                random_key = choice(keys)

            random_incorrect_image = random_image(dataset[random_key])
            captcha_images.append(random_incorrect_image)

        captcha_images = secure_shuffle(captcha_images)
        correct_image_indexs.append(captcha_images.index(random_correct_image))

    data["correct_images"] = correct_image_indexs

    state = create_state("captcha_" + captcha_type, data)
    return captcha_images, state


def get_clicked_images(request: Request) -> list:
    """
    Retrieve and clean the list of clicked image indices from the request.

    Args:
        request (Request): The incoming request object containing the 
            clicked image indices.

    Returns:
        list: A list of cleaned integer indices representing the clicked 
            images. If no valid indices are found, an empty list is returned.
    """

    clicked_images = []

    index = request.args.get("i")
    if index:
        clicked_images.append(index[:1])

    if is_post(request):
        for i in range(9):
            index = request.form.get(f"i{i}")
            if index:
                clicked_images.append(i)

    cleaned_clicked_images = []
    for number in clicked_images:
        if isinstance(number, str) and number.isdigit():
            number = int(number)

        if not isinstance(number, int):
            continue

        cleaned_clicked_images.append(number)

    return cleaned_clicked_images


def is_valid_captcha(state_data: dict, clicked_images: list) -> bool:
    """
    Validate the clicked images against the correct CAPTCHA answers.

    Args:
        state_data (dict): A dictionary containing the correct image 
            indices for the CAPTCHA.
        clicked_images (list): A list of indices representing the images 
            clicked by the user.

    Returns:
        bool: True if the clicked images match the correct images, 
            False otherwise.
    """

    if sorted(state_data["correct_images"]) != sorted(clicked_images):
        return False

    return True


load_dataset()
