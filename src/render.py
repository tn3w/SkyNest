"""
src/render.py

This module provides functionality for rendering HTML templates in a Flask application.
"""

from html import escape
from functools import lru_cache
from typing import Optional, Final
from re import DOTALL, sub, findall
from os import listdir, path, environ

from flask import Response, request, send_file
from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    from src.state import create_state
    from src.request import get_domain_host
    from src.captcha import generate_powbox_challenge, create_captcha
    from src.utils import TEMPLATES_DIRECTORY_PATH, FAVICON_FILE_PATH, Error, read_text, load_dotenv
    from src.localisation import (
        LANGUAGES, get_language, get_translations, translate_text, translate_error
    )
except ModuleNotFoundError:
    from state import create_state
    from request import get_domain_host
    from captcha import generate_powbox_challenge, create_captcha
    from utils import TEMPLATES_DIRECTORY_PATH, FAVICON_FILE_PATH, Error, read_text, load_dotenv
    from localisation import (
        LANGUAGES, get_language, get_translations, translate_text, translate_error
    )


load_dotenv()
CREATOR: Final[Optional[str]] = environ.get("CREATOR", None)

REQUIRED_LANGUAGE: Optional[str] = environ.get("REQUIRED_LANGUAGE", None)
if REQUIRED_LANGUAGE not in LANGUAGES:
    REQUIRED_LANGUAGE = None

DEFAULT_LANGUAGE: str = environ.get("DEFAULT_LANGUAGE", "en")
if DEFAULT_LANGUAGE not in LANGUAGES:
    REQUIRED_LANGUAGE = "en"


def minimize_html(html: str) -> str:
    """
    Minimize an HTML template by removing unnecessary whitespace, comments,
    and newlines, while also minimizing embedded <style> and <script> tags.

    Args:
        html (str): The input HTML string to be minimized.

    Returns:
        str: A minimized version of the input HTML string.
    """

    pre_tags = findall(r"(<pre.*?>.*?</pre>)", html, flags=DOTALL)
    for idx, pre_tag in enumerate(pre_tags):
        placeholder = f"__PRE_TAG_{idx}__"
        html = html.replace(pre_tag, placeholder)

    html = sub(r"<!--.*?-->", "", html, flags=DOTALL)

    def minify_js_css(content: str) -> str:
        content = sub(r"\s*([{}:;,])\s*", r"\1", content)
        content = sub(r"\s+", " ", content)
        return content.strip()

    def minify_js(content: str) -> str:
        content = sub(r"\s*([{}();,:])\s*", r"\1", content)
        content = sub(r"\s+", " ", content)
        return content.strip()

    html = sub(
        r"(<style.*?>)(.*?)(</style>)",
        lambda m: m.group(1) + minify_js_css(m.group(2)) + m.group(3),
        html, flags=DOTALL
    )

    html = sub(
        r"(<script.*?>)(.*?)(</script>)",
        lambda m: m.group(1) + minify_js(m.group(2)) + m.group(3),
        html, flags=DOTALL
    )

    html = sub(r">\s*<", "><", html)

    html = sub(r"\s{2,}", " ", html)
    html = sub(r"\s*<\s*", "<", html)
    html = sub(r"\s*>\s*", ">", html)

    html = sub(r">\s+<", "><", html)
    html = html.strip()

    for idx, pre_tag in enumerate(pre_tags):
        placeholder = f"__PRE_TAG_{idx}__"
        html = html.replace(placeholder, pre_tag)

    return html


TEMPLATES: dict[str, str] = {}


for template in listdir(TEMPLATES_DIRECTORY_PATH):
    template_path = path.join(TEMPLATES_DIRECTORY_PATH, template)
    if not path.isfile(template_path) or not template.endswith(".html"):
        continue

    template_content = read_text(template_path)
    if not template_content:
        continue

    TEMPLATES[template] = minimize_html(template_content)


@lru_cache()
def get_template(template_name: str) -> Optional[str]:
    """
    Retrieves the specified template from the TEMPLATES dictionary.

    Args:
        template_name (str): The name of the template to retrieve. 
            It should be a string that may or may not include the '.html' extension.

    Returns:
        Optional[str]: The template content as a string if found, 
            or None if the template does not exist in the TEMPLATES dictionary.
    """

    if not template_name.endswith(".html"):
        template_name += ".html"

    return TEMPLATES.get(template_name, None)


def render_jinja_template(template_html: str, **context) -> str:
    """
    Renders an HTML template with the given context.

    Args:
        minimized_template (str): The html template.
        **context: Arbitrary keyword arguments that will be passed to the template for rendering.

    Returns:
        str: The rendered HTML as a string.
    """

    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIRECTORY_PATH),
        autoescape=select_autoescape(['html', 'xml'])
    )

    template_env = env.from_string(template_html)

    return template_env.render(**context)


def render_template(template_name: str, translate_text_fields: \
                    Optional[list] = None, **context) -> str:
    """
    Renders a Jinja template with the given context and language settings.

    Args:
        template_name (str): The name of the template to render. If the name 
            does not end with '.html', it will be appended.
        **context: Additional context variables to be passed to the template.

    Returns:
        str: The rendered HTML content of the template as a string.
    """

    if not isinstance(translate_text_fields, list):
        translate_text_fields = []

    language = REQUIRED_LANGUAGE \
        if REQUIRED_LANGUAGE else \
            get_language(request, DEFAULT_LANGUAGE)

    default_context = {
        "creator": CREATOR,
        "required_language": REQUIRED_LANGUAGE,
        "language": language
    }
    default_context.update(context)

    default_context = {
        key: escape(value) if isinstance(value, str) else value
        for key, value in default_context.items()
    }

    for field in translate_text_fields:
        context_field_content = default_context.get(field, None)
        if isinstance(context_field_content, str):
            translated_field_content = translate_text(context_field_content, language)
            if translated_field_content:
                default_context[field] = translated_field_content

    context_error = default_context.get("error", None)
    if isinstance(context_error, Error):
        default_context["error"] = translate_error(context_error, language)

    minimized_template = get_template(template_name)
    if not minimized_template:
        return "Not Found."

    translations = get_translations(language)
    for key, value in translations.items():
        if "DOMAIN" in value:
            value = value.replace("DOMAIN", escape(get_domain_host(request)))
        minimized_template = minimized_template.replace(key, value)

    return render_jinja_template(minimized_template, **default_context)


def render_text(text: str) -> Response:
    """
    Create a plain text response.

    Args:
        text (str): The text content to be included in the response.

    Returns:
        Response: A Response object containing the provided text and
            a MIME type of "text/plain".
    """

    return Response(text, mimetype = "text/plain")


@lru_cache(maxsize=1)
def render_favicon() -> Response:
    """
    Render the favicon for the application.

    Returns:
        Response: A Flask Response object containing the favicon file.
    """

    response = send_file(FAVICON_FILE_PATH, mimetype="image/vnd.microsoft.icon")
    response.headers["Cache-Control"] = "public, max-age=86400"

    return response


@lru_cache(maxsize=1)
def render_robots() -> Response:
    """
    Render the robots.txt file for the application.

    Returns:
        Response: A Flask Response object containing the robots.txt content.
    """

    response = render_text("User-agent: *\nAllow: /")
    response.headers["Cache-Control"] = "public, max-age=86400"

    return response


def render_login(user_name: Optional[str] = None,
                 password: Optional[str] = None,
                 error: Optional[Error] = None) -> str:
    """
    Render the login page.

    Args:
        user_name (Optional[str]): The username entered by the user. Defaults to None.
        password (Optional[str]): The password entered by the user. Defaults to None.
        error (Optional[Error]): An optional error message to display. Defaults to None.

    Returns:
        str: The rendered HTML of the login page.
    """

    powbox_challenge, powbox_state = generate_powbox_challenge()

    return render_template(
        "login", error = error, user_name = user_name, password = password,
        powbox_challenge = powbox_challenge, powbox_state = powbox_state
    )


def render_signup(user_name: Optional[str] = None,
                  password: Optional[str] = None,
                  repeated_password: Optional[str] = None,
                  error: Optional[Error] = None) -> str:
    """
    Render the signup page.

    Args:
        user_name (Optional[str]): The username entered by the user. Defaults to None.
        password (Optional[str]): The password entered by the user. Defaults to None.
        repeated_password (Optional[str]): The password repeated by the user
            for confirmation. Defaults to None.
        error (Optional[Error]): An optional error message to display. Defaults to None.

    Returns:
        str: The rendered HTML of the signup page.
    """

    powbox_challenge, powbox_state = generate_powbox_challenge()

    return render_template(
        "signup", error = error, user_name = user_name, password = password,
        repeated_password = repeated_password, powbox_challenge = powbox_challenge,
        powbox_state = powbox_state
    )


def render_captcha(user_name: str, password: str, error: Optional[Error] = None) -> str:
    """
    Render the CAPTCHA page.

    Args:
        user_name (str): The username entered by the user.
        password (str): The password entered by the user.
        error (Optional[Error]): An optional error message to display. Defaults to None.

    Returns:
        str: The rendered HTML of the CAPTCHA page.
    """

    images, state = create_captcha(
        {"user_name": user_name, "password": password}
    )

    return render_template(
        "captcha", images = images,
        state = state, error = error
    )


def render_twofa(user_name: str, password: str, error: Optional[Error] = None) -> str:
    """
    Render the two-factor authentication (2FA) page.

    Args:
        user_name (str): The username entered by the user.
        password (str): The password entered by the user.
        error (Optional[Error]): An optional error message to display. Defaults to None.

    Returns:
        str: The rendered HTML of the two-factor authentication page.
    """

    state = create_state(
        "twofa", {
            "user_name": user_name,
            "password": password
        }
    )

    return render_template("twofa", state = state, error = error)
