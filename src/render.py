"""
src/render.py

This module provides functionality for rendering HTML templates in a Flask application.
"""

from re import DOTALL, sub
from functools import lru_cache
from typing import Optional, Final
from os import listdir, path, environ

from flask import Request
from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    from src.request import get_domain_host
    from src.localisation import LANGUAGES, get_language, get_translations
    from src.utils import TEMPLATES_DIRECTORY_PATH, read_text, load_dotenv
except ModuleNotFoundError:
    from request import get_domain_host
    from localisation import LANGUAGES, get_language, get_translations
    from utils import TEMPLATES_DIRECTORY_PATH, read_text, load_dotenv


load_dotenv()
CREATOR: Final[Optional[str]] = environ.get("CREATOR", None)

REQUIRED_LANGUAGE: Optional[str] = environ.get("REQUIRED_LANGUAGE", None)
if REQUIRED_LANGUAGE not in LANGUAGES:
    REQUIRED_LANGUAGE = None

DEFAULT_LANGUAGE: Optional[str] = environ.get("DEFAULT_LANGUAGE", "en")
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


def render_template(template_name: str, request: Request, **context) -> str:
    """
    Renders a Jinja template with the given context and language settings.

    Args:
        template_name (str): The name of the template to render. If the name 
            does not end with '.html', it will be appended.
        request (Request): The request object used to determine the language 
            and domain for the template rendering.
        **context: Additional context variables to be passed to the template.

    Returns:
        str: The rendered HTML content of the template as a string.
    """

    language = REQUIRED_LANGUAGE \
        if REQUIRED_LANGUAGE else \
            get_language(request, DEFAULT_LANGUAGE)

    default_context = {
        "creator": CREATOR,
        "required_language": REQUIRED_LANGUAGE,
        "language": language
    }
    default_context.update(context)

    minimized_template = get_template(template_name)

    translations = get_translations(language)
    for key, value in translations.items():
        if "DOMAIN" in value:
            value = value.replace("DOMAIN", get_domain_host(request))
        minimized_template = minimized_template.replace(key, value)

    return render_jinja_template(minimized_template, **default_context)
