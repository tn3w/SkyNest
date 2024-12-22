from os import environ
from typing import Final, Optional, Tuple, Union

from gunicorn.app.base import BaseApplication
from flask import Flask, Response, request, g
from werkzeug.middleware.proxy_fix import ProxyFix

from cli import init_cli
from src.access import verify_access
from src.render import render_template
from src.crypto import sha256_hash_text
from src.state import get_state, create_state, get_beam_id
from src.ddos_mitigation import rate_limit, is_ip_malicious
from src.utils import CURRENT_DIRECTORY_PATH, Error, text_response
from src.request import is_post, get_scheme, get_user_agent, get_ip_address
from src.errors import WEB_ERROR_CODES, NOT_RIGHT_ERROR, UN_OR_PWD_NOT_RIGHT_ERROR
from src.user import create_test_user, get_signin_error, create_session, verify_twofa
from src.captcha import (
    generate_powbox_challenge, verify_pow_response, create_captcha,
    get_clicked_images, is_valid_captcha
)


LOGO: Final[str] = """
┏━━━┓┏┓━━━━━━━┏━┓━┏┓━━━━━━━━━┏┓━
┃┏━┓┃┃┃━━━━━━━┃┃┗┓┃┃━━━━━━━━┏┛┗┓
┃┗━━┓┃┃┏┓┏┓━┏┓┃┏┓┗┛┃┏━━┓┏━━┓┗┓┏┛
┗━━┓┃┃┗┛┛┃┃━┃┃┃┃┗┓┃┃┃┏┓┃┃━━┫━┃┃━
┃┗━┛┃┃┏┓┓┃┗━┛┃┃┃━┃┃┃┃┃━┫┣━━┃━┃┗┓
┗━━━┛┗┛┗┛┗━┓┏┛┗┛━┗━┛┗━━┛┗━━┛━┗━┛
━━━━━━━━━┏━┛┃━━━━━━━━━━━━━━━━━━━
━━━━━━━━━┗━━┛━━━━━━━━━━━━━━━━━━━
"""


POW_DIFFICULTY_RAW: str = environ.get("POW_DIFFICULTY", "")
POW_DIFFICULTY: int = 5
if POW_DIFFICULTY_RAW.isdigit():
    POW_DIFFICULTY = int(POW_DIFFICULTY_RAW)


ACCESS_TOKEN: Final[Optional[str]] = environ.get("ACCESS_TOKEN", None)
ONE_YEAR_IN_SECONDS: Final[int] = 31536000


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)


########################
#### Error Handlers ####
########################


def handle_exception(exception: Exception) -> Tuple[str, int]:
    """
    Handle exceptions and render an appropriate error response.

    Args:
        exception (Exception): The exception that was raised. This can be
            any instance of the Exception class or its subclasses.

    Returns:
        str: A rendered HTML template containing the error information,
            along with the HTTP status code associated with the error.
    """

    title = None
    description = None

    code = str(exception).split(' ', maxsplit=1)[0]
    if hasattr(exception, "code"):
        code = getattr(exception, "code", None)
        if code in WEB_ERROR_CODES:
            title = WEB_ERROR_CODES[code]['title']
            description = WEB_ERROR_CODES[code]['description']

    elif isinstance(exception, Exception):
        title = type(exception).__name__

    if not isinstance(code, int):
        code = 400

    if not description and title:
        description = str(exception).replace(title, '').strip()

    reveal = getattr(g, "browser_verified", False) and \
        (ACCESS_TOKEN is None or getattr(g, "access_verified", False))

    return render_template(
        "exception", request, ["title", "description"],
        code = code, title = title or "Unexpected Error",
        description = description or "Something unexpected has happened.",
        reveal = reveal
    ), code


for error_code in WEB_ERROR_CODES:
    app.register_error_handler(error_code, handle_exception)


##############################
#### before/after request ####
##############################


@app.before_request
def checking_browser() -> Optional[str]:
    """
    Check the browser's verification status before processing the request.

    Returns:
        Optional[str]: If the browser is verified, returns None to
            continue processing the request. If the browser fails verification,
            returns a rendered template for rate limiting or a browser check
            challenge, which will halt further request processing.
    """

    ip_address = get_ip_address(request)

    hashed_ip_address = ""
    if isinstance(ip_address, str):
        hashed_ip_address = sha256_hash_text(ip_address)

    if rate_limit(ip_address):
        return render_template("rate_limit", request)

    challenge_cookie = request.cookies.get("challenge")
    if challenge_cookie:
        state_name, state_data = get_state(challenge_cookie)
        if state_name == "browser_checked" and \
            state_data.get("ip") == hashed_ip_address:

            g.browser_verified = True
            return None

    reason = is_ip_malicious(ip_address)
    if not reason:
        return

    if verify_pow_response(request, difficulty = POW_DIFFICULTY):
        g.browser_verified = True

        cookies = getattr(g, "cookies", {})
        cookies["challenge"] = create_state("browser_checked", {"ip": hashed_ip_address})
        g.cookies = cookies
        return None

    beam_id = get_beam_id([get_ip_address(request), get_user_agent(request)])

    powbox_challenge, powbox_state = generate_powbox_challenge()
    return render_template(
        "browser_check", request, powbox_challenge = powbox_challenge,
        powbox_state = powbox_state, difficulty = POW_DIFFICULTY,
        beam_id = beam_id, reason = reason
    )


if ACCESS_TOKEN:
    @app.before_request
    def verify_access_wrapper() -> Optional[str]:
        """
        A wrapper function to verify access before processing each request.
        
        Uses the global `ACCESS_TOKEN` to validate the incoming request.
        
        Returns:
            Optional[str]: A object if access verification fails, 
                otherwise None to allow the request to proceed.
        """

        if request.path in ["/robots.txt"]:
            return None

        return verify_access(request, ACCESS_TOKEN)


@app.after_request
def add_cookies(response: Response) -> Response:
    """
    Adds cookies to the HTTP response if any are set during the request lifecycle.
    
    Args:
        response (Response): The HTTP response object to modify.
    
    Returns:
        Response: The modified HTTP response object with cookies added.
    """

    cookies = getattr(g, "cookies", None)
    if not isinstance(cookies, dict):
        return response

    is_secure = get_scheme(request) == "https"

    for key, value in cookies.items():
        response.set_cookie(
            key, value, max_age = ONE_YEAR_IN_SECONDS,
            secure = is_secure, httponly = True, samesite = "Strict"
        )

    return response


################
#### Routes ####
################


@app.route("/", methods = ["GET", "POST"])
def index():
    """
    Render the index page of the application.

    Returns:
        str: The rendered HTML of the "index" template.
    """

    return render_template("index", request)


@app.route("/auth", methods = ["GET", "POST"])
def auth() -> str:
    """
    Render the authentication page.

    Returns:
        str: The rendered authentication page.
    """

    return render_template("auth", request)


def render_login(user_name: Optional[str] = None,
                 password: Optional[str] = None,
                 error: Optional[Error] = None) -> str:
    powbox_challenge, powbox_state = generate_powbox_challenge()

    return render_template(
        "login", request,
        error = error, user_name = user_name, password = password,
        powbox_challenge = powbox_challenge, powbox_state = powbox_state
    )

def render_captcha(user_name: str, password: str, error: Optional[Error] = None) -> str:
    images, state = create_captcha(
        {"user_name": user_name, "password": password}
    )

    return render_template(
        "captcha", request,
        images = images, state = state, error = error
    )

def render_twofa(user_name: str, password: str, error: Optional[Error] = None) -> str:
    state = create_state(
        "twofa", {
            "user_name": user_name,
            "password": password
        }
    )

    return render_template(
        "twofa", request,
        state = state, error = error
    )


@app.get("/login")
def login() -> str:
    """
    Renders the login.html template.

    Returns:
        str: The rendered template.
    """

    return render_login()


@app.post("/login")
def posted_login() -> Union[str, Response]:
    """
    Handle the login process, including form submission, CAPTCHA verification, 
    and two-factor authentication (2FA).

    This function processes login requests and handles the following steps:
      - Validating user credentials.
      - Verifying CAPTCHA challenges if required.
      - Performing 2FA token verification if enabled.
      - Setting up a session for a successful login.

    Returns:
        Union[str, Response]: The rendered template or response
            text based on the current login state.
    """

    user_name: Optional[str] = None
    password: Optional[str] = None

    submitted = False
    is_captcha_verified = verify_pow_response(request)
    is_valid_password = False
    is_totp_verified = False

    state = request.form.get("state")
    if state:
        state_name, state_data = get_state(state, True)
        if state_name:
            user_name = state_data.get("user_name")
            password = state_data.get("password")

            submitted = True

        if not isinstance(user_name, str) or not isinstance(password, str):
            return render_login(user_name, password, error = UN_OR_PWD_NOT_RIGHT_ERROR)

        if state_name == "captcha_oneclick":
            is_valid = is_valid_captcha(
                state_data, get_clicked_images(request)
            )

            if not is_valid:
                # FIXME: Add failed attempt to ip address
                return render_captcha(user_name, password, NOT_RIGHT_ERROR)

            is_captcha_verified = True

        if state_name == "twofa":
            is_captcha_verified = True

            token = request.form.get("codes", None)
            is_totp_verified = verify_twofa(user_name, token)
            if not is_totp_verified:
                return render_twofa(user_name, password, NOT_RIGHT_ERROR)

            is_valid_password = True

    if not submitted:
        user_name = request.form.get("user_name")
        password = request.form.get("password")
        submitted = user_name is not None or password is not None

    if submitted:
        user, error = get_signin_error(user_name, password)

        if not user:
            return render_login(user_name, password, error)

        if not isinstance(user_name, str) or not isinstance(password, str):
            return render_login(user_name, password, error = UN_OR_PWD_NOT_RIGHT_ERROR)

        if not is_captcha_verified:
            return render_captcha(user_name, password)

        if not is_valid_password and not user.is_valid_password(password):
            return render_login(user_name, password, UN_OR_PWD_NOT_RIGHT_ERROR)

        if user.twofa_token and not is_totp_verified:
            return render_twofa(user_name, password)

        user_agent, ip = get_user_agent(request), get_ip_address(request)

        session = create_session(user, user_agent, ip)
        if not session:
            return render_login(user_name, password, UN_OR_PWD_NOT_RIGHT_ERROR)

        state = create_state(
            "session", {
                "session_id": session.session_id,
                "session_token": session.session_token,
                "user_name": user.user_name
            }
        )

        cookies = getattr(g, "cookies", {})
        cookies["session"] = state
        g.cookies = cookies

        return text_response(user_name)

    return render_login(user_name, password)


def render_signup(user_name: Optional[str] = None,
                  password: Optional[str] = None,
                  repeated_password: Optional[str] = None,
                  error: Optional[Error] = None) -> str:
    powbox_challenge, powbox_state = generate_powbox_challenge()

    return render_template(
        "signup", request,
        error = error, user_name = user_name,
        password = password,
        repeated_password = repeated_password,
        powbox_challenge = powbox_challenge,
        powbox_state = powbox_state
    )


@app.get("/signup")
def signup() -> str:
    """
    Renders the signup.html template.

    Returns:
        str: The rendered template.
    """

    return render_signup()


@app.post("/signup")
def posted_signup() -> str:
    return "Posted"


@app.route("/robots.txt", methods = ["GET", "POST"])
def robots():
    """
    Generates the robots.txt file to disallow all web crawlers from accessing the site.

    Returns:
        str: The contents of the robots.txt file, instructing crawlers to avoid the site.
    """

    return text_response("User-agent: *\nDisallow: /")


##############
#### Main ####
##############


class GunicornApp(BaseApplication):
    """
    Custom Gunicorn application for running Flask with programmatically defined options.
    """


    def __init__(self, application, options=None):
        self.application = application
        self.options = options or {}
        super().__init__()


    def load_config(self):
        if not self.cfg:
            return

        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }

        for key, value in config.items():
            self.cfg.set(key.lower(), value)


    def load(self):
        return self.application


def main() -> None:
    """
    Start the application server.
    """

    init_cli()

    create_test_user() # FIXME: Remove create_test_user

    host = environ.get("HOST", "127.0.0.1")
    port = environ.get("PORT", "8080")

    workers_raw = environ.get("WORKERS", "")

    workers = 16
    if isinstance(workers_raw, str) and workers_raw.isdigit():
        workers = int(workers_raw)

    cert_file_path = environ.get("CERT_FILE_PATH", None)
    if cert_file_path:
        cert_file_path = cert_file_path.replace("./", CURRENT_DIRECTORY_PATH)

    key_file_path = environ.get("KEY_FILE_PATH", None)
    if key_file_path:
        key_file_path = key_file_path.replace("./", CURRENT_DIRECTORY_PATH)

    options = {
        "bind": f"{host}:{port}",
        "workers": workers
    }

    if cert_file_path and key_file_path:
        options.update({
            "certfile": cert_file_path,
            "keyfile": key_file_path
        })

    GunicornApp(app, options).run()


if __name__ == "__main__":
    main()
