from sys import argv
from os import environ
from typing import Final, Tuple
from argparse import ArgumentParser, ArgumentTypeError

try:
    from src.logger import set_quiet
except (ModuleNotFoundError, ImportError):
    from logger import set_quiet


LOGO: Final[str] =\
"""
┏━━━┓┏┓━━━━━━━┏━┓━┏┓━━━━━━━━━┏┓━
┃┏━┓┃┃┃━━━━━━━┃┃┗┓┃┃━━━━━━━━┏┛┗┓
┃┗━━┓┃┃┏┓┏┓━┏┓┃┏┓┗┛┃┏━━┓┏━━┓┗┓┏┛
┗━━┓┃┃┗┛┛┃┃━┃┃┃┃┗┓┃┃┃┏┓┃┃━━┫━┃┃━
┃┗━┛┃┃┏┓┓┃┗━┛┃┃┃━┃┃┃┃┃━┫┣━━┃━┃┗┓
┗━━━┛┗┛┗┛┗━┓┏┛┗┛━┗━┛┗━━┛┗━━┛━┗━┛
━━━━━━━━━┏━┛┃━━━━━━━━━━━━━━━━━━━
━━━━━━━━━┗━━┛━━━━━━━━━━━━━━━━━━━

Author: TN3W
GitHub: https://github.com/tn3w/SkyNest
"""


def parse_bind_address(bind_str: str) -> Tuple[str, int]:
    """
    Parse bind address string in format 'host:port'.
    
    Args:
        bind_str: String in format 'host:port'
        
    Returns:
        Tuple of (host, port)
        
    Raises:
        ArgumentTypeError if format is invalid
    """

    try:
        if ":" not in bind_str:
            return bind_str, 8080

        host, port = bind_str.split(':')
        port = int(port)
        if port < 1 or port > 65535:
            raise ArgumentTypeError("Port must be between 1 and 65535")

        return host, port

    except ValueError:
        pass

    raise ArgumentTypeError("Bind address must be in format 'host:port'")


def init_cli() -> None:
    """
    Initializes command line interface for deploying SkyNest.

    Args:
        None

    Returns:
        None
    """

    quiet = "-q" in argv or "--quiet" in argv
    set_quiet(quiet)

    if not quiet:
        print(LOGO)

    parser = ArgumentParser(
        description = (
            "Quickly deploy your own little social media."
        )
    )

    parser.add_argument(
        '-b', '--bind',
        type=parse_bind_address,
        default='127.0.0.1:8080',
        help='Address to bind to in format host:port'
    )

    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=16,
        help='Number of worker processes for Gunicorn'
    )

    parser.add_argument(
        '-e', '--cert-file',
        dest='cert_file_path',
        default=None,
        help='Path to SSL certificate file'
    )

    parser.add_argument(
        '-k', '--key-file',
        dest='key_file_path',
        default=None,
        help='Path to SSL key file'
    )

    parser.add_argument(
        '-d', '--pow-difficulty',
        type=int,
        default=5,
        help='Difficulty level for proof of work calculations'
    )

    parser.add_argument(
        '-a', '--access-token',
        default=None,
        help='Access token for development security'
    )

    parser.add_argument(
        '-l', '--default-language',
        default='en',
        help='Default application language'
    )

    parser.add_argument(
        '-r', '--required-language',
        default=None,
        help='Specific required application language'
    )

    parser.add_argument(
        '-c', '--creator',
        default=None,
        help='Creator name to display in the application'
    )

    args = parser.parse_args()

    if args.bind:
        host, port = args.bind
        environ['HOST'] = str(host)
        environ['PORT'] = str(port)

    if args.workers:
        environ['WORKERS'] = str(args.workers)

    if args.cert_file_path:
        environ['CERT_FILE_PATH'] = str(args.cert_file_path)
    if args.key_file_path:
        environ['KEY_FILE_PATH'] = str(args.key_file_path)

    if args.pow_difficulty:
        environ['POW_DIFFICULTY'] = str(args.pow_difficulty)

    if args.access_token:
        environ['ACCESS_TOKEN'] = str(args.access_token)

    if args.default_language:
        environ['DEFAULT_LANGUAGE'] = str(args.default_language)
    if args.required_language:
        environ['REQUIRED_LANGUAGE'] = str(args.required_language)

    if args.creator:
        environ['CREATOR'] = str(args.creator)


if __name__ == "__main__":
    init_cli()
