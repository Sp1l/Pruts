"""Simple HTTP library."""

from gzip import decompress as gzip_decompress

try:
    from compression.zstd import decompress as zstd_decompress
except ImportError:
    zstd_decompress = None
from zlib import decompress as zlib_decompress
from http import HTTPStatus  # noqa: F401
from http.client import HTTPSConnection, HTTPConnection, HTTPResponse
from urllib.parse import urlparse
from sys import version_info
import logging

logger = logging.getLogger(__name__)

USER_AGENT = f"Python/HttpLib-{version_info.major}.{version_info.minor}"
TIMEOUT = 15


def request(
    url: str, headers: dict | None = None, method: str = "GET", timeout: float = TIMEOUT
) -> tuple[HTTPResponse, bytes]:
    if isinstance(url, str):
        url = urlparse(url)
    method = method.upper()
    if not headers:
        headers = {}
    headers["User-Agent"] = USER_AGENT
    headers["Accept-Encoding"] = "gzip, deflate, zstd" if zstd_decompress else "gzip, deflate"

    hostname = url.netloc.split(":")
    port = hostname[1] if len(hostname) > 1 else None
    hostname = hostname[0]

    if url.scheme == "http":
        conn = HTTPConnection(host=hostname, port=port)
    elif url.scheme == "https":
        conn = HTTPSConnection(host=hostname, port=port)

    headers["host"] = hostname
    conn.request(method, url.path, headers=headers)

    response = conn.getresponse()
    content_length = response.getheader("content-length", None)

    if content_length or response.chunked:
        response_body = response.read()
    else:
        response_body = None
    content_encoding = response.getheader("content-encoding", None)
    if content_encoding == "gzip":
        response_body = gzip_decompress(response_body)
    elif content_encoding == "zstd":
        response_body = zstd_decompress(response_body)
    elif content_encoding == "deflate":
        response_body = zlib_decompress(response_body)

    return response, response_body


def get(
    url: str, headers: dict | None = None, timeout: float = TIMEOUT
) -> tuple[HTTPResponse, bytes]:
    return request(url, headers, "GET", timeout)
