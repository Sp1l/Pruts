"""Get latest apps from Nextcloud API"""

import logging
from urllib.parse import urlparse, ParseResult
import json

from pathlib import Path
from packaging.version import Version

from httplib import HTTPStatus
import httplib

logger = logging.getLogger(__name__)

NEXTCLOUD_APIURL = "https://apps.nextcloud.com/api/v1"
NEXTCLOUD_DOWNLOADURL = "https://download.nextcloud.com/server/releases/"
NEXTCLOUD_GITHUBURL = "https://api.github.com/repos/nextcloud-releases/server/releases"
TMP_PATH = Path("/tmp/nextcloud-updatecheck")

if not TMP_PATH.exists():
    TMP_PATH.mkdir(mode=500)


def path_from_url(url: str) -> Path:
    parsed: ParseResult = urlparse(url)
    filename = (
        f"{parsed.scheme}:{parsed.netloc}{parsed.path}".replace("_", "__")
        .replace("/", "_")
        .replace(":", "_")
    )
    return TMP_PATH / filename


def read_etag(url: str) -> str | None:
    """Read persisted etag from disk.

    Args:
        resource(str): URL, Prefix or path

    Returns:
        str: the ETag of the json file on disk
        None: if an error occured reading the file
    """
    file = path_from_url(f"{url}.etag")
    etag = ""  # Makes empty file work
    try:
        for line in file.read_text(encoding="utf-8").splitlines():
            etag = line
    except OSError:
        return None
    return etag


def write_etag(url: str, etag: str) -> None:
    """Persist etag to disk

    Args:
        resource(str): Prefix or path
        etag (str): ETag from Nextcloud HTTP headers
    """
    file = path_from_url(f"{url}.etag")
    file.write_text(etag, encoding="utf-8")


def read_file(url: str) -> dict | str | None:
    """Read persisted file/json from disk

    Args:
        url (str): url we cached for

    Returns:
        dict|str|None:
            None if file does not exist
            JSON dictionary if url ends with ".json"
            Contents of file
    """
    file = path_from_url(url)
    if not file.exists():
        return None
    contents = file.read_text(encoding="utf-8")
    if file.suffix == ".json":
        logger.debug("read_file: Returning JSON as dict for %s", file)
        return json.loads(contents)
    logger.debug("read_file: Returning contents for %s", file)
    return contents


def write_file(url: str, contents: dict | str) -> None:
    """Persist JSON payload to disk

    Args:
        url (str): URL this resource was downloaded from.
        payload (dict): JSON dictionary
    """
    file = path_from_url(url)
    if file.suffix == ".json" or isinstance(contents, (dict, list)):
        logger.debug("write_file: Writing JSON to %s", file)
        file.write_text(json.dumps(contents, indent=2), encoding="utf-8")
    else:
        logger.debug("write_file: Writing contents to %s", file)
        file.write_text(contents, encoding="utf-8")


def get_url(url: str, fetch: bool | None) -> dict | str:
    """Get contents from url, cached or fresh.

    Args:
        url (str): URL to update
        fetch (bool|None): True = Force, False = No, None = Check

    Returns:
        dict|str: dict if json, str otherwise
        str: etag for URL
    """
    etag = read_etag(url)
    payload = read_file(url)
    status = "Cached"

    # If fetch is not forced, and we have an etag, use it
    headers = {"If-None-Match": etag} if (etag and not fetch) else {}

    if fetch is False and not (etag and payload):
        err_msg = f"Can't use --nofetch when payload is not cached for {url}"
        logger.error("get_url: %s", err_msg)
        raise AttributeError(err_msg)

    if fetch is not False:
        resp, body = httplib.get(url, headers)

        if resp.status == HTTPStatus.NOT_MODIFIED:
            status = "Cached"
        else:
            status = "New"
            etag = resp.getheader("etag", "")
            if resp.msg.get_content_type() == "application/json" or url.endswith(".json"):
                payload = json.loads(body)
            elif isinstance(body, bytes):
                payload = body.decode()
            write_etag(url, etag)
            write_file(url, payload)

    return status, payload, etag


def get_nextcloud_apps(version: str, fetch: bool | None) -> dict:
    """Get latest apps versions from Nextcloud API.

    Args:
        version (str): Nextcloud version string
        args (argparse.Namespace): Argument parser

    Returns:
        dict: Dictionary of apps from Nextcloud API
    """
    url = f"{NEXTCLOUD_APIURL}/platform/{version}/apps.json"
    status, payload, etag = get_url(url, fetch)
    if status == "Cached":
        logger.debug("get_nextcloud_apps: Using cached apps.json for Nextcloud %s", version)
    else:
        logger.debug("get_nextcloud_apps: New apps.json for Nextcloud %s", version)

    # Process content
    apps = {}
    for app in payload:
        releases = [release["version"] for release in app["releases"]]
        apps.update({app["id"]: {"releases": releases}})
    logger.debug("get_nextcloud_apps: Found %s apps in apps.json", len(apps))
    return apps


def get_nextcloud_core(version: str, fetch: bool | None) -> tuple[str, str]:
    """Get patch and latest version of core.

    Args:
        version (str): Currently install version
        args (argparse.Namespace): Argument parser

    Returns:
        tuple[str, str]: Latest patch for version and latest version
    """
    url = NEXTCLOUD_GITHUBURL
    status, payload, etag = get_url(url, fetch)
    if status == "Cached":
        logger.debug("get_nextcloud_core: Using cached Nextcloud github releases")
        payload = json.loads(payload)
    else:
        logger.debug("get_nextcloud_core: New Nextcloud github releases")

    # Process content
    latest = patch = Version(version)
    for v in [line.get("tag_name") for line in payload]:
        v = Version(v)
        if not v.is_prerelease and v > latest:
            latest = v
            if v.major == patch.major and v.minor == patch.minor:
                patch = v
                logger.info("get_nextcloud_core: New patch version: %s", v)
            else:
                logger.info("get_nextcloud_core: New version: %s", v)
        else:
            logger.debug("get_nextcloud_core: Version %s not newer than %s", v, latest)

    return str(patch), str(latest)
