"""Get latest apps from Nextcloud API"""

import json

try:
    import requests
except ModuleNotFoundError:
    print("Missing required \"requests\" package from https://docs.python-requests.org")
    quit()

from pathlib import Path

NEXTCLOUD_API_URL = "https://apps.nextcloud.com/api/v1"
TMP_PATH = Path("/tmp")

def read_etag(version: str) -> str:
    """Read persisted etag from disk

    Args:
        version (str): Nextcloud version string

    Returns:
        str: the ETag of the json file on disk
    """
    apps_etag = TMP_PATH / f"apps_{version}.etag"
    try:
        for line in apps_etag.read_text(encoding="utf-8").splitlines():
            etag = line
        return etag
    except OSError:
        return None

def write_etag(version: str, etag: str) -> None:
    """Persist etag to disk

    Args:
        version (str): Nextcloud version string
        etag (str): ETag from Nextcloud HTTP headers
    """
    apps_etag = TMP_PATH / f"apps_{version}.etag"
    apps_etag.write_text(etag, encoding="utf-8")

def read_json(version: str) -> dict:
    """Read persisted json from disk

    Args:
        version (str): Nextcloud version string

    Returns:
        dict: JSON dictionary
    """
    apps_json = TMP_PATH / f"apps_{version}.json"
    payload = apps_json.read_text(encoding="utf-8")
    return json.loads(payload)

def write_json(version: str, payload: dict) -> None:
    """Persist JSON payload to disk

    Args:
        version (str): Nextcloud version string
        payload (dict): JSON dictionary
    """
    apps_json = TMP_PATH / "apps_{version}.json"
    apps_json.write_text(json.dumps(payload, indent=3), encoding="utf-8")

def get_apps(version: str, args) -> dict:
    """Get latest apps versions from Nextcloud API

    Args:
        version (str): Nextcloud version string
        args (argparse.Namespace): Argument parser

    Returns:
        dict: Dictionary of apps from Nextcloud API
    """
    if not args.nofetch:
        url = f'{NEXTCLOUD_API_URL}/platform/{version}/apps.json'
        etag = read_etag(version)
        headers = dict()

        if not (etag is None or args.fetch):
            headers.update({'If-None-Match': etag})
        req = requests.get(url, headers=headers, timeout=15)

        if req.status_code == 304:
            payload = read_json(version)
            status = 'Cached'
        else:
            etag = req.headers.get('etag').strip('W/')
            status = 'New'
            payload = req.json()
            write_etag(version, etag)
            write_json(version, payload)
    else:
        etag = read_etag(version)
        payload = read_json(version)
        status = 'Loaded'

    if not args.quiet: 
        print(f'{status} apps.json for Nextcloud {version}:', etag)

    apps = dict()
    for app in payload:
        latest = None
        releases = []
        for release in app["releases"]:
            releases.append(release["version"])
        apps.update({app["id"]: {"releases": releases}})
    return apps
