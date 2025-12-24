"""Extract apps information from a Nextcloud install"""

import json
import logging

import xml.etree.ElementTree as ET
from pathlib import Path

logger = logging.getLogger(__name__)

def get_installed_nextcloud_version(nextcloud_dir: Path) -> dict:
    """Extract Nextcloud version from installation

    Args:
        nextcloud_dir (str): Root directory of Nextcloud installation

    Returns:
        str: Version number
    """
    version = {}
    with (nextcloud_dir / "version.php").open(encoding="utf-8") as f:
        for line in f:
            line = line.removeprefix("$OC_")
            parts = line.split("=")
            if len(parts) == 1:
                continue
            key = parts[0].strip(" ';\n")
            value = parts[1].strip(" ';\n")
            if key == "VersionCanBeUpgradedFrom":
                continue
            version[key] = value
    logger.debug("get_installed_nextcloud_version: Extracted version %s from %s",
                 version, nextcloud_dir / "version.php")
    return version

def get_shipped_apps(nextcloud_dir):
    """Extract apps bundled with the base Nextcloud installation

    Args:
        nextcloud_dir (str): Root directory of Nextcloud installation

    Returns:
        list: List of bundled apps
    """
    shipped_json = nextcloud_dir / "core/shipped.json"
    with open(shipped_json, encoding="utf-8") as file:
        shipped = json.load(file)
    return shipped["shippedApps"]

def get_installed_apps(nextcloud_dir):
    """Extract installed apps from the Nextcloud installation

    Args:
        nextcloud_dir (str): Root directory of Nextcloud installation

    Returns:
        list: list of installed apps
    """
    path = Path(nextcloud_dir)
    shipped_apps = get_shipped_apps(nextcloud_dir)
    ports = list()
    for path in list(path.glob("apps*/*/appinfo/info.xml")):
        port = dict()
        tree = ET.parse(path)
        root = tree.getroot()
        port["name"] = root.find("id").text
        port["version"] = root.find("version").text
        if port["name"] not in shipped_apps:
            ports.append(port)
    logger.debug("get_installed_apps: Extracted apps %s from %s",
                 ports, nextcloud_dir)
    return ports

