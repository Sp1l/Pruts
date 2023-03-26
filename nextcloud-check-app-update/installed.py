"""Extract apps information from a Nextcloud install"""

import json
import re

import xml.etree.ElementTree as ET
from pathlib import Path

def get_nextcloud_version(nextcloud_dir):
    """Extract Nextcloud version from installation

    Args:
        nextcloud_dir (str): Root directory of Nextcloud installation

    Returns:
        str: Version number
    """
    version_php = Path(nextcloud_dir + "/version.php")
    version_php = version_php.read_text(encoding="utf-8")
    for line in version_php.splitlines():
        if re.match(r"^\$OC_VersionString", line):
            return line.split("=")[1].strip(" ';")

def get_shipped_apps(nextcloud_dir):
    """Extract apps bundled with the base Nextcloud installation

    Args:
        nextcloud_dir (str): Root directory of Nextcloud installation

    Returns:
        list: List of bundled apps
    """
    shipped_json = Path(nextcloud_dir + "/core/shipped.json")
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
    return ports

if __name__ == "__main__":

#    print(getNextcloudVersion("/jails/nextcloud/usr/local/www/nextcloud") )
    print(get_installed_apps("/jails/nextcloud/usr/local/www/nextcloud"))
