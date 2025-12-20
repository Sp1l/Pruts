"""Extract Nextcloud apps information from FreeBSD ports tree"""

import logging
import re

from pathlib import Path

logger = logging.getLogger(__name__)

def get_ports_nextcloud_version(ports_dir: Path) -> dict:
    """Extract Nextcloud version from installation

    Args:
        ports_dir (Path): FreeBSD PORTSDIR root

    Returns:
        str: Version number
    """
    nextcloud_makefile = ports_dir / "www/nextcloud/Makefile"

    nextcloud_makefile = nextcloud_makefile.read_text(encoding="utf-8")
    for line in nextcloud_makefile.splitlines():
        if re.match("^PORTVERSION=",line):
            return {"VersionString": line.split("\t")[1]}

def clean_distname(distname: str) -> str:
    """Remove unwanted elements from a string

    Args:
        distname (str): String to remove Makefile vars from

    Returns:
        str: Cleaned string
    """
    for remove in ["PORTNAME", "PORTVERSION", "DISTVERSION", "DISTVERSIONPREFIX"]:
        distname = distname.replace("${" + remove + "}","")
    return distname.strip("-_")

def get_ports_apps(ports_dir: Path) -> list:
    """Get nextcloud apps from a FreeBSD ports tree

    Args:
        ports_dir (Path): FreeBSD PORTSDIR root

    Returns:
        list: {"name", "version", "version_prefix", "appname"}
    """
    ports = list()
    for path in list(ports_dir.glob("*/nextcloud-*/Makefile")):
        makefile = path.read_text(encoding="utf-8")
        port = dict()
        distname = None
        for line in makefile.splitlines():
            if re.match("^PORTNAME=",line):
                port["name"] = line.split("=")[1].strip()
            if re.match("^(PORT|DIST)VERSION=",line):
                port["version"] = line.split("=")[1].strip()
            if re.match("^DISTVERSIONPREFIX=",line):
                port["versionprefix"] = line.split("=")[1].strip()
            if re.match("^DISTNAME=",line):
                distname = clean_distname(line.split("=")[1].strip())
                if distname != "":
                    port["appname"] = distname
        if port["name"] == "nextcloud-spreed-signaling":
            # Not a Nextcloud PHP App
            continue
        port["portdir"] = path.parent
        ports.append(port)
    return ports
