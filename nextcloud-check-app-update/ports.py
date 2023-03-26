"""Extract Nextcloud apps information from FreeBSD ports tree"""
import os
import re

from pathlib import Path

def get_nextcloud_version(ports_dir):
    """Extract Nextcloud version from installation

    Args:
        ports_dir (str): FreeBSD PORTSDIR root

    Returns:
        str: Version number
    """
    nextcloud_makefile = Path(ports_dir + "/www/nextcloud/Makefile")
    nextcloud_makefile = nextcloud_makefile.read_text(encoding="utf-8")
    for line in nextcloud_makefile.splitlines():
        if re.match("^PORTVERSION=",line):
            return line.split("\t")[1]

def clean_distname(distname):
    """Remove unwanted elements from a string

    Args:
        distname (str): String to remove Makefile vars from

    Returns:
        str: Cleaned string
    """
    for remove in ["PORTNAME", "PORTVERSION", "DISTVERSION", "DISTVERSIONPREFIX"]:
        distname = distname.replace("${" + remove + "}","")
    return distname.strip("-_")

def get_ports_apps(ports_dir: str) -> list:
    """Get nextcloud apps from a FreeBSD ports tree

    Args:
        PORTSDIR (_type_): _description_

    Returns:
        _type_: _description_
    """
    ports_dir = Path(ports_dir)
    ports = list()
    for path in list(ports_dir.glob("*/nextcloud-*/Makefile")):
        makefile = path.read_text(encoding="utf-8")
        port = dict()
        distname = None
        for line in makefile.splitlines():
            if re.match("^PORTNAME=",line):
                port["name"] = line.split("\t")[1]
            if re.match("^(PORT|DIST)VERSION=",line):
                port["version"] = line.split("\t")[1]
            if re.match("^DISTVERSIONPREFIX=",line):
                port["versionprefix"] = line.split("\t")[1]
            if re.match("^DISTNAME=",line):
                distname = clean_distname(line.split("\t")[1])
                if distname != "":
                    port["appname"] = distname
        port["portdir"] = os.sep.join(str(path).split(os.sep)[:-1])
        ports.append(port)
    return ports
