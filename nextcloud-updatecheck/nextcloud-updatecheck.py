#!/usr/bin/env python3
"""Checks if nextcloud apps need updating using
an installed nextcloud or FreeBSD ports tree"""

try:
    from packaging.version import parse
except ModuleNotFoundError:
    print('Missing required "packaging" package from https://packaging.pypa.io')
    quit()

import logging
from parse_args import parse_args
from installed import get_installed_nextcloud_version, get_installed_apps
from ports import get_ports_nextcloud_version, get_ports_apps
from nextcloud_api import get_nextcloud_apps as get_new_apps, get_nextcloud_core
from utils import max_version

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    args = parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.WARNING, format="%(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.portsdir:
        root_dir = args.portsdir
        get_nextcloud_version = get_ports_nextcloud_version
        get_nextcloud_apps = get_ports_apps
    else:
        root_dir = args.nextclouddir
        get_nextcloud_version = get_installed_nextcloud_version
        get_nextcloud_apps = get_installed_apps

    if args.nextcloudVersion:
        nextcloud_version = args.nextcloudVersion
    else:
        nextcloud_version = get_nextcloud_version(root_dir).get("VersionString")

    if args.core:
        logger.debug("Checking for new Nextcloud version")
        patch, latest = get_nextcloud_core(nextcloud_version, args.fetch)

        if nextcloud_version != patch:
            logger.warning("Nextcloud patch update from %s to %s", nextcloud_version, patch)
        if patch != latest:
            logger.info("Nextcloud upgrade from %s to %s", nextcloud_version, latest)

    if args.apps:
        apps = get_nextcloud_apps(root_dir)
        logger.debug("check_apps: Checking Nextcloud App updates %s", nextcloud_version)
        nextcloud_apps = get_new_apps(nextcloud_version, args.fetch)

        uptodate = []
        for app in apps:
            # Use appname when detected in port (i.e. spreed vs. talk)
            nextcloud_app = nextcloud_apps.get(
                app.get("appname", "not-an-app"),
                nextcloud_apps.get(app["name"]),
            )
            if not nextcloud_app:
                logger.warning(
                    "App '%s': not available for %s", app["name"], nextcloud_version
                )
                continue

            app_version = parse(app["version"])

            # Check Nextcloud app for this version
            #        if nextcloud_appname in all_app:
            latest_version = max_version(nextcloud_app["releases"])
            if latest_version > app_version:
                logger.warning("App '%s': new version %s", app["name"], latest_version)
            else:
                logger.debug(
                    "check_apps: App '%s': version %s is up to date", app["name"], app["version"]
                )
                uptodate.append(f"{app['name']}({app['version']})")

        logger.debug("check_apps: Up to date: %s", " ".join(uptodate))
