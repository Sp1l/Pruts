#!/usr/bin/env python3
"""Checks if nextcloud apps need updating using
an installed nextcloud or FreeBSD ports tree"""

try:
    from packaging.version import parse
except ModuleNotFoundError:
    print("Missing required \"packaging\" package from https://packaging.pypa.io")
    quit()

from parse_args import parse_args
from nextcloud_api import get_apps as get_api_apps

def max_version(releases):
    """Get highest version number from iterable

    Args:
        releases (iterable): version strings

    Returns:
        str: packaging.version.Version
    """
    version = parse("0")
    for release in releases:
        if parse(release["version"]) > version:
            version = parse(release["version"])
    return version

if __name__  == "__main__":

    args = parse_args()
    print(args)

    if args.portsdir is None:
        root_dir = args.nextclouddir
        from installed import get_nextcloud_version
        from installed import get_installed_apps as get_apps
    else:
        root_dir = args.portsdir
        from ports import get_nextcloud_version
        from ports import get_ports_apps as get_apps

    if args.nextcloudVersion is None:
        nextcloud_version = get_nextcloud_version(root_dir)
    else:
        nextcloud_version = args.nextcloudVersion

    all_apps = get_api_apps(nextcloud_version, args)

    # pylint: disable=invalid-name
    uptodate = str()
    for app in get_apps(root_dir):
        # Use appname when detected in port (i.e. spreed vs. talk)
        if "appname" in app:
            nextcloud_appname = app["appname"]
        else:
            nextcloud_appname = app["name"]

        if nextcloud_appname == "nextcloud-spreed-signaling":
            continue
        app_version = parse(app["version"])

        # Check Nextcloud app for this version
        if nextcloud_appname in all_apps:
            latest_version = max_version(all_apps[nextcloud_appname]["releases"])
            if latest_version > app_version:
                print(f"{nextcloud_appname}: new version {latest_version}")
            else:
                uptodate += f"{app['name']}({app['version']}) "
        else:
            if not args.quiet:
                print(f"{app['name']} not available for {nextcloud_version}")

    if not args.quiet:
        print("Up to date:", uptodate.strip(" "))
