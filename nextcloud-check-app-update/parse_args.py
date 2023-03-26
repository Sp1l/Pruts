"""Arguments parser for nextcloud-check-app-update"""

import argparse

def parse_args():
    """Arguments parser for nextcloud-check-app-update

    Returns:
        argparse.Namespace: Arguments
    """

    argparser = argparse.ArgumentParser(
        description="Check Nextcloud app versions against apps.nextcloud.com API"
    )

    argparser.add_argument("--nextcloudVersion", metavar="VERSION", type=str,
        help="Nextcloud version to check apps for, " +
        "defaults to the version in the www/nextcloud port"
    )

    dirgroup = argparser.add_mutually_exclusive_group(required=True)
    dirgroup.add_argument("--portsdir", type=str, metavar="DIRECTORY",
        help="Path to the FreeBSD ports directory root"
    )
    dirgroup.add_argument("--nextclouddir", type=str, metavar="DIRECTORY",
        help="Path to the Nextcloud installation root"
    )

    fetchgroup = argparser.add_mutually_exclusive_group()
    fetchgroup.add_argument("--fetch", "-f", action="store_true",
        help="Force fetching latest info from nextcloud API"
    )
    fetchgroup.add_argument("--nofetch", "-n", action="store_true",
        help="Do not fetch latest info from nextcloud API"
    )

    argparser.add_argument("--quiet", "-q", action="store_true",
        help="Quiet output, only apps with new versions will be listed"
    )

    return argparser.parse_args()
