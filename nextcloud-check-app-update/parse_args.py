"""Arguments parser for nextcloud-check-app-update"""

import argparse
from pathlib import Path

def parse_args():
    """Arguments parser for nextcloud-check-app-update

    Returns:
        argparse.Namespace: Arguments
    """

    argparser = argparse.ArgumentParser(
        description="Check Nextcloud and Apps for new versions"
    )

    argparser.add_argument("--nextcloudVersion", metavar="VERSION",
        help="Nextcloud version to check apps for " 
        "(default: uses version from Nextcloud or Ports dir)"
    )

    dirgroup = argparser.add_mutually_exclusive_group(required=True)
    dirgroup.add_argument("--portsdir", type=Path, metavar="DIRECTORY",
        help="Path to the FreeBSD ports directory root"
    )
    dirgroup.add_argument("--nextclouddir", type=Path, metavar="DIRECTORY",
        help="Path to the Nextcloud installation root"
    )

    fetchgroup = argparser.add_mutually_exclusive_group()
    fetchgroup.add_argument("--fetch", "-f", action="store_true",
        help="Force fetching latest info from nextcloud API"
    )
    fetchgroup.add_argument("--nofetch", "-n", action="store_true",
        help="Do not fetch latest info from nextcloud API"
    )

    verbositygroup = argparser.add_argument_group(
        "Verbosity (default: info)"
    ).add_mutually_exclusive_group()
    verbositygroup.add_argument("--quiet", "-q", action="store_true",
        help="Quiet output, only warnings, errors and apps with new versions will be listed"
    )
    verbositygroup.add_argument("--verbose", "-v", action="store_true",
        help="Verbose (debug) output")

    scopegroup = argparser.add_argument_group("Check core, apps or both (default: both)")
    scopegroup.add_argument("--core", action="store_true",
        help="Check updates for Nextcloud core only.")
    scopegroup.add_argument("--apps", action="store_true",
        help="Check updates for apps only.")

    args = argparser.parse_args()

    if not args.core and not args.apps:
        args.core = True
        args.apps = True

    if not args.fetch and not args.nofetch:
        fetch = None
    elif args.fetch:
        fetch = True
    else:
        fetch = False

    args.fetch = fetch
    del args.nofetch

    return args
