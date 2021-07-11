import argparse

def parseArgs():

    argparser = argparse.ArgumentParser(description='Check Nextcloud app versions against apps.nextcloud.com API')
    argparser.add_argument('--nextcloudVersion', metavar='VERSION', type=str,
                           help='Nextcloud version to check apps for, defaults to the version in the www/nextcloud port')
    group = argparser.add_mutually_exclusive_group(required=True)
    group.add_argument('--portsdir', type=str, metavar='DIRECTORY', 
                       help='Path to the FreeBSD ports directory root')
    group.add_argument('--nextclouddir', type=str, metavar='DIRECTORY',
                       help='Path to the Nextcloud installation root')
    argparser.add_argument('--nofetch', '-n', action='store_true',
                           help='Do not fetch latest info from nextcloud API')
    argparser.add_argument('--quiet', '-q', action='store_true',
                           help='Quiet output, only apps with new versions will be listed')
    return argparser.parse_args()
