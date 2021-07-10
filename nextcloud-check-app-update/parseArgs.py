import argparse

def parseArgs():

    argparser = argparse.ArgumentParser(description='Check Nextcloud app versions against apps.nextcloud.com API')
    argparser.add_argument('--nextcloudVersion', metavar='version', type=str,
                           help='Nextcloud version to check apps for, defaults to the version in the www/nextcloud port')
    argparser.add_argument('--portsdir', metavar='portsdir', type=str)
    argparser.add_argument('--nofetch', '-n', action='store_true',
                           help='Do not fetch latest info from nextcloud API')
    argparser.add_argument('--quiet', '-q', action='store_true',
                           help='Quiet output, only apps with new versions will be listed')
    return argparser.parse_args()
