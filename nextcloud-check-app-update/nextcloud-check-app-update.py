#!/usr/bin/env python3

try:
    from packaging.version import parse
except:
    print('Missing required "packaging" package from https://packaging.pypa.io')
    quit()

from pathlib import Path

from parseArgs import parseArgs
from nextcloudAPI import getApps

def maxVersion(releases):
    version = parse('0')
    for release in releases:
        if parse(release['version']) > version:
            version = parse(release['version'])
    return version

if __name__  == '__main__':

    args = parseArgs()

    if args.portsdir is None:
        DIR = args.nextclouddir
        from installed import getNextcloudVersion, getPorts
    else:
        DIR = args.portsdir
        from ports import getNextcloudVersion, getPorts

    if args.nextcloudVersion is None:
        nextcloudVersion = getNextcloudVersion(DIR)
    else:
        nextcloudVersion = args.nextcloudVersion

    ports = getPorts(DIR)

    apps = getApps(nextcloudVersion, args)

    uptodate = ''
    for port in ports:
        portName = port['name']
        if portName == 'nextcloud-spreed-signaling': continue
        portVersion = parse(port['version'])

        # Use appname when detected in port (i.e. spreed vs. talk)
        if 'appname' in port:
            appName = port['appname']
        else:
            appName = port['name']

        # Check Nextcloud app for this version
        if appName in apps:
            appVersion = maxVersion(apps[appName]['releases'])
            if appVersion > portVersion:
                print(f'{portName} new version {appVersion}')
            else:
                uptodate += f'{portName}({port["version"]}) '
        else:
            if not args.quiet:
                print(f'{portName} not available for {nextcloudVersion}')

    if not args.quiet:
        print('Up to date:', uptodate.strip(' '))
   
