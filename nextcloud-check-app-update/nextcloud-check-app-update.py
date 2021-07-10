#!/usr/bin/env python3

import os
import re
import json
try:
    import requests
except:
    print('Missing required "requests" package from https://docs.python-requests.org')
    quit()

try:
    from packaging.version import parse
except:
    print('Missing required "packaging" package from https://packaging.pypa.io')
    quit()
from pathlib import Path, PurePath

def getNextcloudVersion():
    p = Path(PORTSDIR + '/www/nextcloud/Makefile')
    Makefile = p.read_text()
    for line in Makefile.splitlines():
        if re.match('^PORTVERSION=',line):
             return line.split('\t')[1]

def readETag(version):
    p = Path(f'./apps_{version}.etag')
    try:
        for line in p.read_text().splitlines():
    	    etag = line
        return etag
    except:
        return None

def writeETag(version, etag):
    p = Path(f'./apps_{version}.etag')
    p.write_text(etag)

def readJson(version):
    p = Path(f'./apps_{version}.json')
    payload = p.read_text()
    return json.loads(payload)

def writeJson(version, payload):
    p = Path(f'./apps_{version}.json')
    p.write_text(json.dumps(payload, indent=3))

def getApps(version):
    url = f'https://apps.nextcloud.com/api/v1/platform/{version}/apps.json'
    etag = readETag(version)
    headers = dict()
    if not etag is None:
        headers.update({'If-None-Match': etag})
    req = requests.get(url, headers=headers)
    
    if req.status_code == 304:
        payload = readJson(version)
    else:
        etag = req.headers['ETag'].strip('W/')
        print(f'New apps.json for {version}:', etag)
        payload = req.json()
        writeETag(version, etag)
        writeJson(version, payload)

    apps = dict()
    for app in payload:
        apps.update({app["id"]: app})
    return apps

def maxVersion(releases):
    version = parse('0')
    for release in releases:
        if parse(release['version']) > version:
            version = parse(release['version'])
    return version

def cleanDistname(distname):
    for remove in ['PORTNAME','PORTVERSION','DISTVERSION']:
        distname = distname.replace('${' + remove + '}','')
    return distname.strip('-_')

def getPorts():
    p = Path(PORTSDIR)
    ports = list()
    for path in list(p.glob('*/nextcloud-*/Makefile')):
        Makefile = path.read_text()
        port = dict()
        for line in Makefile.splitlines():
            if re.match('^PORTNAME=',line):
                port['name'] = line.split('\t')[1]
            if re.match('^(PORT|DIST)VERSION=',line):
                port['version'] = line.split('\t')[1]
            if re.match('^DISTVERSIONPREFIX=',line):
                port['versionprefix'] = line.split('\t')[1]
            if re.match('^DISTNAME=',line):
                port['appname'] = cleanDistname(line.split('\t')[1])
                if port['appname'] == '': del port['appname']
        port['portdir'] = os.sep.join(str(path).split(os.sep)[:-1])
        ports.append(port)
    return ports

PORTSDIR = "/jails/porting/usr/ports"

nextcloudVersion = getNextcloudVersion()
#nextcloudVersion = '22.0.0'

ports = getPorts()

apps = getApps(nextcloudVersion)
p = Path('./apps.json')
p.write_text(json.dumps(apps, indent=4))

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
        print(f'{portName} not available for {nextcloudVersion}')

print('Up to date:', uptodate.strip(' '))
   
