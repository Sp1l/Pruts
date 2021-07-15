#!/usr/bin/env python3

import json
try:
    import requests
except:
    print('Missing required "requests" package from https://docs.python-requests.org')
    quit()

from pathlib import Path

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

def getApps(version, args):
    if not args.nofetch:
        url = f'https://apps.nextcloud.com/api/v1/platform/{version}/apps.json'
        etag = readETag(version)
        headers = dict()

        if not (etag is None or args.fetch):
            headers.update({'If-None-Match': etag})
        req = requests.get(url, headers=headers)
    
        if req.status_code == 304:
            payload = readJson(version)
            status = 'Cached'
        else:
            etag = req.headers['ETag'].strip('W/')
            status = 'New'
            payload = req.json()
            writeETag(version, etag)
            writeJson(version, payload)
    else:
        etag = readETag(version)
        payload = readJson(version)
        status = 'Loaded'

    if not args.quiet:
        print(f'{status} apps.json for Nextcloud {version}:', etag)

    apps = dict()
    for app in payload:
        apps.update({app["id"]: app})
    return apps
