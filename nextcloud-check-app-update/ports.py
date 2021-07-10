#!/usr/bin/env python3

import os
import re

from pathlib import Path, PurePath

def getNextcloudVersion(PORTSDIR):
    p = Path(PORTSDIR + '/www/nextcloud/Makefile')
    Makefile = p.read_text()
    for line in Makefile.splitlines():
        if re.match('^PORTVERSION=',line):
             return line.split('\t')[1]

def cleanDistname(distname):
    for remove in ['PORTNAME','PORTVERSION','DISTVERSION']:
        distname = distname.replace('${' + remove + '}','')
    return distname.strip('-_')

def getPorts(PORTSDIR):
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
