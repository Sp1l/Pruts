import json
import re

import xml.etree.ElementTree as ET
from pathlib import Path

def getNextcloudVersion(NEXTCLOUDDIR):
    p = Path(NEXTCLOUDDIR + '/version.php')
    versionphp = p.read_text()
    for line in versionphp.splitlines():
        if re.match('^\$OC_VersionString',line):
             return line.split('=')[1].strip(" ';")

def getShippedApps(NEXTCLOUDDIR):
    with open(NEXTCLOUDDIR + '/core/shipped.json') as file:
        shipped = json.load(file)
    return shipped['shippedApps']

def getPorts(NEXTCLOUDDIR):
    p = Path(NEXTCLOUDDIR)
    shippedApps = getShippedApps(NEXTCLOUDDIR)
    ports = list()
    for path in list(p.glob('apps*/*/appinfo/info.xml')):
        port = dict()
        tree = ET.parse(path)
        root = tree.getroot()
        port['name'] = root.find('id').text
        port['version'] = root.find('version').text
        if port['name'] not in shippedApps:
            ports.append(port)
    return ports

if __name__ == '__main__':

#    print(getNextcloudVersion('/jails/nextcloud/usr/local/www/nextcloud') )
    print(getPorts('/jails/nextcloud/usr/local/www/nextcloud'))
