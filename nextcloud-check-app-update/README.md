# nextcloud-check-app-updates

Script to check if apps in your Nextcloud application have updates.

Checks either a FreeBSD ports tree or an installed Nextcloud instance against
the most recent list of apps retrieved via the Nextcloud Apps API.

## Usage

```
usage: nextcloud-check-app-update.py [-h] [--nextcloudVersion version] (--portsdir  | --nextclouddir ) [--nofetch] [--quiet]

Check Nextcloud app versions against apps.nextcloud.com API

optional arguments:
  -h, --help            show this help message and exit
  --nextcloudVersion VERSION
                        Nextcloud version to check apps for, defaults to the version in the www/nextcloud port
  --portsdir DIRECTORY  Path to the FreeBSD ports directory root
  --nextclouddir DIRECTORY
                        Path to the Nextcloud installation root
  --nofetch, -n         Do not fetch latest info from nextcloud API
  --quiet, -q           Quiet output, only apps with new versions will be listed
```

## FreeBSD ports

The script was initially created for my task as maintainer of Nextcloud ports
in FreeBSD. Hence the option to check against a FreeBSD ports tree.
The current versions in ports are extracted from the `Makefile`.

The same principle applies to an installed Nextcloud version. The app id and
current version is extracted from the App's `appinfo\info.xml`.
The FreeBSD Nextcloud port stores packaged apps in `apps-pkg` rather than in
`apps`. This allows separation between Apps installed from FreeBSD packages
and apps downloaded from Nextcloud's App portal.
The script checks `apps\*` to acoomodate for this multiple apps dir feature.
