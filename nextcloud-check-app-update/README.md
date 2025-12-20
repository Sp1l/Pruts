# nextcloud-check-app-updates

Script to check if apps in your Nextcloud and/or Nextcloud Apps have updates.

Checks either a FreeBSD ports tree or an installed Nextcloud instance against
the most recent list of apps retrieved via the Nextcloud Apps API.

## Usage

```txt
usage: nextcloud-updatecheck.py [-h] [--nextcloudVersion VERSION] (--portsdir DIRECTORY | --nextclouddir DIRECTORY) [--fetch | --nofetch] [--quiet | --verbose] [--core] [--apps]

Check Nextcloud and Apps for new versions

options:
  -h, --help            show this help message and exit
  --nextcloudVersion VERSION
                        Nextcloud version to check apps for (default: uses version from nextclouddir or portsdir)
  --portsdir DIRECTORY  Path to the FreeBSD ports directory root
  --nextclouddir DIRECTORY
                        Path to the Nextcloud installation root
  --fetch, -f           Force fetching latest info from nextcloud API
  --nofetch, -n         Do not fetch latest info from nextcloud API

Verbosity (default: info):
  --quiet, -q           Quiet output, only warnings, errors and apps with new versions will be listed
  --verbose, -v         Verbose (debug) output

Check core, apps or both (default: both):
  --core                Check updates for Nextcloud core only.
  --apps                Check updates for apps only.
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
