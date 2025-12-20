from packaging.version import Version

from html.parser import HTMLParser


def max_version(releases: list) -> Version:
    """Get highest version number from iterable

    Args:
        releases (iterable): version strings

    Returns:
        str: packaging.version.Version
    """
    latest = Version("0")
    for release in releases:
        version = Version(release)
        if not version.is_prerelease and version > latest:
            latest = version
    return latest


class ModDirParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.versions = []

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        for attr in attrs:
            if (
                attr[0] == "href"
                and attr[1].startswith("nextcloud-")
                and attr[1].endswith(".tar.bz2")
            ):
                version_str = attr[1].removeprefix("nextcloud-").removesuffix(".tar.bz2")
                self.versions.append(Version(version_str))


def parse_moddirhtml(index_html) -> list[Version]:
    parser = ModDirParser()
    parser.feed(index_html)
    return parser.versions
