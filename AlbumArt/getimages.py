#!/usr/bin/env python3
"""Download images for artist from TheAudioDB"""

import argparse
from hashlib import sha256
from pathlib import Path
from random import random
from time import sleep

from bs4 import BeautifulSoup
import httpx

BASEURL = "https://www.theaudiodb.com"


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:126.0) Gecko/20100101 Firefox/126.0",
# pylint: disable-next=line-too-long
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Origin": "https://www.theaudiodb.com",
    "DNT": "1",
    "Referer": "https://www.theaudiodb.com/",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Priority": "u=1",
}

TYPE_TO_FILENAME = {
    "artist_logo": "logo",
    "artist_thumb": "folder",
    "wide_thumb": "background",
    "artist_clearart": "extrafanart",
    "artist_banner": "backdrop",
    "fanart_thumb": "fanart",
}

CONTENTTYPE_TO_EXT = {
    'image/jpeg': ".jpg",
    'image/png': ".png",
}

COOKIES = None

def rand_wait():
    """sleep between 0.3 and 1.3 seconds"""
    sleep(0.3+random())


def find_artist_link(artist: str) -> str:
    """Find the link to the artist's page
    Matching is done on lower-case comparison

    Args:
        artist (str): The name of the artist

    Returns:
        str: The path part of the URL to use
    """

    r = client.post(url=f"{BASEURL}/browse.php", data={"search": artist})
    HEADERS.update({"Referer": f"{BASEURL}/browse.php"})
    client.headers = HEADERS
    body = r.text

    search_res = BeautifulSoup(body, "html.parser")

    aidx = None
    artist_a = None
    for row in search_res.find("section", id="feature").find_all(class_="row"):
        n = 0
        for col in row:
            n += 1
            if not aidx and col.text == "Artist":
                aidx = n
                break
            elif aidx and aidx == n:
                # If no artist was found, we get an empty <div>
                if str(row.div) == "None":
                    continue
                # The Artist div-column can have multiple entries
                for link in row.div.find_all("a"):
                    if link.text.lower() == artist.lower():
                        artist_a = link
                        break
                # Once we have the link, we're done!
                if artist_a: break  # pylint:disable=multiple-statements
            if artist_a: break  # pylint:disable=multiple-statements
        if artist_a: break  # pylint:disable=multiple-statements

    if not artist_a:
        return None
    try:
        return artist_a["href"]
    except KeyError:
        return None

def get_images(artist_path: str) -> list:
    """Get all relevant images from an artist's page

    Args:
        artist_path (str): The path part of the URL to use

    Returns:
        list: Artist images dicts containing:
                * Filename (str): original filename
                * Type (str): Type (see TYPE_TO_FILENAME)
                * Content-Type (str): from response headers
                * Picture (bytes): the actual picture blob
    """

    # Get the html page for the artist
    r = client.get(url=f"{BASEURL}{artist_path}")
    HEADERS.update({"Referer": f"{BASEURL}{artist_path}"})
    client.headers = HEADERS
    artistbody = r.text

    # Extract the main section only
    artist_soup = BeautifulSoup(artistbody, "html.parser").find("section", id="feature")

    # Extract images from page
    artist_imgs = []
    for item, _ in TYPE_TO_FILENAME.items():
        if item == "fanart_thumb":
            continue
        # for link in artist_soup.find("img", alt=item.replace("_", " ")).find_parent().a["href"]:
        img = artist_soup.find("img", alt=item.replace("_", " "))
        if not img:
            continue
        link = img.find_parent().a["href"]
        if link:
            rand_wait()
            r = client.get(url=link)
            artist_imgs += [{
                "Filename": link.split("/")[-1],
                "Type": item,
                "Content-Type": r.headers["Content-Type"],
                "Picture": r.content,
            }]
    # Fanart is structured differently
    item = "fanart_thumb"
    img = artist_soup.find("img", alt=item.replace("_", " "))
    if not img:
        return artist_imgs
    try:
        while img.text != "Fanart":
            try:
                link = img["src"].removesuffix("/preview")
            except KeyError:
                img = img.previous_sibling
                continue
            rand_wait()
            r = client.get(url=link)
            artist_imgs += [{
                "Filename": link.split("/")[-1],
                "Type": item,
                "Content-Type": r.headers["Content-Type"],
                "Picture": r.content,
            }]
            # More thumbs can be prepended to this alt text
            img = img.previous_sibling
    except AttributeError:
        pass

    return artist_imgs

def process_artist(artist: str) -> list:
    """Process an artist's name

    Args:
        artist (str): Name of artist

    Returns:
        list: artist_imgs, see get_images
    """
    artist_page = find_artist_link(artist)
    if not artist_page:
        print(f"Artist \"{artist}\" not found")
        return None

    rand_wait()
    return get_images(artist_page)

def save_images(path: Path, artist_imgs: list):
    """Save all images to disk

    Args:
        path (Path): Artist's directory
        artist_imgs (list): see get_images
    """
    for img in artist_imgs:
        found = False
        ext = CONTENTTYPE_TO_EXT[img["Content-Type"]]
        filename = TYPE_TO_FILENAME[img["Type"]]
        filehash = sha256(img["Picture"]).digest()
        files = []
        idx = ""
        for existing in path.glob(f"{filename}*.*"):
            files += [existing.name]
            if sha256(existing.read_bytes()).digest() == filehash:
                found = True
        if found: continue  # pylint:disable=multiple-statements
        while True:
            if f"{filename}{idx}{ext}" in files:
                if idx == "":
                    idx = 1
                else:
                    idx += 1
            else:
                break
        img_file = Path(path, f"{filename}{idx}{ext}")
        files += [f"{filename}{idx}{ext}"]
        img_file.write_bytes(img["Picture"])
        # print(f"Wrote {img_file}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="""Try to get artist art from TheAudioDB.com.

Expects the directory to contain directories named after the artist.
If the artist does not match, add a file .artist_name to the directory
containing the artist name (e.g. ACDC/.artist_name containing \"AC/DC\".
Does not overwrite existing files.""")
    parser.add_argument(
        'dir',
        type=Path,
        help="Directory containing artist's directories",
        default=Path("./")
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Don't skip folders already containing a folder.jpg file"
    )

    args = parser.parse_args()

    if not args.dir.exists():
        raise ValueError(f"Directory \"{args.dir}\" does not exist")

    COOKIES = httpx.get(BASEURL).cookies

    client = httpx.Client(http2=True, headers=HEADERS, cookies=COOKIES)

    for path in [ x for x in args.dir.iterdir() if x.is_dir() ]:
        if Path(path, ".artist_name").exists():
            artist = Path(path, ".artist_name").read_text().split('\n')[0]
        else:
            artist = path.name
        if not args.force and Path(path, 'folder.jpg').exists():
            continue
        print(f"Processing artist \"{artist}\"")
        images = process_artist(artist)
        if images:
            save_images(path, images)
