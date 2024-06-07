# README

This script attempts to find pictures for an artist that are usable in
[Jellyfin](https://jellyfin.org/). These images are used in the "Artists"
tab of your Jellyfin music library.
See the
[Music images](https://jellyfin.org/docs/general/server/media/music/)
page to learn more.

The script expects a directory containing directories of artists' names.
Like:

```txt  
Pop
├── Elvis Presley
├── Lady Gaga
└── etc.
```

Run the script with `getimages.py ./Pop`.

If the artist's name differs from the directory's name, you can add an
`.artist_name` file containing the name that is in TheAudioDB.

```sh
Pop
└── ACDC
    └── .artist_name

$ cat ./Pop/ACDC/.artist_name
AC/DC
```
