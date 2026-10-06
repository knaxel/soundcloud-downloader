# SoundCloud Likes Downloader

Exports and downloads the tracks you've liked on SoundCloud, using the official API.

## Setup

```sh
pip install -r requirements.txt
```

Optional: install [ffmpeg](https://ffmpeg.org/) so tracks that only have AAC/Opus streams can be downloaded too.

### 1. Register a SoundCloud app (one time)

1. Go to <https://soundcloud.com/you/apps> and register a new app.
2. Set the **Redirect URI** to exactly `http://localhost:8080/callback`.
3. Keep the **Client ID** and **Client Secret** handy.

### 2. Log in

```sh
python sc_likes.py login
```

The first time, it asks for your Client ID and Secret and saves them to `config.json`. It then opens your browser so you can approve access. After you approve, the token is saved to `token.json` and refreshed automatically when it expires.

You can also pass the credentials as environment variables: `SOUNDCLOUD_CLIENT_ID`, `SOUNDCLOUD_CLIENT_SECRET` and, optionally, `SOUNDCLOUD_REDIRECT_URI`.

## Usage

```sh
python sc_likes.py list                 # writes likes.json + likes.csv
python sc_likes.py download             # saves audio into ./downloads
python sc_likes.py download --limit 20  # only the 20 most recent likes
python sc_likes.py logout               # deletes token.json
```

For each track, `download`:

1. downloads the original file if the uploader allows downloads (skip this with `--no-original`)
2. otherwise saves the 128 kbps MP3 stream
3. otherwise uses the AAC/Opus stream through ffmpeg

If a file with the same name is already there, the track is skipped, so you can re-run the command to pick up where it stopped. Tracks that fail are listed in `downloads/failed.json`.

`config.json` and `token.json` hold your credentials. Both are git-ignored, so don't commit them.

Only download music for personal use, and respect artists' rights.
