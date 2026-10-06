"""SoundCloud likes downloader.

Uses the official SoundCloud API with OAuth 2.1 (authorization code + PKCE).

    python sc_likes.py login       # one-time: authorize this app on your account
    python sc_likes.py list        # export liked tracks to likes.json / likes.csv
    python sc_likes.py download    # download liked tracks as audio files
    python sc_likes.py logout      # forget saved tokens
"""

import argparse
import base64
import csv
import hashlib
import http.server
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path

import requests

API = "https://api.soundcloud.com"
AUTHORIZE_URL = "https://secure.soundcloud.com/authorize"
TOKEN_URL = "https://secure.soundcloud.com/oauth/token"
DEFAULT_REDIRECT = "http://localhost:8080/callback"

APP_DIR = Path(__file__).resolve().parent
CONFIG_FILE = APP_DIR / "config.json"
TOKEN_FILE = APP_DIR / "token.json"


# --------------------------------------------------------------------------
# Config / token storage
# --------------------------------------------------------------------------

def load_json(path):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return None


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def get_config(interactive=True):
    """Client credentials come from env vars, then config.json, then a prompt."""
    cfg = load_json(CONFIG_FILE) or {}
    cfg["client_id"] = os.environ.get("SOUNDCLOUD_CLIENT_ID") or cfg.get("client_id")
    cfg["client_secret"] = os.environ.get("SOUNDCLOUD_CLIENT_SECRET") or cfg.get("client_secret")
    cfg["redirect_uri"] = os.environ.get("SOUNDCLOUD_REDIRECT_URI") or cfg.get("redirect_uri") or DEFAULT_REDIRECT

    if cfg["client_id"] and cfg["client_secret"]:
        return cfg
    if not interactive:
        sys.exit("No SoundCloud app credentials found. Run: python sc_likes.py login")

    print(
        "\nYou need a SoundCloud API app (one-time setup):\n"
        "  1. Go to https://soundcloud.com/you/apps and register a new app.\n"
        f"  2. Set its Redirect URI to exactly: {cfg['redirect_uri']}\n"
        "  3. Copy the Client ID and Client Secret below.\n"
    )
    cfg["client_id"] = input("Client ID: ").strip()
    cfg["client_secret"] = input("Client Secret: ").strip()
    if not cfg["client_id"] or not cfg["client_secret"]:
        sys.exit("Client ID and Client Secret are required.")
    save_json(CONFIG_FILE, cfg)
    print(f"Saved app credentials to {CONFIG_FILE.name}")
    return cfg


def store_token(tok):
    tok["expires_at"] = time.time() + int(tok.get("expires_in", 3600)) - 60
    save_json(TOKEN_FILE, tok)
    return tok


# --------------------------------------------------------------------------
# OAuth 2.1 + PKCE login
# --------------------------------------------------------------------------

def login():
    cfg = get_config()
    redirect = urllib.parse.urlparse(cfg["redirect_uri"])
    if redirect.hostname not in ("localhost", "127.0.0.1"):
        sys.exit("Redirect URI must point at localhost so this script can catch the callback.")

    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)

    auth_url = AUTHORIZE_URL + "?" + urllib.parse.urlencode({
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    })

    result = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            if url.path != redirect.path:
                self.send_response(404)
                self.end_headers()
                return
            result.update({k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()})
            ok = "code" in result and result.get("state") == state
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            msg = "Logged in! You can close this tab." if ok else "Login failed. Check the terminal."
            self.wfile.write(f"<h2>{msg}</h2>".encode())

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer((redirect.hostname, redirect.port or 80), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    print("\nOpening your browser to authorize with SoundCloud...")
    print(f"If it doesn't open, visit this URL manually:\n\n  {auth_url}\n")
    webbrowser.open(auth_url)

    try:
        while thread.is_alive():
            thread.join(0.5)
    except KeyboardInterrupt:
        sys.exit("\nLogin cancelled.")
    finally:
        server.server_close()

    if "error" in result:
        sys.exit(f"Authorization denied: {result.get('error_description') or result['error']}")
    if result.get("state") != state:
        sys.exit("State mismatch in OAuth callback — aborting.")
    if "code" not in result:
        sys.exit("No authorization code received.")

    res = requests.post(TOKEN_URL, data={
        "grant_type": "authorization_code",
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "redirect_uri": cfg["redirect_uri"],
        "code_verifier": verifier,
        "code": result["code"],
    }, headers={"Accept": "application/json; charset=utf-8"}, timeout=30)
    if not res.ok:
        sys.exit(f"Token exchange failed ({res.status_code}): {res.text}")
    store_token(res.json())

    me = Client().get_json(f"{API}/me")
    print(f"Logged in as {me.get('username')}. Token saved to {TOKEN_FILE.name}")


def logout():
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()
    print("Removed saved token. (App credentials in config.json were kept.)")


# --------------------------------------------------------------------------
# API client
# --------------------------------------------------------------------------

class Client:
    def __init__(self):
        self.cfg = get_config(interactive=False)
        self.token = load_json(TOKEN_FILE)
        if not self.token:
            sys.exit("Not logged in. Run: python sc_likes.py login")
        self.session = requests.Session()

    def refresh(self):
        if not self.token.get("refresh_token"):
            sys.exit("Session expired. Run: python sc_likes.py login")
        res = requests.post(TOKEN_URL, data={
            "grant_type": "refresh_token",
            "client_id": self.cfg["client_id"],
            "client_secret": self.cfg["client_secret"],
            "refresh_token": self.token["refresh_token"],
        }, headers={"Accept": "application/json; charset=utf-8"}, timeout=30)
        if not res.ok:
            sys.exit(f"Token refresh failed ({res.status_code}). Run: python sc_likes.py login")
        self.token = store_token(res.json())

    def get(self, url, **kwargs):
        for attempt in range(5):
            if time.time() >= self.token.get("expires_at", 0):
                self.refresh()
            headers = {"Authorization": f"OAuth {self.token['access_token']}",
                       "Accept": "application/json; charset=utf-8"}
            res = self.session.get(url, headers=headers, timeout=60, **kwargs)
            if res.status_code == 401 and attempt == 0:
                self.refresh()
                continue
            if res.status_code == 429 or res.status_code >= 500:
                wait = 2 ** attempt * 5
                print(f"  ({res.status_code} from API, retrying in {wait}s)")
                time.sleep(wait)
                continue
            res.raise_for_status()
            return res
        res.raise_for_status()
        return res

    def get_json(self, url, **kwargs):
        return self.get(url, **kwargs).json()

    def liked_tracks(self):
        url = f"{API}/me/likes/tracks?limit=200&linked_partitioning=true"
        while url:
            data = self.get_json(url)
            for item in data.get("collection", []):
                # Items are usually track objects; some API versions wrap them in {"track": ...}
                yield item.get("track", item) if isinstance(item, dict) else item
            url = data.get("next_href")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def fetch_likes(client):
    tracks = []
    for t in client.liked_tracks():
        tracks.append(t)
        print(f"\rFetched {len(tracks)} liked tracks...", end="", flush=True)
    print()
    return tracks


def track_row(t):
    return {
        "id": t.get("id"),
        "urn": t.get("urn"),
        "title": t.get("title"),
        "artist": (t.get("user") or {}).get("username"),
        "url": t.get("permalink_url"),
        "duration_sec": round((t.get("duration") or 0) / 1000),
        "genre": t.get("genre"),
        "access": t.get("access"),
        "downloadable": t.get("downloadable"),
        "created_at": t.get("created_at"),
    }


def cmd_list(args):
    client = Client()
    rows = [track_row(t) for t in fetch_likes(client)]
    out = Path(args.output)
    out.with_suffix(".json").write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    with out.with_suffix(".csv").open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["id"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} tracks to {out.with_suffix('.json')} and {out.with_suffix('.csv')}")


def safe_filename(name, max_len=150):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    return name[:max_len] or "untitled"


def download_to(client, url, dest, authed=True):
    tmp = dest.with_suffix(dest.suffix + ".part")
    res = client.get(url, stream=True) if authed else requests.get(url, stream=True, timeout=60)
    res.raise_for_status()
    with tmp.open("wb") as f:
        for chunk in res.iter_content(1 << 16):
            f.write(chunk)
    tmp.replace(dest)


def download_hls(client, playlist_url, dest):
    """MP3 HLS streams are plain MP3 segments, so they can just be concatenated."""
    playlist = requests.get(playlist_url, timeout=60)
    playlist.raise_for_status()
    segments = [urllib.parse.urljoin(playlist_url, line.strip())
                for line in playlist.text.splitlines()
                if line.strip() and not line.startswith("#")]
    tmp = dest.with_suffix(dest.suffix + ".part")
    with tmp.open("wb") as f:
        for seg in segments:
            r = requests.get(seg, timeout=60)
            r.raise_for_status()
            f.write(r.content)
    tmp.replace(dest)


def download_hls_ffmpeg(playlist_url, dest):
    tmp = dest.with_name(dest.stem + ".part" + dest.suffix)
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-i", playlist_url, "-c", "copy", str(tmp)], check=True)
    tmp.replace(dest)


def download_track(client, t, out_dir, prefer_original):
    track_id = t.get("urn") or t.get("id")
    artist = (t.get("user") or {}).get("username") or "Unknown"
    base = safe_filename(f"{artist} - {t.get('title') or track_id}")

    existing = list(out_dir.glob(glob_escape(base) + ".*"))
    existing = [p for p in existing if ".part" not in p.suffixes]
    if existing:
        return "skipped (already downloaded)"

    if t.get("access") == "blocked":
        return "skipped (blocked in your region)"

    # 1. Original file, if the uploader enabled downloads
    if prefer_original and t.get("downloadable"):
        try:
            ext = t.get("original_format") or "mp3"
            if ext == "raw":
                ext = "mp3"
            download_to(client, f"{API}/tracks/{track_id}/download", out_dir / f"{base}.{ext}")
            return f"downloaded original ({ext})"
        except requests.HTTPError:
            pass  # fall back to the stream

    # 2. Stream URLs
    streams = client.get_json(f"{API}/tracks/{track_id}/streams")
    if t.get("access") == "preview":
        print("    note: only a 30s preview is available for this track")

    if streams.get("http_mp3_128_url"):
        download_to(client, streams["http_mp3_128_url"], out_dir / f"{base}.mp3")
        return "downloaded mp3"

    hls_mp3 = streams.get("hls_mp3_128_url")
    if hls_mp3:
        playlist_url = resolve_redirect(client, hls_mp3)
        download_hls(client, playlist_url, out_dir / f"{base}.mp3")
        return "downloaded mp3 (hls)"

    hls_aac = streams.get("hls_aac_160_url") or streams.get("hls_opus_64_url")
    if hls_aac:
        if not shutil.which("ffmpeg"):
            return "skipped (only AAC/Opus HLS available — install ffmpeg to download these)"
        playlist_url = resolve_redirect(client, hls_aac)
        ext = "m4a" if "aac" in hls_aac else "ogg"
        download_hls_ffmpeg(playlist_url, out_dir / f"{base}.{ext}")
        return f"downloaded {ext} (hls)"

    if streams.get("preview_mp3_128_url"):
        download_to(client, streams["preview_mp3_128_url"], out_dir / f"{base} (preview).mp3")
        return "downloaded preview only"

    return "skipped (no stream available)"


def resolve_redirect(client, url):
    """Stream endpoints 302 to a signed CDN URL; fetch it without following."""
    res = client.get(url, allow_redirects=False)
    if res.is_redirect:
        return res.headers["Location"]
    try:
        return res.json().get("url", url)
    except ValueError:
        return url


def glob_escape(s):
    return re.sub(r"([\[\]*?])", r"[\1]", s)


def cmd_download(args):
    client = Client()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tracks = fetch_likes(client)
    if args.limit:
        tracks = tracks[: args.limit]

    failures = []
    for i, t in enumerate(tracks, 1):
        label = f"{(t.get('user') or {}).get('username')} - {t.get('title')}"
        print(f"[{i}/{len(tracks)}] {label}")
        try:
            status = download_track(client, t, out_dir, prefer_original=not args.no_original)
            print(f"    {status}")
        except Exception as e:  # keep going on per-track failures
            print(f"    FAILED: {e}")
            failures.append({"title": label, "url": t.get("permalink_url"), "error": str(e)})
        time.sleep(args.delay)

    if failures:
        (out_dir / "failed.json").write_text(json.dumps(failures, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n{len(failures)} tracks failed; see {out_dir / 'failed.json'}")
    print(f"\nDone. Files are in {out_dir.resolve()}")


def main():
    parser = argparse.ArgumentParser(description="Download your SoundCloud likes.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("login", help="Authorize with your SoundCloud account")
    sub.add_parser("logout", help="Delete the saved access token")

    p_list = sub.add_parser("list", help="Export liked tracks to JSON and CSV")
    p_list.add_argument("-o", "--output", default="likes", help="Output path without extension (default: likes)")

    p_dl = sub.add_parser("download", help="Download liked tracks as audio")
    p_dl.add_argument("-o", "--output-dir", default="downloads", help="Folder to save into (default: downloads)")
    p_dl.add_argument("--limit", type=int, help="Only download the N most recent likes")
    p_dl.add_argument("--no-original", action="store_true", help="Skip original-file downloads, always use streams")
    p_dl.add_argument("--delay", type=float, default=0.5, help="Seconds to wait between tracks (default: 0.5)")

    args = parser.parse_args()
    if args.command == "login":
        login()
    elif args.command == "logout":
        logout()
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "download":
        cmd_download(args)


if __name__ == "__main__":
    main()
