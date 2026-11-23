#!/usr/bin/env python3
"""Tesla "now playing" and synchronized-lyrics web page.

The app reuses TeslaMate's encrypted Owner API access token, reads the current
media state, and confidence-gates matches from several lyric providers. Playback
preferences stay in the browser; legacy server preferences are read only for
migration. The supplied Compose setup publishes the service on loopback so an
authenticated HTTPS reverse proxy can expose it safely.
"""
import base64
import concurrent.futures
import hashlib
import html
import json
import math
import os
import re
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from collections import OrderedDict
from functools import wraps

import psycopg2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, request, Response

try:                       # trad->simp folding so 陀飛輪==陀飞轮 when matching titles/artists
    from zhconv import convert as _zhconv
except Exception:
    _zhconv = None

# ─────────────────────────────── Configuration ────────────────────────────────
# Every knob is read from the environment; see .env.example for the full list and
# defaults. Real values live in the git-ignored .env file, so nothing secret or
# host-specific is hard-coded here.
def _env(*names, default=""):
    """First non-empty value among a list of env-var aliases, else `default`."""
    for n in names:
        v = os.environ.get(n)
        if v not in (None, ""):
            return v
    return default


# Tesla API / auth. Default to the free Owner API path; the Fleet API + a refresh
# token file are only kept as a legacy fallback (TOKEN_SOURCE=file).
CLIENT_ID = _env("TESLA_AUTH_CLIENT_ID")
API_HOST = _env("TESLA_API_HOST", default="https://owner-api.teslamotors.com")
AUTH_HOST = _env("TESLA_AUTH_HOST", default="https://auth.tesla.com")
AUTH_PATH = _env("TESLA_AUTH_PATH", default="/oauth2/v3")
FORCED_VIN = _env("TESLA_VIN").strip()
TOKEN_SOURCE = _env("TOKEN_SOURCE", default="teslamate_db").strip().lower()

# TeslaMate database — source of the encrypted Tesla access token. The extra
# aliases keep older TESLAMATE_*/DATABASE_* deployments working unchanged.
TESLAMATE_DB_HOST = _env("TM_DB_HOST", "TESLAMATE_DB_HOST", "DATABASE_HOST", default="database")
TESLAMATE_DB_NAME = _env("TM_DB_NAME", "TESLAMATE_DB_NAME", "DATABASE_NAME", default="teslamate")
TESLAMATE_DB_USER = _env("TM_DB_USER", "TESLAMATE_DB_USER", "DATABASE_USER", default="teslamate")
TESLAMATE_DB_PASS = _env("TM_DB_PASS", "TESLAMATE_DB_PASS", "DATABASE_PASS")
TESLAMATE_ENCRYPTION_KEY = _env("TM_ENCRYPTION_KEY", "TESLAMATE_ENCRYPTION_KEY", "ENCRYPTION_KEY")
TESLAMATE_ACCESS_TTL = float(_env("TESLAMATE_ACCESS_TTL", default="60"))

# Runtime data files (live on the mounted /data volume).
TOKEN_FILE = _env("TOKEN_FILE", default="/data/token.json")
PREFS_FILE = _env("PREFS_FILE", default="/data/prefs.json")
REPORTS_FILE = _env("REPORTS_FILE", default="/data/reports.jsonl")

# Web server + features.
BIND_HOST = _env("BIND_HOST", default="0.0.0.0")
BIND_PORT = int(_env("BIND_PORT", default="8475"))
TRANSLATE_TARGET_LANG = _env("TRANSLATE_TARGET_LANG", default="zh-CN")

app = Flask(__name__)

# Public-endpoint safety limits. These are deliberately well above normal song
# metadata/lyrics sizes while still bounding anonymous work and memory use.
MAX_REQUEST_BYTES = 64 * 1024
MAX_UPSTREAM_BYTES = 2 * 1024 * 1024
MAX_TITLE_CHARS = 200
MAX_ARTIST_CHARS = 200
MAX_SOURCE_CHARS = 2048
MAX_DURATION_SECONDS = 24 * 60 * 60
MAX_LRC_LINES = 300
MAX_LRC_LINE_CHARS = 1000
MAX_LRC_OUTPUT_CHARS = 100_000
MAX_TIMESTAMPS_PER_LINE = 8
MAX_TRANSLATE_LINES = 300
MAX_TRANSLATE_LINE_CHARS = 500
MAX_TRANSLATE_CHARS = 30_000
MAX_TRANSLATE_NETWORK_CALLS = 8
MAX_PREFS_ENTRIES = 5000
MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_REPORT_NOTE_CHARS = 500
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES


@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if response.mimetype == "text/html":
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        )
    return response


class BoundedTTLCache:
    """Small thread-safe mapping with LRU eviction and TTL expiry."""

    def __init__(self, maxsize, ttl):
        self.maxsize = int(maxsize)
        self.ttl = float(ttl)
        self._data = OrderedDict()
        self._lock = threading.RLock()

    def _get(self, key):
        value, created = self._data[key]
        if time.monotonic() - created > self.ttl:
            del self._data[key]
            raise KeyError(key)
        self._data.move_to_end(key)
        return value

    def __getitem__(self, key):
        with self._lock:
            return self._get(key)

    def __setitem__(self, key, value):
        with self._lock:
            self._data[key] = (value, time.monotonic())
            self._data.move_to_end(key)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)

    def __contains__(self, key):
        with self._lock:
            try:
                self._get(key)
                return True
            except KeyError:
                return False

    def get(self, key, default=None):
        with self._lock:
            try:
                return self._get(key)
            except KeyError:
                return default

    def clear(self):
        with self._lock:
            self._data.clear()

    def __len__(self):
        with self._lock:
            for key in list(self._data):
                try:
                    self._get(key)
                except KeyError:
                    pass
            return len(self._data)

_tok_lock = threading.Lock()
_prefs_lock = threading.Lock()
_reports_lock = threading.Lock()
_state_lock = threading.Lock()
_state_refresh_lock = threading.Lock()
_expensive_slots = threading.BoundedSemaphore(3)
# Provider work outlives the HTTP request when a faster source wins. Keep both
# running and queued work globally bounded so anonymous callers cannot create an
# unbounded number of background threads/futures.
_provider_pool = concurrent.futures.ThreadPoolExecutor(max_workers=6, thread_name_prefix="lyrics-provider")
_provider_slots = threading.BoundedSemaphore(10)
_access = {"token": None, "exp": 0}
_tm_access = {"token": None, "ts": 0.0}
_vin_cache = {"vin": FORCED_VIN or None}
_lyrics_cache = BoundedTTLCache(512, 24 * 3600)
_candidate_usable_cache = BoundedTTLCache(2048, 6 * 3600)
# Short-TTL cache for /api/state so bursts (scheduled poll + visibilitychange,
# extra tabs, retries) collapse into one Fleet API vehicle_data hit. The browser
# already advances lyrics locally, so a couple seconds of staleness is invisible.
_state_cache = {"data": None, "ts": 0.0}
STATE_TTL = float(_env("STATE_TTL", default="2.0"))
STATE_STALE_TTL = float(_env("STATE_STALE_TTL", default="30.0"))

# Debug-only audit hook: each lyrics source records the candidate it actually served
# here (keyed by source name). Never read by production logic — the offline
# verification harness clears it per song and inspects _PICK[used_source] to see WHICH
# track's lyrics were returned, so wrong-song matches can be caught automatically.
_PICK = {}


def _record_pick(source, title="", artist="", duration=None, sid=None, via=None):
    try:
        _PICK[source] = {"title": title or "", "artist": artist or "",
                         "duration": duration, "id": sid, "via": via}
    except Exception:
        pass


class _SameHostHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when they stay HTTPS on the original hostname."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
        if new.scheme != "https" or new.hostname != old.hostname:
            raise urllib.error.HTTPError(newurl, code, "unsafe_redirect", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_HTTP_OPENER = urllib.request.build_opener(_SameHostHTTPSRedirectHandler())


def _http(url, data=None, headers=None, timeout=15):
    target = urllib.parse.urlsplit(url)
    if target.scheme != "https" or not target.hostname:
        raise ValueError("https_required")
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with _HTTP_OPENER.open(req, timeout=timeout) as r:
        raw = r.read(MAX_UPSTREAM_BYTES + 1)
        if len(raw) > MAX_UPSTREAM_BYTES:
            raise ValueError("upstream_response_too_large")
        return r.status, raw.decode("utf-8", "replace")


def _atomic_write_json(path, payload):
    """Write private JSON mode-0600 from the first byte, then atomically replace."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1
            json.dump(payload, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def song_key(title, artist):
    return (title or "").strip().lower() + "|" + (artist or "").strip().lower()


def _valid_source(source):
    """Allow known providers and opaque provider IDs, never arbitrary schemes."""
    if not isinstance(source, str) or not source or len(source) > MAX_SOURCE_CHARS:
        return False
    if source == "auto" or source in SOURCES:
        return True
    if ":" not in source:
        return False
    provider, opaque_id = source.split(":", 1)
    return (provider in {"lrclib", "netease", "kugou", "petitlyrics"}
            and bool(re.fullmatch(r"[A-Za-z0-9._~+/=:-]{1,2030}", opaque_id)))


def _song_query(include_source=False):
    title = (request.args.get("title") or "").strip()
    artist = (request.args.get("artist") or "").strip()
    raw_duration = request.args.get("duration")
    try:
        duration = float(raw_duration) if raw_duration not in (None, "") else None
    except (TypeError, ValueError):
        return None
    if (not title or len(title) > MAX_TITLE_CHARS or len(artist) > MAX_ARTIST_CHARS
            or (duration is not None and
                (not math.isfinite(duration) or duration < 0 or duration > MAX_DURATION_SECONDS))):
        return None
    if not include_source:
        return title, artist, duration
    source = (request.args.get("source") or "auto").strip()
    if not _valid_source(source):
        return None
    return title, artist, duration, source


def _limit_expensive(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not _expensive_slots.acquire(blocking=False):
            return jsonify({"ok": False, "error": "busy"}), 429
        try:
            return fn(*args, **kwargs)
        finally:
            _expensive_slots.release()
    return wrapped


# ---------------- Tesla token + media ----------------
def _load_refresh():
    with open(TOKEN_FILE) as f:
        return json.load(f)["refresh_token"]


def _save_refresh(rt):
    _atomic_write_json(TOKEN_FILE, {"refresh_token": rt})


def _cloak_decrypt_aes_gcm(ciphertext):
    """Decrypt TeslaMate 4 private.tokens bytea (Cloak AES.GCM.V1)."""
    if not TESLAMATE_ENCRYPTION_KEY:
        raise RuntimeError("missing TeslaMate encryption key")
    b = bytes(ciphertext)
    if len(b) < 2 or b[0] != 1:
        raise RuntimeError("unsupported TeslaMate token header")
    tag_len = b[1]
    tag = b[2:2 + tag_len].decode("ascii", "replace")
    if tag != "AES.GCM.V1":
        raise RuntimeError(f"unsupported TeslaMate token cipher {tag!r}")
    p = 2 + tag_len
    iv = b[p:p + 12]
    auth_tag = b[p + 12:p + 28]
    ct = b[p + 28:]
    key = hashlib.sha256(TESLAMATE_ENCRYPTION_KEY.encode()).digest()
    return AESGCM(key).decrypt(iv, ct + auth_tag, b"AES256GCM").decode()


def _load_teslamate_access():
    now = time.time()
    if _tm_access["token"] and now - _tm_access["ts"] < TESLAMATE_ACCESS_TTL:
        return _tm_access["token"]
    if not TESLAMATE_DB_PASS:
        raise RuntimeError("missing TeslaMate DB password")
    with psycopg2.connect(
        host=TESLAMATE_DB_HOST,
        dbname=TESLAMATE_DB_NAME,
        user=TESLAMATE_DB_USER,
        password=TESLAMATE_DB_PASS,
        connect_timeout=5,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT access FROM private.tokens ORDER BY updated_at DESC LIMIT 1")
            row = cur.fetchone()
    if not row or row[0] is None:
        raise RuntimeError("no TeslaMate access token in DB")
    token = _cloak_decrypt_aes_gcm(row[0])
    _tm_access.update(token=token, ts=now)
    return token


def get_access():
    with _tok_lock:
        if TOKEN_SOURCE in ("teslamate", "teslamate_db", "db"):
            return _load_teslamate_access()
        if not CLIENT_ID:
            raise RuntimeError("missing TESLA_AUTH_CLIENT_ID for token-file mode")
        if _access["token"] and _access["exp"] - 60 > time.time():
            return _access["token"]
        body = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": _load_refresh(),
        }).encode()
        _, txt = _http(AUTH_HOST + AUTH_PATH + "/token", data=body,
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        d = json.loads(txt)
        _access["token"] = d["access_token"]
        _access["exp"] = time.time() + int(d.get("expires_in", 28800))
        if d.get("refresh_token"):
            try:
                _save_refresh(d["refresh_token"])
            except Exception:
                pass
        return _access["token"]


def _load_default_vin_from_teslamate():
    if not TESLAMATE_DB_PASS:
        return None
    with psycopg2.connect(
        host=TESLAMATE_DB_HOST,
        dbname=TESLAMATE_DB_NAME,
        user=TESLAMATE_DB_USER,
        password=TESLAMATE_DB_PASS,
        connect_timeout=5,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT vin
                FROM cars
                WHERE vin IS NOT NULL AND vin <> ''
                ORDER BY display_priority ASC, id ASC
                LIMIT 1
                """
            )
            row = cur.fetchone()
    return row[0] if row else None


def get_vin(access):
    if _vin_cache["vin"]:
        return _vin_cache["vin"]
    vin = _load_default_vin_from_teslamate()
    if vin:
        _vin_cache["vin"] = vin
        return vin
    _, txt = _http(API_HOST + "/api/1/vehicles", headers={"Authorization": "Bearer " + access})
    arr = json.loads(txt).get("response") or []
    if arr:
        _vin_cache["vin"] = arr[0]["vin"]
    return _vin_cache["vin"]


def _store_state(data):
    with _state_lock:
        _state_cache["data"] = data
        _state_cache["ts"] = time.time()
    return data


@app.route("/api/state")
def api_state():
    now = time.time()
    with _state_lock:
        cached = _state_cache["data"]
        age = now - _state_cache["ts"]
    if cached is not None and age < STATE_TTL:
        return jsonify(cached)

    # Only one request performs the Tesla API refresh. Other tabs receive a
    # recent stale value, or wait on a cold start and reuse the completed result.
    acquired = _state_refresh_lock.acquire(blocking=False)
    if not acquired:
        if cached is not None and age < STATE_STALE_TTL:
            return jsonify(cached)
        with _state_refresh_lock:
            pass
        with _state_lock:
            cached = _state_cache["data"]
            age = time.time() - _state_cache["ts"]
        if cached is not None and age < STATE_STALE_TTL:
            return jsonify(cached)
        return jsonify({"ok": False, "error": "upstream_unavailable"}), 502

    try:
        access = get_access()
        vin = get_vin(access)
        if not vin:
            return jsonify({"ok": False, "error": "no_vehicle"})
        url = API_HOST + f"/api/1/vehicles/{vin}/vehicle_data?endpoints=" + urllib.parse.quote("vehicle_state")
        try:
            _, txt = _http(url, headers={"Authorization": "Bearer " + access})
        except urllib.error.HTTPError as e:
            if e.code in (408, 405):  # asleep / unavailable
                return jsonify(_store_state({"ok": True, "online": False}))
            if e.code == 401 and TOKEN_SOURCE in ("teslamate", "teslamate_db", "db"):
                # TeslaMate may have refreshed after our short cache was filled.
                _tm_access.update(token=None, ts=0.0)
            raise
        vs = (json.loads(txt).get("response") or {}).get("vehicle_state") or {}
        mi = vs.get("media_info") or {}
        return jsonify(_store_state({
            "ok": True, "online": True,
            "playing": (mi.get("media_playback_status") == "Playing"),
            "status": mi.get("media_playback_status"),
            "title": mi.get("now_playing_title") or "",
            "artist": mi.get("now_playing_artist") or "",
            "album": mi.get("now_playing_album") or "",
            "source": mi.get("now_playing_source") or "",
            "elapsed": (mi.get("now_playing_elapsed") or 0) / 1000.0,
            "duration": (mi.get("now_playing_duration") or 0) / 1000.0,
            "ts": time.time(),
        }))
    except Exception:
        app.logger.exception("state refresh failed")
        if cached is not None and age < STATE_STALE_TTL:
            return jsonify(cached)
        return jsonify({"ok": False, "error": "upstream_unavailable"}), 502
    finally:
        _state_refresh_lock.release()


# ---------------- Lyrics providers and matching ----------------
_TS = re.compile(r"\[(\d+):(\d{1,2})(?:[.:](\d{1,3}))?\]")
_META = re.compile(r"^\[[a-zA-Z]+:")
_CJK = re.compile(r"[\u4e00-\u9fff]{2,}")
# Production credit lines (CN / TW / JP / EN) that some sources put inside the LRC \u2014
# matched as "<role>:<value>"/"<role>\uff1a<value>" so real lyrics aren't dropped.
_CREDIT = re.compile(
    r"^\s*[^:\uff1a\n]{0,8}?(\u4f5c\s*[\u8bcd\u8a5e]|\u4f5c\s*\u66f2|[\u7f16\u7de8]\s*\u66f2|\u586b\s*[\u8bcd\u8a5e]|[\u8c31\u8b5c]\s*\u66f2|[\u5236\u88fd]\s*\u4f5c(\u4eba)?|[\u76d1\u76e3]\s*[\u5236\u88fd]|\u51fa\u54c1|[\u53d1\u767c]\s*\u884c|"
    r"\u4f01[\u5212\u5283]|[\u7edf\u7d71]\s*[\u7b79\u7c4c]|\u914d\s*\u5531|\u548c\s*[\u58f0\u8072]|\u5408\s*[\u58f0\u8072]|\u6df7\s*\u97f3|\u6bcd\s*[\u5e26\u5e36]|[\u5f55\u9304]\s*\u97f3|\u6f14\s*\u594f|"
    r"\u5409\u4ed6|[\u8d1d\u8c9d]\u65af|\u9f13|[\u952e\u9375]\u76d8|[\u94a2\u92fc]\u7434|\u63d0\u7434|[\u957f\u9577]\u7b1b|\u8428\u514b\u65af|\u85a9\u514b\u65af|[\u7f16\u7de8]\u7a0b|[\u7f16\u7de8]\u8f91|[\u5f55\u9304]\u5236|\u5c01\u9762|[\u76d1\u76e3]\u5531|[\u89c6\u8996][\u89c9\u89ba]|\u7f8e[\u672f\u8853]|[\u8425\u71df][\u9500\u92b7]|\u63a8[\u5e7f\u5ee3]|\u5ba3[\u4f20\u50b3]|\u539f\u5531|\u6f14\u5531|\u6587\u6848|[\u7ecf\u7d93][\u7eaa\u7d00]|\u7248[\u6743\u6b0a]|\u51fa\u7248|[\u534f\u5354]\u529b|\u52a9\u7406|\u5de5\u7a0b|[\u540e\u5f8c]\u671f|[\u91c7\u63a1][\u6837\u6a23]|\u5408\u6210|[\u9e23\u9cf4][\u8c22\u8b1d]|\u7b56[\u5212\u5283]|[\u603b\u7e3d][\u76d1\u76e3]|[\u7f29\u7e2e]\u6df7|\u914d\u5668|\u548c\u97f3|[\u5f26\u7ba1][\u4e50\u6a02]|\u5f26[\u4e50\u6a02]|\u6b4c|\u5504|[\u8bcd\u8a5e]|\u66f2|"
    r"produc(ed|er|ers|tion)|a\s*&\s*r|engineer(ing|ed)?|artwork|written|composed|arranged|mix(ed|ing)|master(ed|ing)|record(ed|ing)?|studio|"
    r"lyric(s|ist)?|compos(er|ed)|vocal|guitar|bass|drums|piano|violin|cello|viola|keyboards?|strings|flute|sax|programm(ed|ing)|OP|SP|ISRC)[^:\uff1a\n]{0,10}[:\uff1a]", re.I)
_BAD_ALIAS = {"原唱", "钢琴", "钢琴曲", "纯音乐", "华语", "流行", "合辑", "音乐", "经典", "热门", "翻唱", "伴奏"}
# Keep the public tree free of an operator's listening fingerprints. Cross-script
# aliases and native titles are recovered from provider metadata at runtime.
_ARTIST_ALIASES = {}
# Apple Music / Tesla metadata often reports Mandarin tracks under English
# translations or pinyin. Native title+artist are recovered generically at
# runtime from the iTunes catalog (see recover_native_meta) — no per-song table.
_PLAIN_LYRIC_URLS = {}
_SONG_SOURCE_OVERRIDES = {}


def parse_lrc(text):
    """Parse a bounded LRC payload; reject amplification-shaped input entirely."""
    out = []
    output_chars = 0
    for line in (text or "").splitlines():
        if len(line) > MAX_LRC_LINE_CHARS:
            return []
        stamps = _TS.findall(line)
        if not stamps:
            continue
        if len(stamps) > MAX_TIMESTAMPS_PER_LINE or len(out) + len(stamps) > MAX_LRC_LINES:
            return []
        body = _TS.sub("", line).strip()
        if _META.match(line) and not body:
            continue
        if _CREDIT.match(body):
            continue
        if re.match(r"^.+\s+-\s+.+$", body) and int(stamps[0][0]) == 0:
            continue
        output_chars += len(body) * len(stamps)
        if output_chars > MAX_LRC_OUTPUT_CHARS:
            return []
        for mm, ss, fr in stamps:
            frac = float("0." + fr) if fr else 0.0
            timestamp = round(int(mm) * 60 + int(ss) + frac, 2)
            if timestamp <= MAX_DURATION_SECONDS:
                out.append([timestamp, body])
    out.sort(key=lambda x: x[0])
    return out


def usable_lyrics(lines):
    return len([txt for _, txt in (lines or []) if (txt or "").strip() and txt != "♪"]) >= 4


def make_approx_lrc(lines, duration=None):
    clean = []
    total_chars = 0
    for value in lines:
        value = re.sub(r"\s+", " ", value or "").strip()
        if not value or len(value) > MAX_LRC_LINE_CHARS:
            continue
        if len(clean) >= MAX_LRC_LINES or total_chars + len(value) > MAX_LRC_OUTPUT_CHARS:
            break
        clean.append(value)
        total_chars += len(value)
    if not clean:
        return None
    dur = float(duration or max(90, len(clean) * 5))
    start = 2.0
    step = max(2.2, (dur - 6.0) / max(len(clean), 1))
    out = []
    for i, line in enumerate(clean):
        t = start + i * step
        out.append(f"[{int(t // 60):02d}:{t % 60:05.2f}]{line}")
    return "\n".join(out)


def fetch_letras_plain(url, duration=None):
    _, txt = _http(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}, timeout=8)
    m = re.search(r'<div class="lyric-original">(.*?)</div>', txt, re.S)
    if not m:
        return None
    body = re.sub(r"</p>\s*<p>", "\n", m.group(1))
    body = re.sub(r"<br\s*/?>", "\n", body)
    body = re.sub(r"<[^>]+>", "", body)
    lines = [html.unescape(x).strip() for x in body.splitlines()]
    return make_approx_lrc(lines, duration)


def fetch_plain_fallback(title, artist, duration=None):
    url = _PLAIN_LYRIC_URLS.get(_latin_key(title))
    if not url:
        return None
    return fetch_letras_plain(url, duration)


def _t2s(s):
    if not s or not _zhconv:
        return s or ""
    try:
        return _zhconv(s, "zh-cn")
    except Exception:
        return s


# Katakana -> romaji, so a romanized Apple artist name can match the native
# katakana form on NetEase. Approximate but sufficient for candidate matching.
_KATA = {
    'ア':'a','イ':'i','ウ':'u','エ':'e','オ':'o','カ':'ka','キ':'ki','ク':'ku','ケ':'ke','コ':'ko',
    'サ':'sa','シ':'shi','ス':'su','セ':'se','ソ':'so','タ':'ta','チ':'chi','ツ':'tsu','テ':'te','ト':'to',
    'ナ':'na','ニ':'ni','ヌ':'nu','ネ':'ne','ノ':'no','ハ':'ha','ヒ':'hi','フ':'fu','ヘ':'he','ホ':'ho',
    'マ':'ma','ミ':'mi','ム':'mu','メ':'me','モ':'mo','ヤ':'ya','ユ':'yu','ヨ':'yo',
    'ラ':'ra','リ':'ri','ル':'ru','レ':'re','ロ':'ro','ワ':'wa','ヲ':'wo','ン':'n',
    'ガ':'ga','ギ':'gi','グ':'gu','ゲ':'ge','ゴ':'go','ザ':'za','ジ':'ji','ズ':'zu','ゼ':'ze','ゾ':'zo',
    'ダ':'da','ヂ':'ji','ヅ':'zu','デ':'de','ド':'do','バ':'ba','ビ':'bi','ブ':'bu','ベ':'be','ボ':'bo',
    'パ':'pa','ピ':'pi','プ':'pu','ペ':'pe','ポ':'po','ヴ':'vu',
    'ァ':'a','ィ':'i','ゥ':'u','ェ':'e','ォ':'o','ッ':'','ー':'',
}
_YOUON = {'ャ':'ya','ュ':'yu','ョ':'yo'}


def _kana_romaji(s):
    out = []
    for ch in s or "":
        if ch in _YOUON and out and out[-1].endswith('i') and len(out[-1]) > 1:
            out[-1] = out[-1][:-1] + _YOUON[ch]      # キ+ャ -> kya
        elif ch in _KATA:
            out.append(_KATA[ch])
        elif ch.isalnum():
            out.append(ch.lower())
    return ''.join(out)


def _norm_title(s):
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", _t2s((s or "").lower()))


def title_matches(want, got):
    w = _norm_title(want)
    g = _norm_title(got)
    if not w or not g:
        return False
    if w == g:
        return True
    # LRCLIB sometimes prefixes track numbers, e.g. "04.紅".
    return len(w) <= 2 and g.endswith(w) and re.fullmatch(r"\d+" + re.escape(w), g)


def fetch_lrclib(title, artist, duration):
    headers = {"User-Agent": "tesla-nowplaying/0.2 (self-hosted)"}
    artists = artist_query_aliases(artist)
    for a in artists:
        if duration:
            q = urllib.parse.urlencode({"track_name": title, "artist_name": a, "duration": int(duration)})
            try:
                _, txt = _http("https://lrclib.net/api/get?" + q, headers=headers, timeout=7)
                obj = json.loads(txt)
                sy = obj.get("syncedLyrics")
                if sy:
                    _record_pick("lrclib", obj.get("trackName") or title, obj.get("artistName") or a,
                                 obj.get("duration") or duration, obj.get("id"), via="exact")
                    return sy
            except Exception:
                pass
    for a in artists:
        try:
            _, txt = _http("https://lrclib.net/api/search?" +
                           urllib.parse.urlencode({"q": f"{title} {a}".strip()}), headers=headers, timeout=6)
        except Exception:
            continue
        for it in json.loads(txt):
            if it.get("syncedLyrics") and title_matches(title, it.get("trackName") or ""):
                _record_pick("lrclib", it.get("trackName"), it.get("artistName"),
                             it.get("duration"), it.get("id"), via="search")
                return it["syncedLyrics"]
    return None


def fetch_lrclib_id(lid):
    headers = {"User-Agent": "tesla-nowplaying/0.2 (self-hosted)"}
    _, txt = _http(f"https://lrclib.net/api/get/{urllib.parse.quote(str(lid))}", headers=headers, timeout=16)
    return json.loads(txt).get("syncedLyrics")


def search_lrclib(title, artist, duration, limit=5):
    headers = {"User-Agent": "tesla-nowplaying/0.2 (self-hosted)"}
    _, txt = _http("https://lrclib.net/api/search?" +
                   urllib.parse.urlencode({"q": f"{title} {artist}".strip()}), headers=headers, timeout=12)
    out = []
    for i, it in enumerate(json.loads(txt)):
        if not it.get("syncedLyrics"):
            continue
        dur = it.get("duration") or 0
        score = max(0, 100 - i * 8 - (abs(float(dur) - float(duration or 0)) if duration and dur else 0) / 3)
        out.append({"id": f"lrclib:{it.get('id')}", "source": "lrclib", "title": it.get("trackName") or "",
                    "artist": it.get("artistName") or "", "album": it.get("albumName") or "",
                    "duration": dur, "score": round(score)})
        if len(out) >= limit:
            break
    return out


def _norm_words(s):
    return set(re.findall(r"[a-z0-9\u4e00-\u9fff]+", (s or "").lower()))


def _candidate_score(title, artist, duration, item, index=0):
    dur = (item.get("duration") or 0) / 1000.0
    artists = ", ".join(a.get("name", "") for a in (item.get("artists") or []) if a.get("name"))
    score = 80 - index * 7
    if title and (item.get("name") or "").strip().lower() == title.strip().lower():
        score += 18
    if duration and dur:
        score += max(0, 30 - abs(float(dur) - float(duration)) / 2)
    awant = _norm_words(artist)
    ahave = _norm_words(artists)
    if awant and ahave:
        overlap = len(awant & ahave)
        score += 18 * overlap / max(len(awant), 1)
        if overlap == 0:
            score -= 18
    return score


def _strip_suffix(s):
    # Drop trailing descriptors that shouldn't block a title match: bracketed
    # groups ((Live)/(电影…片尾曲)/(feat. X)/（cover …）) and "feat." clauses.
    s = re.sub(r"\s*[(（\[【].*?[)）\]】]\s*", " ", s or "")
    s = re.sub(r"\s*(feat\.?|ft\.?|featuring)\s.*$", "", s, flags=re.I)
    return s.strip()


def _title_match(qt, ct):
    def hit(a, b):
        if not a or not b:
            return False
        if a == b:
            return True
        lo, hi = (a, b) if len(a) <= len(b) else (b, a)   # one a substantial substring of the other
        return len(lo) >= 3 and lo in hi and len(lo) / len(hi) >= 0.5
    # compare both the full titles and their suffix-stripped base forms, so e.g.
    # "Fruits (feat. asmi)" still matches "Fruits" while "唯一 (Only One)" still
    # matches "Only One" (the full form is kept too).
    qs = {_norm_title(qt), _norm_title(_strip_suffix(qt))} - {""}
    cs = {_norm_title(ct), _norm_title(_strip_suffix(ct))} - {""}
    return any(hit(a, b) for a in qs for b in cs)


def _artist_match(qartist, cartist, aliases):
    cand = _t2s((cartist or "")).lower()
    cand_toks = {t for t in _norm_words(cartist) if len(t) > 1}   # drop 1-char latin noise (the g/e/m of "G.E.M.")
    cand_romaji = _kana_romaji(cartist or "")                    # ツルシマアンナ -> tsurushimaanna
    for a in list(aliases or []) + [qartist]:
        a2 = _t2s((a or "")).lower()
        if {t for t in _norm_words(a) if len(t) > 1} & cand_toks:
            return True
        for run in re.findall(r"[一-鿿]{2,}", a2):   # CJK alias run inside the candidate artist
            if run in cand:
                return True
        an = re.sub(r"[^a-z0-9]", "", a2)            # romanized alias vs katakana artist
        if len(an) >= 4 and cand_romaji and (an in cand_romaji or cand_romaji in an):
            return True
    return False


def _match_ok(qt, qa, qd, ct, ca, cd, aliases):
    """Fail closed unless the candidate describes the queried recording."""
    try:
        dd = abs(float(cd) - float(qd)) if (qd and cd) else None
    except (TypeError, ValueError):
        dd = None
    t = _title_match(qt, ct)
    a = _artist_match(qa, ca, aliases)
    title_known = bool((qt or "").strip() and (ct or "").strip())
    artist_known = bool((qa or "").strip() and (ca or "").strip())
    if title_known and not t:
        return False
    if artist_known and not a:
        return False
    if not title_known and not artist_known:
        return False
    if dd is not None and dd > 6:
        return False
    # If either metadata field is absent, duration must provide the second anchor.
    return (title_known and artist_known) or dd is not None


def fetch_netease(title, artist, duration=None):
    h = {"Referer": "https://music.163.com/", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
         "Cookie": "appver=2.0.2"}
    _, txt = _http("https://music.163.com/api/search/get/?" +
                   urllib.parse.urlencode({"s": f"{title} {artist}".strip(), "type": 1, "limit": 8}), headers=h, timeout=5)
    songs = (json.loads(txt).get("result") or {}).get("songs") or []
    aliases = artist_query_aliases(artist)
    scored = sorted(enumerate(songs), key=lambda p: _candidate_score(title, artist, duration, p[1], p[0]), reverse=True)
    for _, s in scored[:6]:
        sid = s.get("id")
        if not sid:
            continue
        cartists = ", ".join(a.get("name", "") for a in (s.get("artists") or []) if a.get("name"))
        cd = (s.get("duration") or 0) / 1000.0
        # Gate: skip a candidate whose identity doesn't match the query (the real
        # song may have no synced lyrics, in which case we'd rather return nothing
        # than serve a popular same-titled decoy's lyrics).
        if not _match_ok(title, artist, duration, s.get("name") or "", cartists, cd, aliases):
            continue
        try:
            _, txt = _http(f"https://music.163.com/api/song/lyric?id={sid}&lv=-1&kv=-1&tv=-1", headers=h, timeout=5)
            lrc = (json.loads(txt).get("lrc") or {}).get("lyric") or ""
            if _TS.search(lrc):
                _record_pick("netease", s.get("name"), cartists, cd, sid)
                return lrc
        except Exception:
            continue
    return None


def fetch_netease_id(sid):
    h = {"Referer": "https://music.163.com/", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
         "Cookie": "appver=2.0.2"}
    _, txt = _http(f"https://music.163.com/api/song/lyric?id={urllib.parse.quote(str(sid))}&lv=-1&kv=-1&tv=-1", headers=h, timeout=5)
    lrc = (json.loads(txt).get("lrc") or {}).get("lyric") or ""
    return lrc if _TS.search(lrc) else None


def search_netease(title, artist, duration, limit=5):
    h = {"Referer": "https://music.163.com/", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
         "Cookie": "appver=2.0.2"}
    _, txt = _http("https://music.163.com/api/search/get/?" +
                   urllib.parse.urlencode({"s": f"{title} {artist}".strip(), "type": 1, "limit": limit}), headers=h, timeout=5)
    out = []
    for i, s in enumerate((json.loads(txt).get("result") or {}).get("songs") or []):
        dur = (s.get("duration") or 0) / 1000.0
        score = max(0, 82 - i * 8 - (abs(float(dur) - float(duration or 0)) if duration and dur else 0) / 3)
        artists = ", ".join(a.get("name", "") for a in (s.get("artists") or []) if a.get("name"))
        album = (s.get("album") or {}).get("name") or ""
        out.append({"id": f"netease:{s.get('id')}", "source": "netease", "title": s.get("name") or "",
                    "artist": artists, "album": album, "duration": dur, "score": round(score)})
    return out


def has_cjk(s):
    return bool(_CJK.search(s or ""))


def _latin_key(s):
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _dedupe(seq):
    out = []
    seen = set()
    for x in seq:
        if x and x not in seen:
            out.append(x)
            seen.add(x)
    return out


_artist_alias_cache = BoundedTTLCache(512, 6 * 3600)


def artist_query_aliases(artist):
    cached = _artist_alias_cache.get(artist)
    if cached is not None:
        return cached
    aliases = [artist] + _ARTIST_ALIASES.get(artist, [])
    # Generic Apple Music case: English artist name, Chinese song catalog.
    # NetEase search for the artist usually exposes the local Chinese spelling.
    if artist and not has_cjk(artist):
        try:
            for s in _netease_raw_search(artist, limit=6):
                for a in s.get("artists") or []:
                    name = a.get("name") or ""
                    if has_cjk(name):
                        aliases.append(name)
        except Exception:
            pass
    out = _dedupe(aliases)
    _artist_alias_cache[artist] = out
    return out


def _netease_raw_search(query, limit=8):
    h = {"Referer": "https://music.163.com/", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
         "Cookie": "appver=2.0.2"}
    _, txt = _http("https://music.163.com/api/search/get/?" +
                   urllib.parse.urlencode({"s": query, "type": 1, "limit": limit}), headers=h, timeout=5)
    return (json.loads(txt).get("result") or {}).get("songs") or []


_ITUNES_STORES = ["HK", "TW", "CN"]
_INSTRUMENTAL = re.compile(
    r"(钢琴|鋼琴|piano|纯音乐|純音樂|instrumental|karaoke|伴奏|cover|八音盒|music box|"
    r"吉他|guitar|口琴|萨克斯|薩克斯|古筝|古箏|二胡|笛子|remix|dj)", re.I)
# Compilation / playlist / cover-collection names that turn up in iTunes search
# and must NOT be mistaken for a track's native title (e.g. 最新热歌慢摇).
_COMPILATION = re.compile(
    r"(最新|热歌|熱歌|慢摇|慢搖|串烧|串燒|精选|精選|合辑|合輯|合集|排行|金曲|對唱|对唱|網絡|网络|"
    r"抖音|快手|车载|車載|纯享|純享|翻唱|cover|various|v\.?\s*a\.?|群星|榜|歌单|歌單)", re.I)
_native_cache = BoundedTTLCache(512, 6 * 3600)
_auto_cache = BoundedTTLCache(512, 24 * 3600)


def _itunes_search(term, country, limit=8, timeout=6):
    p = urllib.parse.urlencode({"term": term, "entity": "song", "country": country,
                                "limit": limit, "lang": "zh_CN"})
    try:
        _, txt = _http("https://itunes.apple.com/search?" + p,
                       headers={"User-Agent": "tesla-nowplaying/0.3 (self-hosted)"}, timeout=timeout)
        return json.loads(txt).get("results") or []
    except Exception:
        return []


def recover_native_meta(title, artist, duration=None, limit=4):
    """Recover native (CJK) title + artist when Apple Music reports a romanized /
    translated name. Apple's iTunes catalog carries the same recording under
    native names in the CN/TW/HK storefronts; the English term still matches the
    search index there, and duration is a stable cross-storefront join key. Fully
    generic — no per-song table. Returns (native_title, native_artist) pairs."""
    # A duration is required to anchor the cross-storefront join; without it the
    # match is too weak (it made English songs latch onto unrelated same-length
    # Chinese tracks).
    if not title or has_cjk(title) or not duration:
        return []
    ck = (_latin_key(title), _latin_key(artist), int(duration) // 2)
    cached = _native_cache.get(ck)
    if cached is not None:
        return cached
    term = (title + " " + artist).strip()
    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(_ITUNES_STORES)) as ex:
            for rs in ex.map(lambda c: _itunes_search(term, c), _ITUNES_STORES):
                results.extend(rs)
    except Exception:
        results = []
    awant = _norm_words(artist)
    scored = {}
    for r in results:
        tn = (r.get("trackName") or "").strip()
        if not has_cjk(tn):
            continue
        an = (r.get("artistName") or "").strip()
        if _COMPILATION.search(tn) or _COMPILATION.search(an):
            continue   # playlist / compilation / cover entry — not the original track
        dur = (r.get("trackTimeMillis") or 0) / 1000.0
        if not dur or abs(dur - float(duration)) > 4:
            continue   # only trust a tight duration match
        score = 50 - abs(dur - float(duration)) * 4
        if _INSTRUMENTAL.search(tn):
            score -= 45
        if awant and (awant & _norm_words(an)):
            score += 20   # romanized artist tokens line up (typical for English artists)
        pair = (tn, an if has_cjk(an) else artist)
        if score > scored.get(pair, -1e9):
            scored[pair] = score
    out = [p for p, s in sorted(scored.items(), key=lambda kv: kv[1], reverse=True) if s > 0][:limit]
    # NOTE: the old NetEase substring-harvest fallback was removed here — it fired on
    # nearly every non-CJK indie/JP title iTunes doesn't carry and cost 5–15s of
    # serial NetEase queries per song for almost no gain (those have no Chinese name).
    _native_cache[ck] = out
    return out


def _netease_native_fallback(title, artist, duration=None, limit=4):
    """When iTunes can't bridge the translation, harvest likely Chinese titles
    from NetEase search results (duration-weighted). Returns (title, artist) pairs."""
    scored = {}
    artist_aliases = artist_query_aliases(artist)
    cjk_artist = next((a for a in artist_aliases if has_cjk(a)), artist)

    def add(text, base):
        if _COMPILATION.search(text or ""):
            return
        for m in _CJK.findall(text or ""):
            m = m.strip(" 的")
            if len(m) < 2 or m in _BAD_ALIAS or m in artist_aliases:
                continue
            if any(b in m for b in _BAD_ALIAS) and len(m) > 4:
                continue
            sc = base + (12 if (text or "").startswith(m) else 0)
            scored[m] = max(scored.get(m, 0), sc)

    for a in artist_aliases:
        try:
            songs = _netease_raw_search((title + " " + a).strip(), limit=8)
        except Exception:
            songs = []
        for i, s in enumerate(songs):
            dur = (s.get("duration") or 0) / 1000.0
            close = max(0, 30 - abs(dur - float(duration or 0)) / 3) if duration and dur else 8
            album = s.get("album") or {}
            for text in [s.get("name") or "", *(s.get("alias") or []),
                         album.get("name") or "", *(album.get("transNames") or [])]:
                add(text, 60 - i * 6 + close)
    best = [t for t, _ in sorted(scored.items(), key=lambda kv: kv[1], reverse=True)[:limit]]
    return [(t, cjk_artist) for t in best]


def _try_sources(qtitle, qartist, duration, order, deadline=5.0, grace=0.6):
    """Run candidate sources concurrently and return the highest-priority usable
    result (`order` defines priority). Returns the moment priority is decided; but
    once SOME source has hit, a higher-priority source gets only `grace` more
    seconds to answer — so a fast hit from a lower-priority source isn't stuck
    behind a slow/empty higher one (e.g. NetEase ready in 0.5s while LRCLIB grinds
    to its timeout). `deadline` caps the wait while nothing has hit yet. Stragglers
    finish in the background and are discarded."""
    def run(name):
        try:
            raw = SOURCES[name](qtitle, qartist, duration)
        except Exception:
            raw = None
        if raw:
            lines = parse_lrc(raw)
            if usable_lyrics(lines):
                return lines
        return None

    futs, done = {}, set()
    for name in order:
        if not _provider_slots.acquire(blocking=False):
            done.add(name)
            continue
        try:
            fut = _provider_pool.submit(run, name)
        except Exception:
            _provider_slots.release()
            done.add(name)
            continue
        fut.add_done_callback(lambda _f: _provider_slots.release())
        futs[fut] = name
    found, pending = {}, set(futs)
    start, first_hit = time.monotonic(), None

    def cancel_pending():
        for fut in pending:
            fut.cancel()

    def decide():
        # Earliest source in `order` that has a hit wins; if an earlier source is
        # still pending we must wait; if everything finished with no hit, give up.
        for n in order:
            if n in found:
                return n, found[n]
            if n not in done:
                return False
        return None, None

    while pending:
        now = time.monotonic()
        budget = (first_hit + grace if first_hit is not None else start + deadline) - now
        done_now, pending = concurrent.futures.wait(
            pending, timeout=max(0.0, budget), return_when=concurrent.futures.FIRST_COMPLETED)
        if not done_now:          # grace window (or overall deadline) elapsed
            break
        for fut in done_now:
            done.add(futs[fut])
            try:
                lines = fut.result()
            except Exception:
                lines = None
            if lines:
                found[futs[fut]] = lines
                if first_hit is None:
                    first_hit = time.monotonic()
        verdict = decide()
        if verdict is not False:
            cancel_pending()
            return verdict
    cancel_pending()
    for n in order:
        if n in found:
            return n, found[n]
    return None, None


def _strip_kugou_highlight(s):
    return re.sub(r"</?em>", "", s or "").strip()


def search_kugou(title, artist, duration, limit=5):
    h = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    # KuGou's old lyrics endpoint often returns no result for "title artist"
    # on Chinese songs, but title-only returns usable candidates with singer info.
    queries = []
    if title:
        queries.append(title)
    if artist:
        queries.append(f"{title} {artist}".strip())
    seen = set()
    out = []
    for qtxt in queries:
        _, txt = _http("https://lyrics.kugou.com/search?" + urllib.parse.urlencode({
            "ver": 1, "man": "yes", "client": "pc", "keyword": qtxt,
            "duration": int(duration or 0)
        }), headers=h, timeout=6)
        for i, c in enumerate((json.loads(txt).get("candidates") or [])):
            cid = str(c.get("download_id") or c.get("id") or "")
            ak = c.get("accesskey") or ""
            if not cid or not ak or (cid, ak) in seen:
                continue
            seen.add((cid, ak))
            dur = float(c.get("duration") or 0)   # KuGou reports seconds (NOT ms)
            song = _strip_kugou_highlight(c.get("song") or title)
            singer = _strip_kugou_highlight(c.get("singer") or "")
            display_artist = artist if artist and (not singer or singer == song) else singer
            score = 78 - i * 6
            if duration and dur:
                score -= abs(float(dur) - float(duration)) / 3
            if title and song and title.strip().lower() == song.strip().lower():
                score += 6
            if artist:
                score += 12 if artist in display_artist else -8
            label = " / ".join(x for x in [c.get("product_from"), c.get("language")] if x) or "KuGou"
            out.append({"id": f"kugou:{cid}:{ak}", "source": "kugou", "title": song,
                        "artist": display_artist, "album": label, "duration": dur, "score": round(max(0, score))})
            if len(out) >= limit:
                return out
    return out


def fetch_kugou_id(token):
    parts = str(token).split(":", 1)
    if len(parts) != 2:
        return None
    cid, ak = parts
    h = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    _, txt = _http("https://lyrics.kugou.com/download?" + urllib.parse.urlencode({
        "ver": 1, "client": "pc", "id": cid, "accesskey": ak,
        "fmt": "lrc", "charset": "utf8"
    }), headers=h, timeout=6)
    content = json.loads(txt).get("content") or ""
    if not content:
        return None
    return base64.b64decode(content).decode("utf-8", "replace")


def fetch_kugou(title, artist, duration=None):
    aliases = artist_query_aliases(artist)
    for c in search_kugou(title, artist, duration, limit=5):
        if not _match_ok(title, artist, duration, c.get("title") or "", c.get("artist") or "", c.get("duration"), aliases):
            continue
        raw = fetch_kugou_id(c["id"].split(":", 1)[1])
        if raw and _TS.search(raw):
            _record_pick("kugou", c.get("title"), c.get("artist"), c.get("duration"), c.get("id"))
            return raw
    return None




# ---------------- PetitLyrics (JP catalog / word-sync) -------------------------
# Unofficial but long-lived client endpoint used by the MusicBee PetitLyrics plugin.
# lyricsType=3 returns word-sync XML; we collapse each line to a normal LRC timestamp
# using the first word start time.  If a song only has plain text, fall back to an
# approximate timeline so it is still displayable.
_PETIT_BASE = "https://p0.petitlyrics.com/api/GetPetitLyricsData.php"
_PETIT_APP_ID = os.environ.get("PETITLYRICS_CLIENT_APP_ID", "p1110417")
_PETIT_HDRS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "MusicBee.PetitLyrics",
}


def _petit_call(title=None, artist=None, album=None, duration=None, lyrics_type="3"):
    params = {
        "clientAppId": _PETIT_APP_ID,
        "lyricsType": str(lyrics_type),
        "terminalType": "10",
        "key_title": title or "",
        "key_artist": artist or "",
        "key_album": album or "",
    }
    if duration:
        # Endpoint accepts duration in milliseconds and uses it as a fuzzy matcher.
        params["duration"] = str(int(float(duration) * 1000))
    _, txt = _http(_PETIT_BASE, data=urllib.parse.urlencode(params).encode("utf-8"),
                   headers=_PETIT_HDRS, timeout=8)
    try:
        import xml.etree.ElementTree as ET
        return ET.fromstring(txt)
    except Exception:
        return None


def _petit_decode_lyrics_data(text):
    if not text:
        return ""
    try:
        return base64.b64decode(text).decode("utf-8", "replace")
    except Exception:
        return ""


def _petit_song_meta(song):
    def tx(name):
        return (song.findtext(name) or "").strip()
    dur = 0.0
    try:
        dur = float(tx("duration") or 0) / 1000.0
    except Exception:
        dur = 0.0
    return {
        "lyrics_id": tx("lyricsId"),
        "title": tx("title"),
        "artist": tx("artist"),
        "album": tx("album"),
        "duration": dur,
        "lyrics_type": tx("lyricsType"),
        "available_type": tx("availableLyricsType"),
    }


def _petit_token(meta):
    raw = json.dumps({"t": meta.get("title") or "", "a": meta.get("artist") or "",
                      "b": meta.get("album") or "", "d": meta.get("duration") or 0},
                     ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _petit_untoken(token):
    try:
        raw = token + "=" * (-len(token) % 4)
        d = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")).decode("utf-8"))
        return d.get("t") or "", d.get("a") or "", d.get("b") or "", d.get("d") or None
    except Exception:
        return "", "", "", None


def _petit_wordxml_to_lrc(xml_text):
    if not xml_text or "<wsy" not in xml_text:
        return None
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_text)
    except Exception:
        return None
    out = []
    for line in root.findall(".//line"):
        text = (line.findtext("linestring") or "").strip()
        if not text:
            continue
        starts = []
        for w in line.findall("word"):
            try:
                starts.append(int(w.findtext("starttime") or 0))
            except Exception:
                pass
        if not starts:
            continue
        sec = min(starts) / 1000.0
        out.append(f"[{int(sec // 60):02d}:{sec % 60:05.2f}]{text}")
    return "\n".join(out) if out else None


def _petit_fetch_raw(title, artist, album="", duration=None):
    # Prefer word-sync; fall back to plain text if the song only has text lyrics.
    aliases = artist_query_aliases(artist)
    for lt in ("3", "1"):
        root = _petit_call(title, artist, album, duration, lyrics_type=lt)
        songs = root.findall(".//song") if root is not None else []
        for song in songs:
            meta = _petit_song_meta(song)
            if not _match_ok(
                    title, artist, duration,
                    meta.get("title") or "", meta.get("artist") or "",
                    meta.get("duration") or 0, aliases):
                continue
            raw = _petit_decode_lyrics_data(song.findtext("lyricsData"))
            if not raw:
                continue
            if lt == "3":
                lrc = _petit_wordxml_to_lrc(raw)
                if lrc and _TS.search(lrc):
                    _record_pick("petitlyrics", meta.get("title"), meta.get("artist"), meta.get("duration"), meta.get("lyrics_id"), via="wordsync")
                    return lrc
            else:
                lines = [x.strip() for x in raw.splitlines() if x.strip()]
                lrc = make_approx_lrc(lines, duration or meta.get("duration"))
                if lrc:
                    _record_pick("petitlyrics", meta.get("title"), meta.get("artist"), meta.get("duration"), meta.get("lyrics_id"), via="plain")
                    return lrc
    return None


def fetch_petitlyrics(title, artist, duration=None):
    return _petit_fetch_raw(title, artist, "", duration)


def fetch_petitlyrics_id(token):
    title, artist, album, duration = _petit_untoken(token)
    if not title:
        return None
    return _petit_fetch_raw(title, artist, album, duration)


def search_petitlyrics(title, artist, duration, limit=5):
    root = _petit_call(title, artist, "", duration, lyrics_type="3")
    songs = root.findall(".//song") if root is not None else []
    out = []
    aliases = artist_query_aliases(artist)
    for i, song in enumerate(songs):
        meta = _petit_song_meta(song)
        dur = meta.get("duration") or 0
        if not _match_ok(
                title, artist, duration,
                meta.get("title") or "", meta.get("artist") or "", dur, aliases):
            continue
        score = 84 - i * 6
        if title and title_matches(title, meta.get("title") or ""):
            score += 8
        if artist and _artist_match(artist, meta.get("artist") or "", artist_query_aliases(artist)):
            score += 8
        if duration and dur:
            score -= abs(float(dur) - float(duration)) / 3
        out.append({"id": f"petitlyrics:{_petit_token(meta)}", "source": "petitlyrics",
                    "title": meta.get("title") or "", "artist": meta.get("artist") or "",
                    "album": meta.get("album") or "", "duration": dur,
                    "score": round(max(0, score))})
        if len(out) >= limit:
            break
    return out


# ---------------- Musixmatch (Apple Music's own lyrics provider) ----------------
# Same source Apple uses, so it indexes Apple's translated titles and carries
# high-quality synced (and word-by-word) lyrics. The public desktop endpoint is
# token-gated and rate-limited from datacenter IPs, so we cache + retry the token
# and persist it. Matching is strict (title + artist + duration) — on a weak match
# we return None and let the other sources answer, never wrong lyrics.
_MXM_BASE = "https://apic-desktop.musixmatch.com/ws/1.1/"
_MXM_TOKEN_FILE = os.environ.get("MXM_TOKEN_FILE", "/data/mxm_token.json")
_mxm_lock = threading.Lock()
_mxm_tok = {"token": None, "exp": 0}
_MXM_HDRS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)", "Cookie": "x-mxm-token-guid=1"}


def _mxm_fetch_token():
    url = _MXM_BASE + "token.get?app_id=web-desktop-app-v1.0&format=json&user_language=en"
    _, txt = _http(url, headers=_MXM_HDRS, timeout=7)
    return (((json.loads(txt).get("message") or {}).get("body")) or {}).get("user_token")


def _mxm_token():
    with _mxm_lock:
        if _mxm_tok["token"] and _mxm_tok["exp"] > time.time():
            return _mxm_tok["token"]
        for _ in range(3):
            try:
                tk = _mxm_fetch_token()
            except Exception:
                tk = None
            if tk and len(tk) > 20:
                _mxm_tok.update(token=tk, exp=time.time() + 600)
                try:
                    _atomic_write_json(_MXM_TOKEN_FILE, {"token": tk})
                except Exception:
                    pass
                return tk
            time.sleep(0.8)
        if not _mxm_tok["token"]:  # last resort: a token persisted from a prior run
            try:
                with open(_MXM_TOKEN_FILE) as f:
                    _mxm_tok["token"] = json.load(f).get("token")
                    _mxm_tok["exp"] = time.time() + 120
            except Exception:
                pass
        return _mxm_tok["token"]


def _mxm_call(path, timeout=5, **params):
    tok = _mxm_token()
    if not tok:
        return None
    params.update(app_id="web-desktop-app-v1.0", usertoken=tok, format="json")
    _, txt = _http(_MXM_BASE + path + "?" + urllib.parse.urlencode(params), headers=_MXM_HDRS, timeout=timeout)
    return json.loads(txt)


# Title text that itself declares no sung lyrics. Deliberately narrow — excludes
# cover/remix/piano, which usually DO have vocals.
_INST_TITLE = re.compile(
    r"(instrumental|纯音乐|純音樂|伴奏|off[\s\-]?vocal|karaoke|卡拉\s*ok|消音|backing\s*track|\(inst\b|（inst)", re.I)


def _mxm_match_score(title, artist, duration, tr):
    """How well a Musixmatch track matches the query, independent of whether it has
    lyrics (so it can also score instrumental tracks)."""
    score = 0.0
    nt_w, nt_g = _norm_title(title), _norm_title(tr.get("track_name") or "")
    if nt_w and nt_g:
        if nt_w == nt_g:
            score += 45
        elif nt_w in nt_g or nt_g in nt_w:
            score += 10
        else:
            score -= 30
    aw, ag = _norm_words(artist), _norm_words(tr.get("artist_name") or "")
    if aw and ag:
        score += 18 if (aw & ag) else -6   # Apple often romanizes the artist
    d = tr.get("track_length") or 0
    if duration and d:
        score += max(-12, 24 - abs(float(d) - float(duration)) * 2)
    return score


def _mxm_score(title, artist, duration, tr):
    # For picking a lyrics-bearing track: must have synced lyrics, else match score.
    if not tr.get("has_subtitles"):
        return -1e9
    return _mxm_match_score(title, artist, duration, tr)


def musixmatch_probe(title, artist, duration=None):
    """One Musixmatch search -> ('synced', lrc) | ('instrumental', None) | ('none', None).
    Returns synced lyrics from the best lyric-bearing match; flags 'instrumental' only
    on a HIGH-confidence match (exact title + artist/duration) so a near-name miss
    (e.g. a different 'Summer') can't mislabel a real song as instrumental."""
    try:
        s = _mxm_call("track.search", q_track=title, q_artist=artist or "",
                      page_size=12, s_track_rating="desc")
    except Exception:
        return "none", None
    tl = (((s or {}).get("message") or {}).get("body") or {}).get("track_list") or []
    best_lyr, bl, best_match, bm = None, 0.0, None, 0.0
    for it in tl:
        tr = it.get("track") or {}
        sl = _mxm_score(title, artist, duration, tr)
        if sl > bl:
            bl, best_lyr = sl, tr
        sm = _mxm_match_score(title, artist, duration, tr)
        if sm > bm:
            bm, best_match = sm, tr
    if best_lyr and bl >= 35 and best_lyr.get("has_subtitles"):   # need exact title, or strong artist+duration — a bare substring match isn't enough
        try:
            sub = _mxm_call("track.subtitle.get", track_id=best_lyr["track_id"], subtitle_format="lrc")
            body = ((sub or {}).get("message") or {}).get("body")
            lrc = ((body or {}).get("subtitle") or {}).get("subtitle_body") if isinstance(body, dict) else ""
            if lrc and _TS.search(lrc):
                _record_pick("musixmatch", best_lyr.get("track_name"), best_lyr.get("artist_name"),
                             best_lyr.get("track_length"), best_lyr.get("track_id"))
                return "synced", lrc
        except Exception:
            pass
    if best_match and bm >= 40 and best_match.get("instrumental"):
        return "instrumental", None
    return "none", None


def fetch_musixmatch(title, artist, duration=None):
    kind, lrc = musixmatch_probe(title, artist, duration)
    return lrc if kind == "synced" else None


SOURCES = {"musixmatch": fetch_musixmatch, "lrclib": fetch_lrclib, "netease": fetch_netease,
           "kugou": fetch_kugou, "petitlyrics": fetch_petitlyrics, "plain": fetch_plain_fallback}


def _mxm_warmup():
    # Keep the first song from waiting on Musixmatch's slow token.get: optimistically
    # adopt the token persisted from a prior run, then refresh it in the background.
    try:
        with open(_MXM_TOKEN_FILE) as f:
            tk = json.load(f).get("token")
        if tk:
            _mxm_tok.update(token=tk, exp=time.time() + 45)
    except Exception:
        pass
    try:
        tk = _mxm_fetch_token()
        if tk and len(tk) > 20:
            _mxm_tok.update(token=tk, exp=time.time() + 600)
            _atomic_write_json(_MXM_TOKEN_FILE, {"token": tk})
    except Exception:
        pass


if os.environ.get("DISABLE_MXM_WARMUP") != "1":
    threading.Thread(target=_mxm_warmup, daemon=True).start()


def _override_source(title, artist):
    keys = [song_key(title, artist), f"{title or ''}|{_latin_key(artist)}".lower()]
    for k in keys:
        if k in _SONG_SOURCE_OVERRIDES:
            return _SONG_SOURCE_OVERRIDES[k]
    return None


def _duration_cache_bucket(duration):
    """Two-second buckets keep duration-sensitive matches isolated without churn."""
    try:
        return int(round(float(duration or 0) / 2.0) * 2)
    except (TypeError, ValueError):
        return 0


def get_lyrics(title, artist, duration, source):
    override = _override_source(title, artist) if source == "auto" else None
    if override:
        source = override
    if source == "plain":
        key = (song_key(title, artist), "plain", _duration_cache_bucket(duration))
        cached = _lyrics_cache.get(key)
        if cached is not None:
            return source, cached
        try:
            raw = fetch_plain_fallback(title, artist, duration)
        except Exception:
            raw = None
        if raw:
            lines = parse_lrc(raw)
            if usable_lyrics(lines):
                _lyrics_cache[key] = lines
                return source, lines
        return None, []
    if ":" in source:
        name, sid = source.split(":", 1)
        key = (song_key(title, artist), source)
        cached = _lyrics_cache.get(key)
        if cached is not None:
            return source, cached
        try:
            raw = (fetch_lrclib_id(sid) if name == "lrclib" else
                   fetch_netease_id(sid) if name == "netease" else
                   fetch_kugou_id(sid) if name == "kugou" else
                   fetch_petitlyrics_id(sid) if name == "petitlyrics" else None)
        except Exception:
            raw = None
        if raw:
            lines = parse_lrc(raw)
            if usable_lyrics(lines):
                _lyrics_cache[key] = lines
                return source, lines
        return None, []
    # chosen source first, then always fall back to the others until one hits
    base = ["plain", "musixmatch", "lrclib", "netease", "kugou"] if _latin_key(title) in _PLAIN_LYRIC_URLS else ["musixmatch", "lrclib", "petitlyrics", "netease", "kugou", "plain"]
    order = ([source] + [s for s in base if s != source]) if source in SOURCES else base
    sk = (song_key(title, artist), _duration_cache_bucket(duration))
    cached = _auto_cache.get(sk) if source == "auto" else None
    if cached is not None:   # replay of an already-resolved song -> instant
        return cached
    rest = [s for s in order if s != "musixmatch"]   # Musixmatch handled by the probe below

    def probe(qt, qa):
        # Musixmatch only: synced lyrics, a fast 'instrumental' verdict, or nothing.
        kind, lrc = musixmatch_probe(qt, qa, duration)
        if kind == "synced":
            ls = parse_lrc(lrc)
            if usable_lyrics(ls):
                return "musixmatch", ls, False
        return ("instrumental", [], True) if kind == "instrumental" else (None, [], False)

    def done(used, lines, inst):
        if source == "auto":
            _auto_cache[sk] = ("instrumental", []) if inst else (used, lines)
        return ("instrumental", []) if inst else (used, lines)

    # Fast path: the title itself declares it's instrumental / off-vocal.
    if title and _INST_TITLE.search(title):
        return done(None, [], True)
    # 1) Musixmatch on the raw Apple metadata — covers English songs, many translated
    #    ones, and the instrumental verdict.
    used, lines, inst = probe(title, artist)
    if not inst and not lines:
        natives = recover_native_meta(title, artist, duration)[:2] if (title and not has_cjk(title) and duration) else []
        if natives:
            # 2a) Apple romanized/translated a CJK title -> try the recovered name(s).
            #     Skip the wasted other-source pass on the (useless) translated title.
            for nt, na in natives:
                used, lines, inst = probe(nt, na)
                if inst or lines:
                    break
                u, ls = _try_sources(nt, na, duration, rest)
                if ls:
                    used, lines = u, ls
                    break
        else:
            # 2b) No native recovery (English / Japanese-romaji / CJK title): other sources.
            used, lines = _try_sources(title, artist, duration, rest)
    if inst or lines:
        return done(used, lines, inst)
    return None, []


# ---------------- Japanese furigana (ruby) -------------------------------------
# A real morphological analyzer (fugashi + unidic-lite) so kanji get their
# context-correct kun/on reading (君->きみ, not くん). Katakana words are annotated
# with their hiragana equivalent per request; pure-hiragana / latin / digit tokens
# are left untouched. Only run on tracks that actually contain kana, so Chinese
# (hanzi-only) lyrics are never mis-annotated with Japanese readings.
try:
    import fugashi
    _tagger = fugashi.Tagger()
except Exception:
    _tagger = None
_furi_lock = threading.Lock()

_KANA = re.compile(r"[぀-ヿㇰ-ㇿｦ-ﾟ]")
_KANJI = re.compile(r"[㐀-䶿一-鿿豈-﫿々〆〇]")
_KATAKANA = re.compile(r"[ァ-ヺヽヾㇰ-ㇿｦ-ﾝ]")


def has_kana(s):
    return bool(_KANA.search(s or ""))


def _kata_to_hira(s):
    out = []
    for ch in s or "":
        o = ord(ch)
        out.append(chr(o - 0x60) if 0x30A1 <= o <= 0x30F6 else ch)
    return "".join(out)


def _is_kana_ch(ch):
    o = ord(ch)
    return 0x3040 <= o <= 0x309F or 0x30A0 <= o <= 0x30FF


def _ruby(base, rt):
    return "<ruby>" + html.escape(base) + "<rt>" + html.escape(rt) + "</rt></ruby>"


def _furi_word(surface, reading):
    """reading = hiragana reading of the whole surface (may be empty)."""
    has_kanji = bool(_KANJI.search(surface))
    has_kata = bool(_KATAKANA.search(surface))
    if not has_kanji and not has_kata:
        return html.escape(surface)              # kana / latin / digits / symbols
    if not has_kanji:                            # pure katakana -> hiragana above
        return _ruby(surface, _kata_to_hira(surface))
    if not reading:
        return html.escape(surface)
    s, r = surface, reading
    # strip a shared trailing kana run (okurigana) so ruby covers only the kanji
    i = 0
    while i < len(s) and i < len(r) and _is_kana_ch(s[-1 - i]) and s[-1 - i] == r[-1 - i]:
        i += 1
    suf = s[len(s) - i:] if i else ""
    if i:
        s, r = s[:len(s) - i], r[:len(r) - i]
    # ...and a shared leading kana run (rare prefixes)
    j = 0
    while j < len(s) and j < len(r) and _is_kana_ch(s[j]) and s[j] == r[j]:
        j += 1
    pre, s, r = s[:j], s[j:], r[j:]
    if not s:
        return html.escape(surface)
    return html.escape(pre) + _ruby(s, r) + html.escape(suf)


def furigana_line(text):
    """Ruby-annotated HTML for one line, or None if nothing needed annotating."""
    if not _tagger or not text:
        return None
    res, pos, changed = [], 0, False
    with _furi_lock:
        words = list(_tagger(text))
    for w in words:
        surf = w.surface
        if not surf:
            continue
        idx = text.find(surf, pos)
        if idx > pos:                            # preserve spaces / dropped gaps
            res.append(html.escape(text[pos:idx]))
        if idx >= 0:
            pos = idx + len(surf)
        kana = getattr(w.feature, "kana", None)
        reading = _kata_to_hira(kana) if kana else ""
        frag = _furi_word(surf, reading)
        if "<ruby" in frag:
            changed = True
        res.append(frag)
    if pos < len(text):
        res.append(html.escape(text[pos:]))
    return "".join(res) if changed else None


def furigana_lines(lines):
    """Per-line ruby HTML (aligned to lines), or None for non-Japanese tracks."""
    if not _tagger or not any(has_kana(t) for _, t in lines):
        return None
    return [furigana_line(t) for _, t in lines]


# ---------------- Translation (Google gtx endpoint, batched + cached) ----------
_GT_HDRS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
_trans_cache = BoundedTTLCache(256, 6 * 3600)
_trans_lock = threading.Lock()


def _gt_batch(texts, tl):
    payload = urllib.parse.urlencode({"q": "\n".join(texts)}).encode("utf-8")
    url = ("https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl="
           + urllib.parse.quote(tl) + "&dt=t")
    headers = dict(_GT_HDRS, **{"Content-Type": "application/x-www-form-urlencoded"})
    _, txt = _http(url, data=payload, headers=headers, timeout=6)
    segs = json.loads(txt)[0] or []
    joined = "".join(s[0] for s in segs if s and s[0])
    return joined.split("\n")


def is_chinese_lyrics(texts):
    """True for all-Han, no-kana lyrics: a Chinese track. Translating those to a
    Chinese target just reproduces the original (the "double subtitle" the user
    sees), so we skip translation for them entirely. Any kana => Japanese, which
    we DO translate (every line, including pure-kanji ones)."""
    return (not any(has_kana(t) for t in texts)
            and any(_KANJI.search(t or "") for t in texts))


def _translate_raw(texts, tl):
    """Translate in bounded batches with a strict total network-call budget."""
    calls = 0

    def translate_chunk(chunk):
        nonlocal calls
        if not chunk or calls >= MAX_TRANSLATE_NETWORK_CALLS:
            return ["" for _ in chunk]
        calls += 1
        try:
            got = _gt_batch(chunk, tl)
        except Exception:
            got = []
        if len(got) == len(chunk):
            return got
        # Split a misaligned batch only while budget remains. This preserves exact
        # alignment without the former worst case of 300 serial 12-second calls.
        if len(chunk) <= 1 or calls >= MAX_TRANSLATE_NETWORK_CALLS:
            return ["" for _ in chunk]
        mid = len(chunk) // 2
        return translate_chunk(chunk[:mid]) + translate_chunk(chunk[mid:])

    out = []
    for i in range(0, len(texts), 40):
        out.extend(translate_chunk(texts[i:i + 40]))
    return out


def translate_lines(texts, tl="zh-CN"):
    """Translate lines -> `tl`, preserving 1:1 alignment with the input. Lyrics
    already in the target language are returned blank so the page shows no
    near-identical second subtitle."""
    if tl.lower().startswith("zh") and is_chinese_lyrics(texts):
        return ["" for _ in texts]
    out = ["" for _ in texts]
    todo = [i for i, t in enumerate(texts) if t.strip()]
    if todo:
        got = _translate_raw([texts[i] for i in todo], tl)
        for i, g in zip(todo, got):
            out[i] = g
    return out


def candidate_identity_matches_query(title, artist, duration, candidate):
    """Keep loose provider rows from showing lyrics for a different song.

    A provider search can return a perfectly lyric-bearing but unrelated song
    by the same/near title. Usability alone is not enough for the picker: the row
    must also match the queried track identity.
    """
    source = candidate.get("source") or (candidate.get("id") or "").split(":", 1)[0]
    if source not in {"netease", "kugou", "petitlyrics"}:
        return True
    return _match_ok(title, artist, duration, candidate.get("title") or "",
                     candidate.get("artist") or "", candidate.get("duration") or 0,
                     artist_query_aliases(artist))


def candidate_has_usable_lyrics(candidate):
    """Return True only when a source-picker candidate can actually serve lyrics.

    Search APIs often return a high-confidence song metadata match even when the
    provider has no usable lyric body for that ID (for example NetEase returning
    only 作词/作曲 credit lines). Hide those rows from the picker so "相关度 80"
    doesn't look like a lyric match that then fails after clicking.
    """
    cid = candidate.get("id") or ""
    if not cid or ":" not in cid:
        return False
    sentinel = object()
    cached = _candidate_usable_cache.get(cid, sentinel)
    if cached is not sentinel:
        return cached
    name, sid = cid.split(":", 1)
    try:
        raw = (fetch_lrclib_id(sid) if name == "lrclib" else
               fetch_netease_id(sid) if name == "netease" else
               fetch_kugou_id(sid) if name == "kugou" else
               fetch_petitlyrics_id(sid) if name == "petitlyrics" else None)
        ok = bool(raw and usable_lyrics(parse_lrc(raw)))
    except Exception:
        # A provider timeout is not evidence that lyrics do not exist. Do not
        # turn a transient failure into a six-hour negative cache entry.
        return False
    _candidate_usable_cache[cid] = ok
    return ok


@app.route("/api/candidates")
@_limit_expensive
def api_candidates():
    parsed = _song_query()
    if parsed is None:
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    title, artist, duration = parsed
    cand = []
    seen = set()
    natives = recover_native_meta(title, artist, duration)
    # For Apple Music's English/pinyin metadata, the original title often only
    # returns covers or irrelevant tracks. Once the native title+artist are known,
    # search candidates with those directly to keep the panel responsive.
    query_pairs = [(nt, na, 3) for nt, na in natives] + [(title, artist, 0)]
    for qtitle, qartist, penalty in query_pairs:
        # KuGou is a Chinese-only catalog and slow on Latin queries — skip it there.
        fns = (search_lrclib, search_petitlyrics, search_netease, search_kugou) if has_cjk(qtitle) else (search_lrclib, search_petitlyrics, search_netease)
        for fn in fns:
            try:
                for c in fn(qtitle, qartist, duration, limit=5):
                    cid = c.get("id")
                    if not cid or cid in seen:
                        continue
                    seen.add(cid)
                    if not candidate_identity_matches_query(qtitle, qartist, duration, c):
                        continue
                    if not candidate_has_usable_lyrics(c):
                        continue
                    if qtitle != title:
                        c["album"] = ((c.get("album") or "") + f" · 原名匹配: {qtitle}").strip(" ·")
                        c["score"] = max(0, int(c.get("score") or 0) - penalty)
                    cand.append(c)
            except Exception:
                pass
    cand.sort(key=lambda x: x.get("score", 0), reverse=True)
    return jsonify({"ok": True, "candidates": cand[:12], "aliases": [nt for nt, _ in natives]})


@app.route("/api/lyrics")
@_limit_expensive
def api_lyrics():
    parsed = _song_query(include_source=True)
    if parsed is None:
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    title, artist, duration, source = parsed
    used, lines = get_lyrics(title, artist, duration, source)
    # `translatable` is False for Chinese lyrics under a Chinese target: the UI
    # hides the 翻译 button there, since translating would only duplicate them.
    translatable = bool(lines) and not (
        TRANSLATE_TARGET_LANG.lower().startswith("zh")
        and is_chinese_lyrics([t for _, t in lines]))
    return jsonify({"ok": True, "found": bool(lines), "instrumental": used == "instrumental",
                    "source": used, "lines": lines, "translatable": translatable,
                    "furigana": furigana_lines(lines) if lines else None})


@app.route("/api/translate", methods=["POST"])
@_limit_expensive
def api_translate():
    """Translate the current lyric lines (default -> Simplified Chinese)."""
    if not request.is_json:
        return jsonify({"ok": False, "error": "json_required"}), 415
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("lines", []), list):
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    raw_lines = body.get("lines") or []
    if (len(raw_lines) > MAX_TRANSLATE_LINES
            or any(not isinstance(x, str) or len(x) > MAX_TRANSLATE_LINE_CHARS for x in raw_lines)):
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    lines = list(raw_lines)
    if sum(len(x) for x in lines) > MAX_TRANSLATE_CHARS:
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    tl = body.get("tl") or TRANSLATE_TARGET_LANG
    if (not isinstance(tl, str) or not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z]{2,8})?", tl)
            or tl.lower() != TRANSLATE_TARGET_LANG.lower()):
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    if not lines:
        return jsonify({"ok": True, "trans": []})
    digest = hashlib.sha256(json.dumps(lines, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    key = (tl.lower(), digest)
    with _trans_lock:
        cached = _trans_cache.get(key)
    if cached is not None and len(cached) == len(lines):
        return jsonify({"ok": True, "trans": cached, "cached": True})
    trans = translate_lines(lines, tl)
    # Cache only complete results. Provider timeouts/misaligned batches produce
    # blanks for non-empty source lines; caching those would preserve a transient
    # Google failure for six hours.
    complete = all(not source.strip() or bool(target.strip())
                   for source, target in zip(lines, trans))
    if complete:
        with _trans_lock:
            _trans_cache[key] = trans
    return jsonify({"ok": True, "trans": trans})


# ---------------- Per-song prefs (source + offset), saved only when adjusted ----
def _load_prefs():
    try:
        with open(PREFS_FILE) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_prefs(d):
    _atomic_write_json(PREFS_FILE, d)


@app.route("/api/prefs", methods=["GET", "POST"])
def api_prefs():
    if request.method == "GET":
        title = request.args.get("title", "")
        artist = request.args.get("artist", "")
        if len(title) > MAX_TITLE_CHARS or len(artist) > MAX_ARTIST_CHARS:
            return jsonify({"ok": False, "error": "invalid_input"}), 400
        key = song_key(title, artist)
        p = _load_prefs().get(key) or {}
        return jsonify({"source": p.get("source", "auto"), "offset": p.get("offset", 0)})
    if not request.is_json:
        return jsonify({"ok": False, "error": "json_required"}), 415
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    title, artist = body.get("title", ""), body.get("artist", "")
    src = body.get("source", "auto")
    try:
        off = round(float(body.get("offset", 0)), 1)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    if (not isinstance(title, str) or not isinstance(artist, str)
            or len(title) > MAX_TITLE_CHARS or len(artist) > MAX_ARTIST_CHARS
            or not _valid_source(src) or not math.isfinite(off) or off < -10 or off > 10):
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    key = song_key(title, artist)
    if not key.strip("|"):
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    with _prefs_lock:
        prefs = _load_prefs()
        if src == "auto" and off == 0:
            prefs.pop(key, None)          # reset to default -> drop the record
        else:
            prefs.pop(key, None)          # move updated record to newest position
            prefs[key] = {"source": src, "offset": off}
            while len(prefs) > MAX_PREFS_ENTRIES:
                prefs.pop(next(iter(prefs)))
        _write_prefs(prefs)
    return jsonify({"ok": True})


@app.route("/api/report", methods=["POST"])
def api_report():
    """User-reported lyric problem; appended as one JSON line to REPORTS_FILE."""
    if not request.is_json:
        return jsonify({"ok": False, "error": "json_required"}), 415
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    title, artist = body.get("title", ""), body.get("artist", "")
    source, note = body.get("source", ""), body.get("note", "")
    if (not all(isinstance(x, str) for x in (title, artist, source, note))
            or len(title) > MAX_TITLE_CHARS or len(artist) > MAX_ARTIST_CHARS
            or len(source) > MAX_SOURCE_CHARS or len(note) > MAX_REPORT_NOTE_CHARS):
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    for key, low, high in (("duration", 0, MAX_DURATION_SECONDS),
                           ("offset", -10, 10), ("lineCount", 0, 10000)):
        value = body.get(key)
        if value is not None:
            try:
                value = float(value)
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "invalid_input"}), 400
            if not math.isfinite(value) or value < low or value > high:
                return jsonify({"ok": False, "error": "invalid_input"}), 400
    if body.get("found") is not None and not isinstance(body.get("found"), bool):
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    # Reports are local listening-history records and intentionally omit client
    # and network identifiers.
    rec = {"ts": round(time.time()), "when": time.strftime("%Y-%m-%d %H:%M:%S")}
    for k in ("title", "artist", "duration", "source", "found", "lineCount", "offset", "note"):
        rec[k] = body.get(k)
    try:
        encoded = json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n"
        with _reports_lock:
            current_size = os.path.getsize(REPORTS_FILE) if os.path.exists(REPORTS_FILE) else 0
            if current_size + len(encoded.encode()) > MAX_REPORT_BYTES:
                rotated = REPORTS_FILE + ".1"
                if os.path.exists(rotated):
                    os.unlink(rotated)
                if os.path.exists(REPORTS_FILE):
                    os.replace(REPORTS_FILE, rotated)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(REPORTS_FILE, flags, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(encoded)
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        app.logger.exception("report write failed")
        return jsonify({"ok": False, "error": "storage_unavailable"}), 500
    return jsonify({"ok": True})


@app.route("/healthz")
def healthz():
    return "ok"


@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<title>正在播放</title>
<style>
/* Shares its look with the in-car menu (tesla.lyp04.com): same background, surfaces and
   touch sizes. Controls are sized for a car touchscreen (48px targets). */
:root{color-scheme:light dark; --accent:#1db954;
 --fg:#f3f5f8; --dim:#8d95a3; --bg:#07090d; --page-bg:radial-gradient(120% 90% at 50% -10%,#151a24 0%,var(--bg) 62%);
 --line:#5b616a; --line-cur:#fff; --panel:rgba(255,255,255,.05); --panel-border:rgba(255,255,255,.09); --bar-bg:rgba(255,255,255,.08);
 --seg-bg:rgba(255,255,255,.06); --button-bg:rgba(255,255,255,.06); --button-border:rgba(255,255,255,.12); --button-active:rgba(255,255,255,.14); --active-fg:#06210f; --note:#4a4f57; --label:#8d95a3;
 --pop-bg:#11151c; --ring:#7cc4ff}
@media (prefers-color-scheme: light){:root{color-scheme:light; --fg:#10141b; --dim:#5b6472; --bg:#eef1f6; --page-bg:radial-gradient(120% 90% at 50% -10%,#fff 0%,var(--bg) 62%);
 --line:#a2a9b3; --line-cur:#0d1117; --panel:rgba(0,0,0,.04); --panel-border:rgba(0,0,0,.08); --bar-bg:rgba(0,0,0,.08);
 --seg-bg:rgba(0,0,0,.055); --button-bg:rgba(0,0,0,.04); --button-border:rgba(0,0,0,.12); --button-active:rgba(0,0,0,.10); --active-fg:#fff; --note:#7a828d; --label:#5b6472;
 --pop-bg:#fff; --ring:#1d6fd6}}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html,body{height:100%}
body{background:var(--page-bg);color:var(--fg);
 font-family:-apple-system,"PingFang SC","Microsoft YaHei","Noto Sans CJK SC",system-ui,sans-serif;
 display:flex;flex-direction:column;overflow:hidden}
#hdr{padding:14px 22px 8px;text-align:center;flex:0 0 auto}
/* song title / artist / album are intentionally hidden from the top of the page
   (still available in the 「歌词信息」 popup); only the progress bar stays up top. */
#title,#meta,#realsrc{display:none}
#bar{height:4px;background:var(--bar-bg);border-radius:4px;margin:14px 32px 0;overflow:hidden}
#barfill{height:100%;width:0;background:var(--accent);border-radius:4px;transition:width .25s linear}
#lyrics{flex:1 1 auto;overflow:hidden;position:relative;
 -webkit-mask-image:linear-gradient(transparent,#000 16%,#000 76%,transparent);
 mask-image:linear-gradient(transparent,#000 16%,#000 76%,transparent)}
#scroll{position:absolute;left:0;right:0;top:50%;transition:transform .5s cubic-bezier(.22,.7,.16,1);will-change:transform}
.ln{padding:12px 48px;text-align:left;font-size:clamp(30px,8vw,48px);color:var(--line);line-height:1.25;font-weight:700;
 transition:color .28s,opacity .28s,transform .28s;opacity:.5;transform-origin:left center}
.ln.cur{color:var(--line-cur);opacity:1;transform:scale(1.04)}
#hint{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;text-align:center;
 color:var(--dim);font-size:20px;padding:30px}
#ctl{flex:0 0 auto;position:relative;display:flex;align-items:center;justify-content:center;gap:16px;
 padding:14px 24px calc(14px + env(safe-area-inset-bottom));background:var(--panel);
 border-top:1px solid var(--panel-border);font-size:16px;color:var(--dim);flex-wrap:wrap;min-height:76px}
button,#home{font:inherit}
button:focus-visible,#home:focus-visible{outline:3px solid var(--ring);outline-offset:2px}
#home{position:absolute;left:20px;top:50%;transform:translateY(-50%);display:inline-flex;align-items:center;gap:8px;
 height:48px;padding:0 18px 0 12px;border-radius:14px;border:1px solid var(--button-border);background:var(--button-bg);
 color:var(--fg);text-decoration:none;font-size:16px;font-weight:600}
#home svg{width:24px;height:24px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
#home:active{background:var(--button-active)}
.seg{display:inline-flex;background:var(--seg-bg);border-radius:14px;overflow:hidden}
.seg button{background:none;border:0;color:var(--dim);min-height:48px;padding:0 16px;font-size:16px;cursor:pointer}
.seg button.on{background:var(--accent);color:var(--active-fg);font-weight:700}
.info{position:relative;display:inline-flex}
.info button{border:1px solid var(--button-border);border-radius:14px;background:var(--button-bg);color:var(--fg);
 min-height:48px;padding:0 20px;font-size:16px;font-weight:600;cursor:pointer;min-width:128px;text-align:center}
.info button:active{background:var(--button-active)}
#infopanel,#srcpanel{display:none;position:absolute;left:0;bottom:60px;min-width:280px;max-width:min(400px,92vw);z-index:4;
 max-height:min(76vh,600px);
 padding:16px 18px;border:1px solid var(--panel-border);border-radius:18px;background:var(--pop-bg);color:var(--fg);
 box-shadow:0 18px 48px rgba(0,0,0,.4);font-size:16px;line-height:1.6;text-align:left}
#infopanel.show,#srcpanel.show{display:flex;flex-direction:column}
#infohead{flex:0 0 auto}
/* filter chips sit on their own line(s) above the list, free to wrap to two rows */
#candbar{flex:0 0 auto;margin-bottom:10px}
#candbar b{display:block;margin-bottom:8px}
#candfilter{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.fchip{border:1px solid var(--button-border);background:var(--button-bg);color:var(--dim);border-radius:12px;
 min-height:44px;padding:0 12px;font-size:15px;cursor:pointer;line-height:1.3;text-align:center}
.fchip.on{background:var(--accent);color:var(--active-fg);border-color:var(--accent);font-weight:700}
/* candidate list: scrollable SINGLE column (full-width rows so info isn't cut off) */
#candwrap{flex:1 1 auto;overflow-y:auto;-webkit-overflow-scrolling:touch;min-height:38px}
#candwrap .status{padding:6px 2px}
#reportbtn{flex:0 0 auto;margin-top:12px;width:100%;border:1px solid var(--button-border);background:var(--button-bg);
 color:var(--fg);border-radius:14px;min-height:48px;padding:0 12px;font-size:16px;cursor:pointer}
#reportbtn:active{background:var(--button-active)}
#reportmsg{flex:0 0 auto;margin-top:6px;color:var(--dim);font-size:13px;text-align:center;min-height:14px}
#infopanel .dim,#srcpanel .dim{color:var(--dim)}
.cand{display:block;width:100%;margin:8px 0 0;padding:12px 14px;border:1px solid var(--button-border);border-radius:14px;
 background:var(--button-bg);color:var(--fg);text-align:left;font-size:15px;line-height:1.45;cursor:pointer;word-break:break-word}
.cand.on{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.cand:active{background:var(--button-active)}
.step{display:inline-flex;align-items:center;gap:10px}
.step button{width:48px;height:48px;border-radius:50%;border:1px solid var(--button-border);
 background:var(--button-bg);color:var(--fg);font-size:24px;cursor:pointer;line-height:1}
.step button:active{background:var(--button-active)}
#off{min-width:60px;text-align:center;font-variant-numeric:tabular-nums;color:var(--fg)}
.lbl{color:var(--label);font-size:14px}
/* furigana ruby + per-line translation rendered inside each .ln */
.ln ruby{ruby-position:over;-webkit-ruby-position:over;ruby-align:center}
.ln rt{font-size:.4em;font-weight:600;color:var(--dim);line-height:1.05;letter-spacing:.01em;
 -webkit-user-select:none;user-select:none}
.ln .tr{display:block;margin-top:7px;font-size:.46em;font-weight:600;color:var(--dim);line-height:1.25;opacity:.92}
.tgl{border:1px solid var(--button-border);border-radius:14px;background:var(--button-bg);color:var(--fg);
 min-height:48px;padding:0 20px;font-size:16px;font-weight:600;cursor:pointer}
.tgl.on{background:var(--accent);color:var(--active-fg);border-color:var(--accent);font-weight:700}
.tgl:disabled{opacity:.45;cursor:default}
.tgl:active{background:var(--button-active)}
@media (max-width:900px){#home span{display:none}#home{padding:0 12px}}
</style></head>
<body>
<div id="hdr"><div id="title">—</div><div id="meta"></div><div id="bar"><div id="barfill"></div></div></div>
<div id="lyrics"><div id="scroll"></div><div id="hint">等待车辆播放音乐…</div></div>
<div id="ctl">
  <a id="home" href="/" aria-label="返回菜单"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg><span>菜单</span></a>
  <span class="info">
    <button id="infobtn">歌词信息</button>
    <span id="infopanel"></span>
  </span>
  <span class="info">
    <button id="srcbtn">可选歌词源</button>
    <span id="srcpanel"></span>
  </span>
  <button id="trbtn" class="tgl" style="display:none">翻译</button>
  <span class="step"><span class="lbl">微调</span>
    <button id="om">−</button><span id="off">0.0s</span><button id="op">+</button>
  </span>
</div>
<script>
const STEP = 0.5, LEAD = 0.6, SEEK_BACK_S = 5.0;
// LEAD compensates normal display latency. Smaller backward clock corrections
// are accepted, but the visible lyric line waits for playback to catch up.
const QS = new URLSearchParams(location.search);
const MOCK = QS.has("mock");
const MOCK_ENGLISH = QS.has("eng");
const MOCK_STARTED_AT = performance.now()/1000;
const MOCK_DURATION = 270;
const MOCK_LINES = [[5,"示例歌词第一行"],[11,"示例歌词第二行"],[17,"A neutral demo lyric"],[23,"タイミング表示のサンプル"],[31,"示例歌词第五行"],[37,"Another placeholder line"],[45,"仅用于界面与同步测试"],[51,"No real song text is bundled"]];
let st=null, base={elapsed:0,at:0,playing:false};
let lyrics=[], curKey="", curIdx=-1;
let allowLyricRewind=false, lastStateTs=NaN, pollRequestId=0, stateFailures=0;
let songGeneration=0, lyricRequestId=0, candidateRequestId=0, translationRequestId=0;
let furigana=[], translations=[], showTrans=false, transLoading=false, transKey="";
let curTitle="", curArtist="", curSource="auto", curOffset=0;
let lyricInfo={source:"—",found:false,lineCount:0,duration:0,title:"",artist:"",album:""};
let candidates=[], candLoaded=false, candLoading=false, candError=false, candFilter="all";
const $=id=>document.getElementById(id);
const keyOf=d=>(d.title||"")+"|"+(d.artist||"");
const prefStorageKey=(title,artist)=>"tesla-nowplaying:prefs:v1:"+(title||"").trim().toLowerCase()+"|"+(artist||"").trim().toLowerCase();

// Consecutive failed state polls tolerated before the page mentions it.
const STATE_FAIL_HINT_AFTER=4;
// Every endpoint answers with JSON, so a non-2xx body is something else entirely:
// a proxy error page, a rate-limit page, or a redirect to a login form. Reject it
// here instead of letting response.json() throw inside a caller that only meant to
// shrug off malformed data.
async function getJSON(url,opts){
  const r=await fetch(url,opts);
  if(!r.ok) throw new Error("HTTP "+r.status);
  return r.json();
}
function readLocalPref(title,artist){
  try{ const p=JSON.parse(localStorage.getItem(prefStorageKey(title,artist))||"null");
    if(p && typeof p.source==="string" && Number.isFinite(+p.offset)) return {source:p.source,offset:Math.max(-10,Math.min(10,+p.offset))};
  }catch(e){} return null;
}
function writeLocalPref(title,artist,source,offset){
  try{ const k=prefStorageKey(title,artist); if(source==="auto" && +offset===0) localStorage.removeItem(k);
    else localStorage.setItem(k,JSON.stringify({source,offset:+offset||0})); }catch(e){}
}
const sourceName=s=>({musixmatch:"Musixmatch",lrclib:"LRCLIB",petitlyrics:"PetitLyrics",netease:"网易云",kugou:"酷狗",plain:"普通歌词",instrumental:"纯音乐",auto:"自动",mock:"Mock"}[(s||"").split(":")[0]]||s||"—");
function fmtTime(sec){ sec=Math.max(0,Math.round(+sec||0)); return Math.floor(sec/60)+":"+String(sec%60).padStart(2,"0"); }
function esc(s){ return String(s||"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }

function isStaleStateTimestamp(nextTs,previousTs){
  return Number.isFinite(nextTs) && Number.isFinite(previousTs) && nextTs<=previousTs;
}
function shouldAllowLyricRewind(projectedElapsed,incomingElapsed,threshold){
  return projectedElapsed-incomingElapsed>=threshold;
}
function lyricIndexFor(lines,lyricTime,currentIdx,allowBackward){
  let idx=-1;
  for(let i=0;i<lines.length;i++){ if(lines[i][0]<=lyricTime) idx=i; else break; }
  return (!allowBackward && idx<currentIdx) ? currentIdx : idx;
}
function clearCurrentSong(){
  songGeneration+=1; lyricRequestId+=1; candidateRequestId+=1;
  candLoading=false; candLoaded=false; candError=false; candFilter="all"; candidates=[]; renderCands();
  curKey=""; curTitle=""; curArtist=""; allowLyricRewind=false;
}

async function poll(){
  const requestId=++pollRequestId;
  try{
    const d = MOCK ? mockState() : await getJSON("api/state",{cache:"no-store"});
    if(requestId!==pollRequestId) return;
    stateFailures=0;
    if(d.ok && d.online){
      const now=performance.now()/1000, k=keyOf(d), sameSong=!!d.title && k===curKey;
      const incomingElapsed=typeof d.elapsed==="number" ? d.elapsed : NaN;
      const validElapsed=Number.isFinite(incomingElapsed) && incomingElapsed>=0;
      const nextStateTs=typeof d.ts==="number" ? d.ts : NaN;
      if(isStaleStateTimestamp(nextStateTs,lastStateTs)) return;
      const projectedElapsed=base.elapsed+(base.playing ? now-base.at : 0);
      st=d;
      const anchorElapsed=validElapsed ? incomingElapsed : (sameSong ? projectedElapsed : 0);
      if(sameSong && shouldAllowLyricRewind(projectedElapsed,anchorElapsed,SEEK_BACK_S))
        allowLyricRewind=true;
      base={elapsed:anchorElapsed,at:now,playing:!!d.playing};
      if(Number.isFinite(nextStateTs)) lastStateTs=nextStateTs;
      $("title").textContent = (MOCK ? "🧪 " : "") + (d.title || (d.status==="Stopped"?"未在播放":"—"));
      $("meta").textContent = [d.artist,d.album].filter(Boolean).join("  ·  ");
      lyricInfo={...lyricInfo,title:d.title||"",artist:d.artist||"",album:d.album||"",duration:d.duration||0}; updateInfo();
      if(d.title && k!==curKey){
        curKey=k; curTitle=d.title; curArtist=d.artist||"";
        const generation=++songGeneration;
        onNewSong(d,generation);
      }
      if(!d.title){ clearCurrentSong(); setLyrics([]); showHint("未在播放音乐"); }
    } else if(d.ok && !d.online){
      st=null; clearCurrentSong(); $("title").textContent="—"; $("meta").textContent=""; setLyrics([]);
      showHint("车辆休眠中 — 开始播放后自动显示");
    } else { showHint("读取失败: "+(d.error||"?")); }
  }catch(e){
    if(requestId!==pollRequestId) return;
    stateFailures+=1;
    // Say what went wrong rather than leaving the previous hint on screen. Before the
    // first successful poll that hint is the "waiting for playback" placeholder, which
    // reads as an idle car instead of a failing request. A blip or two is tolerated
    // first: lyrics keep scrolling on the local clock and there is nothing to act on.
    if(!st || stateFailures>=STATE_FAIL_HINT_AFTER) showHint("状态读取失败: "+((e&&e.message)||e));
  }
}

function mockState(){
  const elapsed = (performance.now()/1000 - MOCK_STARTED_AT) % MOCK_DURATION;
  return {ok:true,online:true,playing:true,status:"Playing",title:MOCK_ENGLISH?"Demo Song":"示例歌曲",artist:"示例歌手",album:"演示专辑",source:"Mock Player",elapsed,duration:MOCK_DURATION,ts:Date.now()/1000};
}

async function onNewSong(d,generation){
  candidateRequestId+=1;
  setLyrics([]); candidates=[]; candLoaded=false; candLoading=false; candFilter="all";
  renderCands(); showHint("加载歌词…");
  let p=readLocalPref(d.title,d.artist||"");
  if(!p){
    // One-time migration of the former server-side preference into this browser.
    try{ p=await getJSON("api/prefs?"+new URLSearchParams({title:d.title,artist:d.artist||""}),{cache:"no-store"});
      if(p && ((p.source||"auto")!=="auto" || (+p.offset||0)!==0)) writeLocalPref(d.title,d.artist||"",p.source||"auto",+p.offset||0);
    }catch(e){ p=null; }
  }
  if(generation!==songGeneration || keyOf(d)!==curKey) return;
  curSource = (p&&p.source)||"auto"; curOffset = +(p&&p.offset)||0;
  updateCtl();
  await loadLyrics();
  if(generation!==songGeneration || keyOf(d)!==curKey) return;
  // Candidate list resets on song change; refetch only if the source popup is open.
  renderCands();
  if($("srcpanel") && $("srcpanel").classList.contains("show")) loadCandidates();
}

async function loadCandidates(){
  if(!curTitle) return;
  const requestId=++candidateRequestId, generation=songGeneration, requestKey=curKey;
  const requestTitle=curTitle, requestArtist=curArtist||"";
  const requestDuration=Math.round((st&&st.duration)||0);
  candLoading=true; candLoaded=false; candError=false; renderCands();   // show "正在查找…" immediately
  let nextCandidates=[], nextCandError=false;
  try{
    const q=new URLSearchParams({title:requestTitle,artist:requestArtist,duration:requestDuration});
    const j = await getJSON("api/candidates?"+q,{cache:"no-store"});
    nextCandidates = (j.ok && j.candidates) ? j.candidates : [];
  }catch(e){ nextCandError=true; }
  if(requestId!==candidateRequestId || generation!==songGeneration || requestKey!==curKey) return;
  candidates=nextCandidates; candError=nextCandError;
  candLoading=false; candLoaded=true; renderCands();    // show results or "没有找到可选歌词"
}

async function loadLyrics(){
  const requestId=++lyricRequestId;
  const requestKey=curKey, requestTitle=curTitle, requestArtist=curArtist||"";
  const requestSource=curSource, requestDuration=Math.round((st&&st.duration)||0);
  if(MOCK){
    if(requestId!==lyricRequestId || requestKey!==curKey) return;
    lyricInfo={...lyricInfo,source:"mock",found:true,lineCount:MOCK_LINES.length,duration:MOCK_DURATION}; updateInfo();
    setLyrics(MOCK_LINES, null, true); $("realsrc").textContent="· Mock";
    if(showTrans) loadTranslations();
    return;
  }
  try{
    const q=new URLSearchParams({title:requestTitle,artist:requestArtist,duration:requestDuration,source:requestSource});
    const j = await getJSON("api/lyrics?"+q,{cache:"no-store"});
    if(requestId!==lyricRequestId || requestKey!==curKey || requestSource!==curSource) return;
    if(j.ok && j.found){
      lyricInfo={...lyricInfo,source:j.source||"—",found:true,lineCount:(j.lines||[]).length,duration:requestDuration}; updateInfo();
      setLyrics(j.lines, j.furigana, j.translatable); $("realsrc").textContent = j.source?("· "+sourceName(j.source)):"";
      if(showTrans && j.translatable!==false) loadTranslations();
    }
    else if(j.instrumental){ lyricInfo={...lyricInfo,source:"instrumental",found:false,lineCount:0,duration:requestDuration}; updateInfo(); setLyrics([]); showHint("🎵 纯音乐 · 无歌词"); $("realsrc").textContent="· 纯音乐"; }
    else { lyricInfo={...lyricInfo,source:"—",found:false,lineCount:0,duration:requestDuration}; updateInfo(); setLyrics([]); showHint("未找到这首歌的歌词"); $("realsrc").textContent=""; }
  }catch(e){
    if(requestId!==lyricRequestId || requestKey!==curKey || requestSource!==curSource) return;
    lyricInfo={...lyricInfo,source:"—",found:false,lineCount:0,duration:requestDuration}; updateInfo(); setLyrics([]); showHint("歌词加载失败");
  }
}

function showHint(t){ $("hint").textContent=t; $("hint").style.display="flex"; }
function setLyrics(lines, furi, translatable){
  translationRequestId+=1; transLoading=false;
  lyrics=lines||[]; furigana=furi||[]; translations=[]; transKey=""; curIdx=-1; allowLyricRewind=false;
  // Furigana is always shown when available (no toggle). The 翻译 button only
  // appears for tracks worth translating — Chinese lyrics report translatable=false.
  const tb=$("trbtn"); if(tb){ tb.style.display = (lyrics.length && translatable!==false) ? "" : "none";
    tb.textContent="翻译"; tb.classList.toggle("on", showTrans && lyrics.length>0); }
  const sc=$("scroll"); sc.innerHTML="";
  if(!lyrics.length) return;
  $("hint").style.display="none";
  renderLines();
}
// Rebuild #scroll from lyrics + (optional) furigana ruby + (optional) translation.
function renderLines(){
  const sc=$("scroll"); if(!sc) return;
  sc.innerHTML="";
  for(let i=0;i<lyrics.length;i++){
    const txt=lyrics[i][1];
    const e=document.createElement("div"); e.className="ln";
    const main=document.createElement("div"); main.className="main";
    if(furigana[i]) main.innerHTML=furigana[i];   // server-escaped ruby HTML (always on)
    else main.textContent = txt || "♪";
    e.appendChild(main);
    if(showTrans && translations[i]){
      const tr=document.createElement("div"); tr.className="tr"; tr.textContent=translations[i]; e.appendChild(tr);
    }
    sc.appendChild(e);
  }
  const n=sc.children;
  if(curIdx>=0 && n[curIdx]) n[curIdx].classList.add("cur");
  centerLine(curIdx>=0?curIdx:0);
}
async function loadTranslations(){
  if(!lyrics.length || transLoading) return;
  const requestId=++translationRequestId, generation=songGeneration, requestKey=curKey;
  const requestLines=lyrics.map(l=>l[1]||""), requestTitle=curTitle;
  const requestArtist=curArtist, requestSource=lyricInfo.source;
  transLoading=true; const b=$("trbtn"); if(b){ b.classList.add("on"); b.textContent="翻译中…"; }
  let nextTranslations=[];
  try{
    if(MOCK){ nextTranslations = requestLines.map(line=>"译: "+line); }
    else{
      const r = await getJSON("api/translate",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({lines:requestLines,title:requestTitle,artist:requestArtist,source:requestSource})});
      nextTranslations = (r.ok && r.trans) ? r.trans : [];
    }
  }catch(e){}
  if(requestId!==translationRequestId || generation!==songGeneration || requestKey!==curKey) return;
  translations=nextTranslations; transKey=requestKey;
  transLoading=false; if(b){ b.textContent="翻译"; b.classList.toggle("on", showTrans); }
  renderLines();
}

function centerLine(i){
  const n=$("scroll").children;
  if(i>=0 && n[i]) $("scroll").style.transform="translateY(-"+(n[i].offsetTop+n[i].offsetHeight/2)+"px)";
}

function tick(){
  if(st && lyrics.length){
    let el = base.elapsed + (base.playing ? performance.now()/1000-base.at : 0) - curOffset;
    if(st.duration) $("barfill").style.width = (100*Math.min(Math.max(el+curOffset,0),st.duration)/st.duration)+"%";
    const canRewind=allowLyricRewind; allowLyricRewind=false;
    const idx=lyricIndexFor(lyrics,el+LEAD,curIdx,canRewind);
    if(idx<0){
      const n=$("scroll").children;
      if(curIdx>=0&&n[curIdx]) n[curIdx].classList.remove("cur");
      curIdx=-1; centerLine(0);
    }
    else if(idx!==curIdx){
      const n=$("scroll").children;
      if(curIdx>=0&&n[curIdx]) n[curIdx].classList.remove("cur");
      if(idx>=0&&n[idx]){ n[idx].classList.add("cur"); $("scroll").style.transform="translateY(-"+(n[idx].offsetTop+n[idx].offsetHeight/2)+"px)"; }
      curIdx=idx;
    }
  }
  requestAnimationFrame(tick);
}

function updateCtl(){
  $("off").textContent = (curOffset>0?"+":"") + curOffset.toFixed(1) + "s";
  updateInfo();
}

function infoSkeleton(){
  if(!$("infopanel") || $("infohead")) return;
  $("infopanel").innerHTML = `<div id="infohead"></div>`;
}
function srcSkeleton(){
  if(!$("srcpanel") || $("candwrap")) return;
  $("srcpanel").innerHTML =
    `<div id="candbar"><b>歌词源</b><span id="candfilter"></span></div>`+
    `<div id="candwrap"><div class="dim status">展开以查找</div></div>`;
}

// match-info popup (#infopanel) — refreshed every poll
function updateInfo(){
  if(!$("infopanel")) return;
  infoSkeleton();
  const src = lyricInfo.found ? sourceName(lyricInfo.source) : (lyricInfo.source==="instrumental" ? "纯音乐" : "未匹配");
  const song = [lyricInfo.title, lyricInfo.artist].filter(Boolean).join(" — ") || "—";
  $("infohead").innerHTML =
    `<b>歌词匹配信息</b><br>`+
    `<span class="dim">歌词源：</span>${esc(src)}<br>`+
    `<span class="dim">歌曲：</span>${esc(song)}<br>`+
    `<span class="dim">专辑：</span>${esc(lyricInfo.album||'—')}<br>`+
    `<span class="dim">时长：</span>${fmtTime(lyricInfo.duration)}<br>`+
    `<span class="dim">歌词行数：</span>${lyricInfo.lineCount||0}<br>`+
    `<span class="dim">时间微调：</span>${(curOffset>0?"+":"") + curOffset.toFixed(1)}s`;
}

// candidate-source popup (#srcpanel) — rebuilt only on load/filter/select (NOT every
// poll) so the scroll position isn't reset; 2-column grid; per-source filter chips.
function renderCands(){
  if(!$("srcpanel")) return;
  srcSkeleton();
  if($("srcbtn")) $("srcbtn").textContent = "可选歌词源" + (candidates.length ? ` (${candidates.length})` : "");
  const srcs=[...new Set(candidates.map(c=>c.source))];
  if(candidates.length && srcs.length>1){
    const chip=(v,label)=>`<button class="fchip${candFilter===v?' on':''}" data-f="${esc(v)}">${esc(label)}</button>`;
    $("candfilter").innerHTML = chip("all","全部")+srcs.map(s=>chip(s,sourceName(s))).join("");
    for(const b of $("candfilter").querySelectorAll(".fchip")) b.onclick=(e)=>{ e.stopPropagation(); candFilter=b.dataset.f; renderCands(); };
  } else if($("candfilter")) $("candfilter").innerHTML="";
  const list = candidates.filter(c=>candFilter==="all"||c.source===candFilter);
  $("candwrap").innerHTML = list.length ? list.map(c=>
    `<button class="cand${curSource===c.id?' on':''}" data-id="${esc(c.id)}">`+
    `<b>${esc(sourceName(c.source))}</b> · ${esc(c.title||'—')}<br>`+
    `<span class="dim">${esc(c.artist||'—')} · ${esc(c.album||'—')} · ${fmtTime(c.duration)} · 相关度 ${esc(Number.isFinite(Number(c.score)) ? Number(c.score) : 0)}</span>`+
    `</button>`).join("")
    : candLoading ? `<div class="dim status">正在查找候选歌词…</div>`
    : candError ? `<div class="dim status">候选歌词加载失败</div>`
    : candLoaded ? `<div class="dim status">没有找到可选歌词</div>`
    : `<div class="dim status">展开以查找</div>`;
  for(const b of $("candwrap").querySelectorAll(".cand")) b.onclick=(e)=>{ e.stopPropagation(); selectCandidate(b.dataset.id); };
}

async function selectCandidate(id){
  if(!id || id==="mock") return;
  curSource=id; updateCtl(); savePrefs(); $("srcpanel").classList.remove("show"); showHint("加载选择的歌词…"); await loadLyrics();
}
function savePrefs(){
  if(curTitle) writeLocalPref(curTitle,curArtist,curSource,curOffset);
}
$("infobtn").onclick=()=>{ const show=$("infopanel").classList.toggle("show"); if(show){ if($("srcpanel"))$("srcpanel").classList.remove("show"); updateInfo(); } };
$("srcbtn").onclick=()=>{ const show=$("srcpanel").classList.toggle("show"); if(show){ if($("infopanel"))$("infopanel").classList.remove("show"); if(!candLoaded && !candLoading && curTitle) loadCandidates(); else renderCands(); } };
document.addEventListener("click",e=>{ if(!e.target.closest(".info")){ if($("infopanel"))$("infopanel").classList.remove("show"); if($("srcpanel"))$("srcpanel").classList.remove("show"); } });
$("om").onclick=()=>{ curOffset=Math.max(-10,Math.round((curOffset-STEP)*10)/10); allowLyricRewind=true; updateCtl(); savePrefs(); };
$("op").onclick=()=>{ curOffset=Math.min(10,Math.round((curOffset+STEP)*10)/10); allowLyricRewind=true; updateCtl(); savePrefs(); };
$("trbtn").onclick=()=>{ showTrans=!showTrans; $("trbtn").classList.toggle("on", showTrans);
  if(showTrans && (transKey!==curKey || !translations.length)) loadTranslations(); else renderLines(); };

// tiny "actual source" note appended to meta line
const rs=document.createElement("span"); rs.id="realsrc"; rs.style.cssText="color:var(--note);font-size:12px;margin-left:8px;"; $("meta").after(rs);

// Tesla in-car browser should expose the vehicle UI's day/night choice via prefers-color-scheme.
// Keep the document color-scheme live so built-in controls and address-bar chrome follow it too.
const themeMQ = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)");
function syncTheme(){ document.documentElement.style.colorScheme = themeMQ && themeMQ.matches ? "light" : "dark"; }
if(themeMQ){ syncTheme(); (themeMQ.addEventListener||themeMQ.addListener).call(themeMQ, "change", syncTheme); }

// --- Adaptive polling to minimise Fleet API (vehicle_data) calls. Lyrics scroll
// locally via tick(), so /api/state only needs refreshing to catch a song change
// or a pause. Poll densely only as the track nears its end (imminent switch),
// sparsely mid-track (still catches a manual skip within ~POLL_MID), and not at
// all while the page/tab is hidden. ---
const POLL_NEAR=3000, POLL_SOON=3000, POLL_MID=3000, POLL_IDLE=3000, NEAR_S=10, SOON_S=30;
let pollTimer=null;
function nextDelay(){
  if(document.hidden) return null;             // hidden: resume on visibilitychange
  if(!st || !base.playing) return POLL_IDLE;   // offline/asleep or paused: position frozen
  const el = base.elapsed + (performance.now()/1000 - base.at);
  const remain = (st.duration||0) - el;
  if(!st.duration) return POLL_MID;
  if(remain <= NEAR_S) return POLL_NEAR;       // about to switch (or already overran)
  if(remain <= SOON_S) return POLL_SOON;
  return POLL_MID;
}
function scheduleNext(){ clearTimeout(pollTimer); const d=nextDelay(); if(d!=null) pollTimer=setTimeout(runPoll,d); }
async function runPoll(){ await poll(); scheduleNext(); }
requestAnimationFrame(tick); runPoll();
document.addEventListener("visibilitychange",()=>{ if(document.hidden) clearTimeout(pollTimer); else runPoll(); });
</script></body></html>"""

if __name__ == "__main__":
    app.run(host=BIND_HOST, port=BIND_PORT)
