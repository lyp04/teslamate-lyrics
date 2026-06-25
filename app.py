#!/usr/bin/env python3
"""Tesla "now playing" + synced lyrics page.

Reads the car's currently-playing track from the Tesla Owner API (media_info)
and overlays time-synced lyrics from LRCLIB (primary) with NetEase fallback.
By default it reuses TeslaMate's encrypted Owner API access token from the
TeslaMate database without touching the refresh token. Per-song lyric
source + timing offset are remembered server-side (only when the user adjusts
them). Everything is browser-driven: no viewer open => no polling, no fetching.
Bound to 127.0.0.1, served behind nginx + admin SSO.
"""
import base64
import concurrent.futures
import hashlib
import html
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import urllib.error

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

_tok_lock = threading.Lock()
_prefs_lock = threading.Lock()
_state_lock = threading.Lock()
_access = {"token": None, "exp": 0}
_tm_access = {"token": None, "ts": 0.0}
_vin_cache = {"vin": FORCED_VIN or None}
_lyrics_cache = {}  # (key, source) -> list[[t,text]]
_candidate_usable_cache = {}  # candidate id -> bool, avoids re-checking source-picker rows
# Short-TTL cache for /api/state so bursts (scheduled poll + visibilitychange,
# extra tabs, retries) collapse into one Fleet API vehicle_data hit. The browser
# already advances lyrics locally, so a couple seconds of staleness is invisible.
_state_cache = {"data": None, "ts": 0.0}
STATE_TTL = float(_env("STATE_TTL", default="2.0"))

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


def _http(url, data=None, headers=None, timeout=15):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def song_key(title, artist):
    return (title or "").strip().lower() + "|" + (artist or "").strip().lower()


# ---------------- Tesla token + media ----------------
def _load_refresh():
    with open(TOKEN_FILE) as f:
        return json.load(f)["refresh_token"]


def _save_refresh(rt):
    tmp = TOKEN_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"refresh_token": rt}, f)
    os.replace(tmp, TOKEN_FILE)
    os.chmod(TOKEN_FILE, 0o600)


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


def get_vin(access):
    if _vin_cache["vin"]:
        return _vin_cache["vin"]
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
    with _state_lock:
        if _state_cache["data"] is not None and time.time() - _state_cache["ts"] < STATE_TTL:
            return jsonify(_state_cache["data"])
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
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 502


# ---------------- Lyrics (LRCLIB / NetEase) ----------------
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
_ARTIST_ALIASES = {
    "周杰伦": ["Jay Chou", "周杰倫"],
    "周杰倫": ["Jay Chou", "周杰伦"],
    "Jay Chou": ["周杰伦", "周杰倫"],
    "Accusefive": ["告五人"],
    "告五人": ["Accusefive"],
    "Joker Xue": ["薛之谦", "薛之謙"],
    "薛之谦": ["Joker Xue", "薛之謙"],
    "薛之謙": ["Joker Xue", "薛之谦"],
}
# Apple Music / Tesla metadata often reports Mandarin tracks under English
# translations or pinyin. Native title+artist are recovered generically at
# runtime from the iTunes catalog (see recover_native_meta) — no per-song table.
_PLAIN_LYRIC_URLS = {
    "who would you die for": "https://www.letras.mus.br/shiloh-dynasty/so-low",
    "so low": "https://www.letras.mus.br/shiloh-dynasty/so-low",
}
_SONG_SOURCE_OVERRIDES = {
    "紅|accusefive": "lrclib:9396506",
    "紅|告五人": "lrclib:9396506",
    "红|accusefive": "lrclib:9396506",
    "红|告五人": "lrclib:9396506",
    "天外来物|joker xue": "lrclib:16383350",
    "天外来物|薛之谦": "lrclib:16383350",
    "天外來物|joker xue": "lrclib:16383350",
    "天外來物|薛之謙": "lrclib:16383350",
    "who would you die for|lrn slime & shiloh dynasty": "plain",
    "who would you die for|lrn slime shiloh dynasty": "plain",
}


def parse_lrc(text):
    out = []
    for line in text.splitlines():
        stamps = _TS.findall(line)
        if not stamps:
            continue
        body = _TS.sub("", line).strip()
        if _META.match(line) and not body:
            continue
        if _CREDIT.match(body):
            continue
        if re.match(r"^.+\s+-\s+.+$", body) and int(stamps[0][0]) == 0:
            continue
        for mm, ss, fr in stamps:
            frac = float("0." + fr) if fr else 0.0
            out.append([round(int(mm) * 60 + int(ss) + frac, 2), body])
    out.sort(key=lambda x: x[0])
    return out


def usable_lyrics(lines):
    return len([txt for _, txt in (lines or []) if (txt or "").strip() and txt != "♪"]) >= 4


def make_approx_lrc(lines, duration=None):
    clean = [re.sub(r"\s+", " ", x or "").strip() for x in lines]
    clean = [x for x in clean if x]
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
    # Avoid applying this fallback to unrelated songs with the same generic title.
    if not url or (artist and "shiloh" not in artist.lower() and "lrn slime" not in artist.lower()):
        return None
    return fetch_letras_plain(url, duration)


def _t2s(s):
    if not s or not _zhconv:
        return s or ""
    try:
        return _zhconv(s, "zh-cn")
    except Exception:
        return s


# Katakana -> romaji, so a romanized Apple artist ("TsurushimaAnna") matches the
# native katakana one (ツルシマアンナ) on NetEase. Approximate but enough for matching.
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
    """Confidence gate for the loose sources (NetEase/KuGou): only trust a candidate's
    lyrics when its identity actually matches the query, so a same/similar-titled
    *popular* song can't be served for an obscure one. Duration is the romanization-
    robust anchor; a trad/simp-folded title OR an alias-aware artist match must
    corroborate it."""
    dd = abs(float(cd) - float(qd)) if (qd and cd) else None
    t = _title_match(qt, ct)
    a = _artist_match(qa, ca, aliases)
    if t and a:                                  # both identity signals agree
        return dd is None or dd <= 16
    if t and not a:                              # same title, different/unknown artist (a
        return dd is not None and dd <= 6        # generic title like "Collide") -> demand tight duration
    if a and not t:                              # same artist, cross-script title -> demand tight duration
        return dd is not None and dd <= 6
    return False


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


_artist_alias_cache = {}


def artist_query_aliases(artist):
    if artist in _artist_alias_cache:
        return _artist_alias_cache[artist]
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
_native_cache = {}
_auto_cache = {}  # song_key -> (source, lines) for resolved auto lookups (replay = instant)


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
    if ck in _native_cache:
        return _native_cache[ck]
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

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(order)))
    futs = {ex.submit(run, n): n for n in order}
    found, done, pending = {}, set(), set(futs)
    start, first_hit = time.time(), None

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
        budget = (first_hit + grace if first_hit is not None else start + deadline) - time.time()
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
                    first_hit = time.time()
        verdict = decide()
        if verdict is not False:
            ex.shutdown(wait=False)
            return verdict
    ex.shutdown(wait=False)
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
        _, txt = _http("http://lyrics.kugou.com/search?" + urllib.parse.urlencode({
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
    _, txt = _http("http://lyrics.kugou.com/download?" + urllib.parse.urlencode({
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
                    with open(_MXM_TOKEN_FILE, "w") as f:
                        json.dump({"token": tk}, f)
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
           "kugou": fetch_kugou, "plain": fetch_plain_fallback}


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
            with open(_MXM_TOKEN_FILE, "w") as f:
                json.dump({"token": tk}, f)
    except Exception:
        pass


threading.Thread(target=_mxm_warmup, daemon=True).start()


def _override_source(title, artist):
    keys = [song_key(title, artist), f"{title or ''}|{_latin_key(artist)}".lower()]
    for k in keys:
        if k in _SONG_SOURCE_OVERRIDES:
            return _SONG_SOURCE_OVERRIDES[k]
    return None


def get_lyrics(title, artist, duration, source):
    override = _override_source(title, artist) if source == "auto" else None
    if override:
        source = override
    if source == "plain":
        key = (song_key(title, artist), "plain")
        if key in _lyrics_cache:
            return source, _lyrics_cache[key]
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
        if key in _lyrics_cache:
            return source, _lyrics_cache[key]
        try:
            raw = (fetch_lrclib_id(sid) if name == "lrclib" else
                   fetch_netease_id(sid) if name == "netease" else
                   fetch_kugou_id(sid) if name == "kugou" else None)
        except Exception:
            raw = None
        if raw:
            lines = parse_lrc(raw)
            if usable_lyrics(lines):
                _lyrics_cache[key] = lines
                return source, lines
        return None, []
    # chosen source first, then always fall back to the others until one hits
    base = ["plain", "musixmatch", "lrclib", "netease", "kugou"] if _latin_key(title) in _PLAIN_LYRIC_URLS else ["musixmatch", "lrclib", "netease", "kugou", "plain"]
    order = ([source] + [s for s in base if s != source]) if source in SOURCES else base
    sk = song_key(title, artist)
    if source == "auto" and sk in _auto_cache:   # replay of an already-resolved song -> instant
        return _auto_cache[sk]
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
_trans_cache = {}
_trans_lock = threading.Lock()


def _gt_batch(texts, tl):
    q = "\n".join(texts)
    url = ("https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl="
           + urllib.parse.quote(tl) + "&dt=t&q=" + urllib.parse.quote(q))
    _, txt = _http(url, headers=_GT_HDRS, timeout=12)
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
    """Google gtx translate with a batch pass and a per-line fallback whenever the
    batch loses 1:1 alignment with the input."""
    out = []
    B = 40
    for i in range(0, len(texts), B):
        chunk = texts[i:i + B]
        try:
            got = _gt_batch(chunk, tl)
        except Exception:
            got = []
        if len(got) != len(chunk):               # alignment lost -> per-line, exact
            got = []
            for t in chunk:
                if not t.strip():
                    got.append("")
                    continue
                try:
                    g = _gt_batch([t], tl)
                    got.append(g[0] if g else "")
                except Exception:
                    got.append("")
        out.extend(got)
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
    if cid in _candidate_usable_cache:
        return _candidate_usable_cache[cid]
    name, sid = cid.split(":", 1)
    try:
        raw = (fetch_lrclib_id(sid) if name == "lrclib" else
               fetch_netease_id(sid) if name == "netease" else
               fetch_kugou_id(sid) if name == "kugou" else None)
        ok = bool(raw and usable_lyrics(parse_lrc(raw)))
    except Exception:
        ok = False
    _candidate_usable_cache[cid] = ok
    return ok


@app.route("/api/candidates")
def api_candidates():
    title = (request.args.get("title") or "").strip()
    artist = (request.args.get("artist") or "").strip()
    duration = request.args.get("duration", type=float)
    if not title:
        return jsonify({"ok": False, "error": "no_title"})
    cand = []
    seen = set()
    natives = recover_native_meta(title, artist, duration)
    # For Apple Music's English/pinyin metadata, the original title often only
    # returns covers or irrelevant tracks. Once the native title+artist are known,
    # search candidates with those directly to keep the panel responsive.
    query_pairs = [(nt, na, 3) for nt, na in natives] + [(title, artist, 0)]
    for qtitle, qartist, penalty in query_pairs:
        # KuGou is a Chinese-only catalog and slow on Latin queries — skip it there.
        fns = (search_lrclib, search_netease, search_kugou) if has_cjk(qtitle) else (search_lrclib, search_netease)
        for fn in fns:
            try:
                for c in fn(qtitle, qartist, duration, limit=5):
                    cid = c.get("id")
                    if not cid or cid in seen:
                        continue
                    seen.add(cid)
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
def api_lyrics():
    title = (request.args.get("title") or "").strip()
    artist = (request.args.get("artist") or "").strip()
    duration = request.args.get("duration", type=float)
    source = (request.args.get("source") or "auto").strip()
    if not title:
        return jsonify({"ok": False, "error": "no_title"})
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
def api_translate():
    """Translate the current lyric lines (default -> Simplified Chinese)."""
    body = request.get_json(force=True, silent=True) or {}
    lines = [str(x or "") for x in (body.get("lines") or [])]
    tl = (body.get("tl") or TRANSLATE_TARGET_LANG).strip() or TRANSLATE_TARGET_LANG
    if not lines:
        return jsonify({"ok": True, "trans": []})
    key = "|".join([body.get("title") or "", body.get("artist") or "",
                    body.get("source") or "", tl, str(len(lines))])
    with _trans_lock:
        cached = _trans_cache.get(key)
    if cached and len(cached) == len(lines):
        return jsonify({"ok": True, "trans": cached, "cached": True})
    trans = translate_lines(lines, tl)
    with _trans_lock:
        _trans_cache[key] = trans
    return jsonify({"ok": True, "trans": trans})


# ---------------- Per-song prefs (source + offset), saved only when adjusted ----
def _load_prefs():
    try:
        with open(PREFS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _write_prefs(d):
    tmp = PREFS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, ensure_ascii=False)
    os.replace(tmp, PREFS_FILE)


@app.route("/api/prefs", methods=["GET", "POST"])
def api_prefs():
    if request.method == "GET":
        key = song_key(request.args.get("title", ""), request.args.get("artist", ""))
        p = _load_prefs().get(key) or {}
        return jsonify({"source": p.get("source", "auto"), "offset": p.get("offset", 0)})
    body = request.get_json(force=True, silent=True) or {}
    key = song_key(body.get("title", ""), body.get("artist", ""))
    if not key.strip("|"):
        return jsonify({"ok": False})
    src = body.get("source", "auto")
    off = round(float(body.get("offset", 0)), 1)
    with _prefs_lock:
        prefs = _load_prefs()
        if src == "auto" and off == 0:
            prefs.pop(key, None)          # reset to default -> drop the record
        else:
            prefs[key] = {"source": src, "offset": off}
        _write_prefs(prefs)
    return jsonify({"ok": True})


@app.route("/api/report", methods=["POST"])
def api_report():
    """User-reported lyric problem; appended as one JSON line to REPORTS_FILE."""
    body = request.get_json(force=True, silent=True) or {}
    rec = {"ts": round(time.time()), "when": time.strftime("%Y-%m-%d %H:%M:%S"),
           "ip": (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()}
    for k in ("title", "artist", "duration", "source", "found", "lineCount", "offset", "note"):
        rec[k] = body.get(k)
    try:
        with open(REPORTS_FILE, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500
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
:root{color-scheme:light dark; --accent:#1db954;
 --fg:#f2f3f5; --dim:#878d96; --bg:#0a0c10; --page-bg:radial-gradient(120% 80% at 50% -10%,#161a22 0%,var(--bg) 60%);
 --line:#5b616a; --line-cur:#fff; --panel:rgba(255,255,255,.03); --panel-border:rgba(255,255,255,.06); --bar-bg:rgba(255,255,255,.08);
 --seg-bg:rgba(255,255,255,.06); --button-bg:rgba(255,255,255,.04); --button-border:rgba(255,255,255,.14); --button-active:rgba(255,255,255,.12); --active-fg:#06210f; --note:#4a4f57; --label:#666d77}
@media (prefers-color-scheme: light){:root{color-scheme:light; --fg:#15171a; --dim:#5d6570; --bg:#f5f7fb; --page-bg:radial-gradient(120% 80% at 50% -10%,#fff 0%,#eef2f8 62%,var(--bg) 100%);
 --line:#a2a9b3; --line-cur:#0d1117; --panel:rgba(0,0,0,.035); --panel-border:rgba(0,0,0,.07); --bar-bg:rgba(0,0,0,.08);
 --seg-bg:rgba(0,0,0,.055); --button-bg:rgba(0,0,0,.035); --button-border:rgba(0,0,0,.13); --button-active:rgba(0,0,0,.10); --active-fg:#fff; --note:#7a828d; --label:#79818c}}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html,body{height:100%}
body{background:var(--page-bg);color:var(--fg);
 font-family:-apple-system,"PingFang SC","Microsoft YaHei",system-ui,sans-serif;
 display:flex;flex-direction:column;overflow:hidden}
#hdr{padding:14px 22px 8px;text-align:center;flex:0 0 auto}
/* song title / artist / album are intentionally hidden from the top of the page
   (still available in the 「歌词信息」 popup); only the progress bar stays up top. */
#title,#meta,#realsrc{display:none}
#bar{height:3px;background:var(--bar-bg);border-radius:3px;margin:14px 32px 0;overflow:hidden}
#barfill{height:100%;width:0;background:var(--accent);border-radius:3px;transition:width .25s linear}
#lyrics{flex:1 1 auto;overflow:hidden;position:relative;
 -webkit-mask-image:linear-gradient(transparent,#000 16%,#000 76%,transparent);
 mask-image:linear-gradient(transparent,#000 16%,#000 76%,transparent)}
#scroll{position:absolute;left:0;right:0;top:50%;transition:transform .5s cubic-bezier(.22,.7,.16,1);will-change:transform}
.ln{padding:12px 32px;text-align:left;font-size:clamp(30px,8vw,48px);color:var(--line);line-height:1.25;font-weight:700;
 transition:color .28s,opacity .28s,transform .28s;opacity:.5;transform-origin:left center}
.ln.cur{color:var(--line-cur);opacity:1;transform:scale(1.04)}
#hint{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;text-align:center;
 color:var(--dim);font-size:15px;padding:30px}
#ctl{flex:0 0 auto;display:flex;align-items:center;justify-content:center;gap:14px;
 padding:12px 16px calc(12px + env(safe-area-inset-bottom));background:var(--panel);
 border-top:1px solid var(--panel-border);font-size:13px;color:var(--dim);flex-wrap:wrap}
.seg{display:inline-flex;background:var(--seg-bg);border-radius:9px;overflow:hidden}
.seg button{background:none;border:0;color:var(--dim);padding:6px 11px;font-size:13px;cursor:pointer}
.seg button.on{background:var(--accent);color:var(--active-fg);font-weight:700}
.info{position:relative;display:inline-flex}
.info button{border:1px solid var(--button-border);border-radius:999px;background:var(--button-bg);color:var(--fg);
 padding:7px 13px;font-size:13px;cursor:pointer;min-width:110px;text-align:center}
.info button:active{background:var(--button-active)}
#infopanel,#srcpanel{display:none;position:absolute;left:0;bottom:42px;min-width:250px;max-width:min(360px,92vw);z-index:4;
 max-height:min(76vh,560px);
 padding:13px 15px;border:1px solid var(--panel-border);border-radius:14px;background:var(--bg);color:var(--fg);
 box-shadow:0 14px 40px rgba(0,0,0,.28);font-size:15px;line-height:1.6;text-align:left}
#infopanel.show,#srcpanel.show{display:flex;flex-direction:column}
#infohead{flex:0 0 auto}
/* filter chips sit on their own line(s) above the list, free to wrap to two rows */
#candbar{flex:0 0 auto;margin-bottom:8px}
#candbar b{display:block;margin-bottom:7px}
#candfilter{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.fchip{border:1px solid var(--button-border);background:var(--button-bg);color:var(--dim);border-radius:999px;
 padding:6px 12px;font-size:14px;cursor:pointer;line-height:1.4;text-align:center}
.fchip.on{background:var(--accent);color:var(--active-fg);border-color:var(--accent);font-weight:700}
/* candidate list: scrollable SINGLE column (full-width rows so info isn't cut off) */
#candwrap{flex:1 1 auto;overflow-y:auto;-webkit-overflow-scrolling:touch;min-height:38px}
#candwrap .status{padding:6px 2px}
#reportbtn{flex:0 0 auto;margin-top:10px;width:100%;border:1px solid var(--button-border);background:var(--button-bg);
 color:var(--fg);border-radius:10px;padding:9px 10px;font-size:14px;cursor:pointer}
#reportbtn:active{background:var(--button-active)}
#reportmsg{flex:0 0 auto;margin-top:5px;color:var(--dim);font-size:12.5px;text-align:center;min-height:14px}
#infopanel .dim,#srcpanel .dim{color:var(--dim)}
.cand{display:block;width:100%;margin:7px 0 0;padding:9px 11px;border:1px solid var(--button-border);border-radius:10px;
 background:var(--button-bg);color:var(--fg);text-align:left;font-size:14px;line-height:1.4;cursor:pointer;word-break:break-word}
.cand.on{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.cand:active{background:var(--button-active)}
.step{display:inline-flex;align-items:center;gap:9px}
.step button{width:30px;height:30px;border-radius:50%;border:1px solid var(--button-border);
 background:var(--button-bg);color:var(--fg);font-size:17px;cursor:pointer;line-height:1}
.step button:active{background:var(--button-active)}
#off{min-width:52px;text-align:center;font-variant-numeric:tabular-nums;color:var(--fg)}
.lbl{color:var(--label);font-size:12px}
/* furigana ruby + per-line translation rendered inside each .ln */
.ln ruby{ruby-position:over;-webkit-ruby-position:over;ruby-align:center}
.ln rt{font-size:.4em;font-weight:600;color:var(--dim);line-height:1.05;letter-spacing:.01em;
 -webkit-user-select:none;user-select:none}
.ln .tr{display:block;margin-top:7px;font-size:.46em;font-weight:600;color:var(--dim);line-height:1.25;opacity:.92}
.tgl{border:1px solid var(--button-border);border-radius:999px;background:var(--button-bg);color:var(--fg);
 padding:7px 14px;font-size:13px;cursor:pointer}
.tgl.on{background:var(--accent);color:var(--active-fg);border-color:var(--accent);font-weight:700}
.tgl:disabled{opacity:.45;cursor:default}
.tgl:active{background:var(--button-active)}
</style></head>
<body>
<div id="hdr"><div id="title">—</div><div id="meta"></div><div id="bar"><div id="barfill"></div></div></div>
<div id="lyrics"><div id="scroll"></div><div id="hint">等待车辆播放音乐…</div></div>
<div id="ctl">
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
const STEP = 0.5, LEAD = 0.6;  // LEAD = global latency compensation (s)
const QS = new URLSearchParams(location.search);
const MOCK = QS.has("mock");
const MOCK_ENGLISH = QS.has("eng");
const MOCK_STARTED_AT = performance.now()/1000;
const MOCK_DURATION = 270;
const MOCK_LINES = [[5,"故事的小黄花"],[11,"从出生那年就飘着"],[17,"童年的荡秋千"],[23,"随记忆一直晃到现在"],[31,"Re So So Si Do Si La"],[37,"So La Si Si Si Si La Si La So"],[45,"吹着前奏望着天空"],[51,"我想起花瓣试着掉落"],[60,"为你翘课的那一天"],[66,"花落的那一天"],[72,"教室的那一间"],[78,"我怎么看不见"],[90,"从前从前有个人爱你很久"],[98,"但偏偏风渐渐把距离吹得好远"],[108,"好不容易又能再多爱一天"],[116,"但故事的最后你好像还是说了拜拜"]];
let st=null, base={elapsed:0,at:0,playing:false};
let lyrics=[], curKey="", curIdx=-1;
let furigana=[], translations=[], showTrans=false, transLoading=false, transKey="";
let curTitle="", curArtist="", curSource="auto", curOffset=0;
let lyricInfo={source:"—",found:false,lineCount:0,duration:0,title:"",artist:"",album:""};
let candidates=[], candLoaded=false, candLoading=false, candFilter="all";
const $=id=>document.getElementById(id);
const keyOf=d=>(d.title||"")+"|"+(d.artist||"");
const sourceName=s=>({musixmatch:"Musixmatch",lrclib:"LRCLIB",netease:"网易云",kugou:"酷狗",plain:"普通歌词",instrumental:"纯音乐",auto:"自动",mock:"Mock"}[(s||"").split(":")[0]]||s||"—");
function fmtTime(sec){ sec=Math.max(0,Math.round(+sec||0)); return Math.floor(sec/60)+":"+String(sec%60).padStart(2,"0"); }
function esc(s){ return String(s||"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }

async function poll(){
  try{
    const d = MOCK ? mockState() : await (await fetch("api/state",{cache:"no-store"})).json();
    if(d.ok && d.online){
      st=d; base={elapsed:d.elapsed||0, at:performance.now()/1000, playing:!!d.playing};
      $("title").textContent = (MOCK ? "🧪 " : "") + (d.title || (d.status==="Stopped"?"未在播放":"—"));
      $("meta").textContent = [d.artist,d.album].filter(Boolean).join("  ·  ");
      lyricInfo={...lyricInfo,title:d.title||"",artist:d.artist||"",album:d.album||"",duration:d.duration||0}; updateInfo();
      const k=keyOf(d);
      if(d.title && k!==curKey){ curKey=k; curTitle=d.title; curArtist=d.artist; onNewSong(d); }
      if(!d.title){ setLyrics([]); showHint("未在播放音乐"); }
    } else if(d.ok && !d.online){
      st=null; $("title").textContent="—"; $("meta").textContent=""; setLyrics([]);
      showHint("车辆休眠中 — 开始播放后自动显示");
    } else { showHint("读取失败: "+(d.error||"?")); }
  }catch(e){}
}

function mockState(){
  const elapsed = (performance.now()/1000 - MOCK_STARTED_AT) % MOCK_DURATION;
  return {ok:true,online:true,playing:true,status:"Playing",title:MOCK_ENGLISH?"Sunny Day":"晴天",artist:"周杰伦",album:"叶惠美",source:"Mock Player",elapsed,duration:MOCK_DURATION,ts:Date.now()/1000};
}

async function onNewSong(d){
  setLyrics([]); candidates=[]; candLoaded=false; candLoading=false; candFilter="all"; showHint("加载歌词…");
  try{
    const p = await (await fetch("api/prefs?"+new URLSearchParams({title:d.title,artist:d.artist||""}),{cache:"no-store"})).json();
    curSource = p.source||"auto"; curOffset = +p.offset||0;
  }catch(e){ curSource="auto"; curOffset=0; }
  updateCtl();
  await loadLyrics();
  // Candidate list resets on song change; refetch only if the source popup is open.
  renderCands();
  if($("srcpanel") && $("srcpanel").classList.contains("show")) loadCandidates();
}

async function loadCandidates(){
  if(!curTitle) return;
  candLoading=true; candLoaded=false; renderCands();   // show "正在查找…" immediately
  try{
    const q=new URLSearchParams({title:curTitle,artist:curArtist||"",duration:Math.round((st&&st.duration)||0)});
    const j = await (await fetch("api/candidates?"+q,{cache:"no-store"})).json();
    candidates = (j.ok && j.candidates) ? j.candidates : [];
  }catch(e){ candidates=[]; }
  candLoading=false; candLoaded=true; renderCands();    // show results or "没有找到可选歌词"
}

async function loadLyrics(){
  try{
    const q=new URLSearchParams({title:curTitle,artist:curArtist||"",duration:Math.round((st&&st.duration)||0),source:curSource});
    const j = await (await fetch("api/lyrics?"+q,{cache:"no-store"})).json();
    if(j.ok && j.found){
      lyricInfo={...lyricInfo,source:j.source||"—",found:true,lineCount:(j.lines||[]).length,duration:(st&&st.duration)||0}; updateInfo();
      setLyrics(j.lines, j.furigana, j.translatable); $("realsrc").textContent = j.source?("· "+sourceName(j.source)):"";
      if(showTrans && j.translatable!==false) loadTranslations();
    }
    else if(j.instrumental){ lyricInfo={...lyricInfo,source:"instrumental",found:false,lineCount:0,duration:(st&&st.duration)||0}; updateInfo(); setLyrics([]); showHint("🎵 纯音乐 · 无歌词"); $("realsrc").textContent="· 纯音乐"; }
    else { lyricInfo={...lyricInfo,source:"—",found:false,lineCount:0,duration:(st&&st.duration)||0}; updateInfo(); setLyrics([]); showHint("未找到这首歌的歌词"); $("realsrc").textContent=""; }
  }catch(e){
    if(MOCK){
      lyricInfo={...lyricInfo,source:"mock",found:true,lineCount:MOCK_LINES.length,duration:MOCK_DURATION}; updateInfo();
      setLyrics(MOCK_LINES, null, true); $("realsrc").textContent = "· Mock fallback";
      if(showTrans) loadTranslations();
    } else {
      lyricInfo={...lyricInfo,source:"—",found:false,lineCount:0,duration:(st&&st.duration)||0}; updateInfo(); setLyrics([]); showHint("歌词加载失败");
    }
  }
}

function showHint(t){ $("hint").textContent=t; $("hint").style.display="flex"; }
function setLyrics(lines, furi, translatable){
  lyrics=lines||[]; furigana=furi||[]; translations=[]; transKey=""; curIdx=-1;
  // Furigana is always shown when available (no toggle). The 翻译 button only
  // appears for tracks worth translating — Chinese lyrics report translatable=false.
  const tb=$("trbtn"); if(tb){ tb.style.display = (lyrics.length && translatable!==false) ? "" : "none";
    tb.classList.toggle("on", showTrans && lyrics.length>0); }
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
  transLoading=true; const b=$("trbtn"); if(b){ b.classList.add("on"); b.textContent="翻译中…"; }
  try{
    if(MOCK){ translations = lyrics.map(l=>"译: "+(l[1]||"")); }
    else{
      const r = await (await fetch("api/translate",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({lines:lyrics.map(l=>l[1]||""),title:curTitle,artist:curArtist,source:lyricInfo.source})})).json();
      translations = (r.ok && r.trans) ? r.trans : [];
    }
    transKey=curKey;
  }catch(e){ translations=[]; }
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
    let idx=-1; for(let i=0;i<lyrics.length;i++){ if(lyrics[i][0]<=el+LEAD) idx=i; else break; }
    if(idx<0){ centerLine(0); }
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
  $("infopanel").innerHTML =
    `<div id="infohead"></div>`+
    `<button id="reportbtn">⚠️ 上报歌词有误</button><span id="reportmsg"></span>`;
  $("reportbtn").onclick=sendReport;
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
    `<span class="dim">${esc(c.artist||'—')} · ${esc(c.album||'—')} · ${fmtTime(c.duration)} · 相关度 ${c.score||0}</span>`+
    `</button>`).join("")
    : candLoading ? `<div class="dim status">正在查找候选歌词…</div>`
    : candLoaded ? `<div class="dim status">没有找到可选歌词</div>`
    : `<div class="dim status">展开以查找</div>`;
  for(const b of $("candwrap").querySelectorAll(".cand")) b.onclick=(e)=>{ e.stopPropagation(); selectCandidate(b.dataset.id); };
}

async function sendReport(){
  if(!curTitle) return;
  const msg=$("reportmsg"); if(msg) msg.textContent="上报中…";
  try{
    const r = await fetch("api/report",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({title:curTitle,artist:curArtist||"",duration:Math.round((st&&st.duration)||0),
        source:lyricInfo.source,found:!!lyricInfo.found,lineCount:lyricInfo.lineCount||0,offset:curOffset})});
    if(msg) msg.textContent = r.ok ? "已上报 ✓ 谢谢反馈" : "上报失败，请稍后再试";
  }catch(e){ if(msg) msg.textContent="上报失败，请稍后再试"; }
}

async function selectCandidate(id){
  if(!id || id==="mock") return;
  curSource=id; updateCtl(); savePrefs(); $("srcpanel").classList.remove("show"); showHint("加载选择的歌词…"); await loadLyrics();
}
async function savePrefs(){
  if(!curTitle) return;
  try{ await fetch("api/prefs",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({title:curTitle,artist:curArtist,source:curSource,offset:curOffset})}); }catch(e){}
}
$("infobtn").onclick=()=>{ const show=$("infopanel").classList.toggle("show"); if(show){ if($("srcpanel"))$("srcpanel").classList.remove("show"); updateInfo(); } };
$("srcbtn").onclick=()=>{ const show=$("srcpanel").classList.toggle("show"); if(show){ if($("infopanel"))$("infopanel").classList.remove("show"); if(!candLoaded && !candLoading && curTitle) loadCandidates(); else renderCands(); } };
document.addEventListener("click",e=>{ if(!e.target.closest(".info")){ if($("infopanel"))$("infopanel").classList.remove("show"); if($("srcpanel"))$("srcpanel").classList.remove("show"); } });
$("om").onclick=()=>{ curOffset=Math.max(-10,Math.round((curOffset-STEP)*10)/10); updateCtl(); savePrefs(); };
$("op").onclick=()=>{ curOffset=Math.min(10,Math.round((curOffset+STEP)*10)/10); updateCtl(); savePrefs(); };
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
