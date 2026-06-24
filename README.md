# teslamate-lyrics

Synced lyrics page for the Tesla in-car browser. Piggybacks on your existing TeslaMate — no second Tesla login, no token file, just `docker compose up`.

Lyrics come from Musixmatch / LRCLIB / NetEase / KuGou in parallel. Japanese songs get furigana. Non-native lyrics can be translated.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## How it works

TeslaMate already keeps a fresh Tesla access token (encrypted) in its Postgres. This app reads and decrypts it with your `ENCRYPTION_KEY`, calls the Tesla Owner API for the current track, then finds synced lyrics from public sources.

```
TeslaMate Postgres ──(encrypted access token)──> teslamate-lyrics decrypts it
    ──> Tesla Owner API (media_info) ──> lyric matching ──> browser
```

No second OAuth, no token rotation. TeslaMate refreshes the token on its own schedule; this app just reads whatever's current.

## Setup

You need a running TeslaMate v4 stack and Docker Compose.

```bash
git clone https://github.com/lyp04/teslamate-lyrics.git
cd teslamate-lyrics

cp .env.example .env
# Fill in your TeslaMate DB credentials + ENCRYPTION_KEY
# TESLA_VIN can stay blank — it'll pick the first car

docker compose up -d --build
```

Open `http://127.0.0.1:8475` and play something. Lyrics show up.

### Finding your TeslaMate values

Look in your TeslaMate `docker-compose.yml` or `.env` for `DATABASE_USER`, `DATABASE_PASS`, `DATABASE_NAME`, and `ENCRYPTION_KEY`. Network name is usually `teslamate_default` (`docker network ls | grep teslamate` to check).

### Remote / in-car access

No built-in auth — it only binds to 127.0.0.1 by default. For the car browser or external access, put nginx (or whatever) with auth in front:

```nginx
location ^~ /music/ {
    auth_basic           "restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://127.0.0.1:8475/;
}
```

## What it does

- **Multi-source parallel matching** — Musixmatch, LRCLIB, NetEase, KuGou, all at once. Confidence-gated: prefers no lyrics over wrong lyrics.
- **Apple Music title recovery** — the car often reports pinyin or English titles (晴天 → "Sunny Day"). Original CJK metadata is recovered from the iTunes catalog before searching.
- **Japanese furigana** — readings above kanji via fugashi + unidic-lite (君 → きみ), always on.
- **Translation** — translates lyrics to a configurable target language (default zh-CN). Skips same-language lyrics so you don't get a useless duplicate line.
- **Per-song memory** — manually picked source or timing offset is saved server-side.
- **Lazy polling** — no open tab = no API calls. Hidden tabs stop polling. Polling rate adapts based on track position. Follows the car's light/dark theme.

## Configuration

All in `.env` (copy from `.env.example`):

| Variable | Default | |
| --- | --- | --- |
| `TM_DB_HOST` | `database` | TeslaMate Postgres hostname |
| `TM_DB_NAME` / `TM_DB_USER` / `TM_DB_PASS` | `teslamate` / `teslamate` / — | DB credentials |
| `TM_ENCRYPTION_KEY` | — | TeslaMate's `ENCRYPTION_KEY` |
| `TESLAMATE_NETWORK` | `teslamate_default` | TeslaMate's Docker network |
| `TESLA_VIN` | auto | Blank = first car |
| `TRANSLATE_TARGET_LANG` | `zh-CN` | Translation target |
| `HTTP_BIND_ADDR` / `HTTP_PORT` | `127.0.0.1` / `8475` | Host bind |

Full list in [.env.example](.env.example).

`TOKEN_SOURCE` defaults to `teslamate_db` — reads from TeslaMate's DB. There's a legacy `file` mode if you maintain your own refresh token, but you probably don't need it.

## Troubleshooting

| What you see | What's wrong |
| --- | --- |
| Blank page / "车辆休眠中" | Car is asleep. Start playing. |
| DB error on `/api/state` | Bad credentials or container not on TeslaMate's Docker network |
| Decryption error | `TM_ENCRYPTION_KEY` mismatch |
| 401 | TeslaMate's Tesla session died — re-auth in TeslaMate, this app recovers automatically |
| No lyrics for a track | May not exist anywhere. Try the lyric source picker panel at the bottom. |

## API

| Path | |
| --- | --- |
| `/` | Lyrics page |
| `/api/state` | Current playback |
| `/api/lyrics` | Synced lyrics + furigana |
| `/api/candidates` | Alternative lyric sources |
| `/api/translate` | Translate lyrics |
| `/api/prefs` | Per-song source + offset prefs |
| `/api/report` | Report bad match |
| `/healthz` | Health check |

---

Not affiliated with Tesla or TeslaMate. Uses the unofficial Owner API and public lyric providers.

Written with help from AI (Claude). MIT — PRs welcome.
