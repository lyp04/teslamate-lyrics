# teslamate-lyrics

Synced lyrics for the Tesla in-car browser, powered by an existing TeslaMate
installation. The app reuses TeslaMate's encrypted Tesla access token, reads the
current media state, matches time-coded lyrics from several providers, and renders
them in a touch-friendly web page.

No second Tesla login is required. No real credentials, VINs, listening history,
or copyrighted demo lyrics are included in this repository.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> [!IMPORTANT]
> The application has no built-in user authentication. Docker Compose binds it to
> `127.0.0.1` by default. Keep that default unless you deliberately bind to a
> private VPN interface or put an authenticated HTTPS reverse proxy in front.

## Highlights

- **Multiple lyric providers** — Musixmatch, LRCLIB, PetitLyrics, NetEase, and
  KuGou. Matching is prioritized; after the Musixmatch probe, the remaining
  providers are queried concurrently. Results are confidence-gated to prefer no
  result over lyrics for the wrong recording.
- **Alternative source picker** — inspect viable matches and pin a different source
  when automatic matching is not ideal.
- **Apple metadata recovery** — recovers native CJK titles and artists when the car
  reports a romanized or translated name.
- **Japanese furigana** — adds readings above kanji with `fugashi` and
  `unidic-lite`.
- **Optional translation** — translates non-native lyrics to a configurable target
  language. With the default `zh-CN` target, already-Chinese lyrics are skipped.
- **Stable playback synchronization** — scrolls locally between state polls and
  buffers small backward clock corrections so the page does not jump to the
  previous line.
- **Per-browser preferences** — remembers the selected lyric source and timing
  offset in browser `localStorage`.
- **Local bad-match report API** — an optional endpoint appends bounded feedback
  records to the host's private `data/` directory. Client IP addresses are not
  recorded.
- **Hardened container defaults** — non-root process, read-only root filesystem,
  dropped Linux capabilities, resource limits, security headers, bounded inputs,
  bounded caches, and single-flight state refreshes.

## How it works

TeslaMate already stores and refreshes a Tesla access token in Postgres. This app
decrypts the latest token with the same `ENCRYPTION_KEY`, calls Tesla's vehicle
media endpoint, and sends track metadata to lyric providers.

```text
TeslaMate Postgres
    │ encrypted access token
    ▼
teslamate-lyrics ──► Tesla Owner API ──► current media state
    │
    ├──► lyric providers ──► matched timed lyrics
    ├──► iTunes catalog   ──► native-title recovery
    └──► browser          ──► local clock + smooth lyric scrolling
```

TeslaMate remains responsible for Tesla authentication and token refresh. The app
only caches the decrypted access token briefly in memory and reads it again when
needed.

### Playback synchronization and rewind buffering

The browser does not call Tesla for every animation frame:

1. `/api/state` supplies an elapsed-time anchor.
2. `requestAnimationFrame` advances that clock locally for smooth scrolling.
3. A fresh state poll recalibrates the local clock.
4. If a normal poll moves the clock slightly backward, the corrected clock is
   accepted but the visible lyric cursor stays on its current line until playback
   catches up.
5. A backward jump of five seconds or more is treated as a deliberate seek or
   replay and may move the cursor backward immediately.

Duplicate state timestamps and late overlapping poll responses are discarded as a
whole. Lyric, source-candidate, and translation responses are also tied to the
current song generation so a slow previous request cannot overwrite a new track.
Pausing does not disable the small-jitter buffer. The `−` and `+` timing buttons
intentionally bypass it so manual adjustments take effect immediately.

## Requirements

- A running TeslaMate v4 stack
- Docker Engine with Docker Compose v2
- Access to TeslaMate's Postgres credentials and `ENCRYPTION_KEY`
- A Docker network shared with TeslaMate (usually `teslamate_default`)
- An authenticated reverse proxy, or a deliberate bind to a private VPN interface,
  for in-car/remote access

## Quick start

```bash
git clone https://github.com/lyp04/teslamate-lyrics.git
cd teslamate-lyrics

cp .env.example .env
chmod 600 .env
```

Edit `.env` and set at least:

```dotenv
TM_DB_HOST=database
TM_DB_NAME=teslamate
TM_DB_USER=teslamate
TM_DB_PASS=replace-with-your-database-password
TM_ENCRYPTION_KEY=replace-with-your-teslamate-encryption-key
TESLAMATE_NETWORK=teslamate_default
```

Find these values in TeslaMate's own `.env` or Compose file. Check the network
name with:

```bash
docker network ls --format '{{.Name}}' | grep teslamate
```

Create the private runtime directory with the UID/GID used by the container:

```bash
sudo install -d -m 700 -o 10001 -g 10001 data
```

If `data/` already exists, verify it is writable by UID 10001 before starting the
service. Do not make it world-writable.

Build and start the service:

```bash
docker compose up -d --build
docker compose ps
curl --fail http://127.0.0.1:8475/healthz
```

The local page is available at `http://127.0.0.1:8475`. For an in-car browser,
publish it through an authenticated HTTPS reverse proxy as described below.

## Configuration

Copy `.env.example` to `.env`. The real `.env` is intentionally ignored by Git and
must never be committed.

### Common settings

| Variable | Default/example | Purpose |
| --- | --- | --- |
| `TM_DB_HOST` | `database` | TeslaMate Postgres hostname on the shared Docker network |
| `TM_DB_NAME` | `teslamate` | TeslaMate database name |
| `TM_DB_USER` | `teslamate` | Database user |
| `TM_DB_PASS` | required | Database password; secret |
| `TM_ENCRYPTION_KEY` | required | TeslaMate `ENCRYPTION_KEY`; secret |
| `TESLAMATE_NETWORK` | `teslamate_default` | Existing external Docker network |
| `TESLA_VIN` | blank | Blank selects the first vehicle; otherwise choose one VIN |
| `TRANSLATE_TARGET_LANG` | `zh-CN` | Google `gtx` translation target language |
| `HTTP_BIND_ADDR` | `127.0.0.1` | Host address published by Compose |
| `HTTP_PORT` | `8475` | Host port published by Compose |
| `TESLAMATE_ACCESS_TTL` | `60` | Seconds to cache the decrypted access token in memory |
| `STATE_TTL` | `2.0` | Seconds to reuse a fresh vehicle state |
| `STATE_STALE_TTL` | `30.0` | Maximum stale state age used during a concurrent/upstream failure |

The app also accepts the older `TESLAMATE_DB_*` and `DATABASE_*` database names,
plus `TESLAMATE_ENCRYPTION_KEY` and `ENCRYPTION_KEY`, for compatibility. Prefer
the `TM_*` names in new installations.

### Advanced and legacy settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `TOKEN_SOURCE` | `teslamate_db` | Recommended DB-backed token source; `file` is a legacy fallback |
| `TESLA_API_HOST` | Tesla Owner API | Override only for a compatible endpoint |
| `TESLA_AUTH_HOST` / `TESLA_AUTH_PATH` | Tesla auth defaults | Legacy file-token refresh endpoint |
| `TESLA_AUTH_CLIENT_ID` | blank | Required when `TOKEN_SOURCE=file` |
| `TOKEN_FILE` | `/data/token.json` | Legacy token file |
| `PREFS_FILE` | `/data/prefs.json` | Legacy server preference store used for one-time browser migration |
| `REPORTS_FILE` | `/data/reports.jsonl` | Local bad-match report file |
| `MXM_TOKEN_FILE` | `/data/mxm_token.json` | Cached Musixmatch guest token |
| `PETITLYRICS_CLIENT_APP_ID` | built-in public client ID | Optional PetitLyrics client override |
| `DISABLE_MXM_WARMUP` | unset | Set to `1` in tests to skip background Musixmatch warm-up |

`BIND_HOST` and `BIND_PORT` only affect direct development runs with
`python app.py`. The supplied image listens on `0.0.0.0:8475`; normally only
`HTTP_BIND_ADDR` and `HTTP_PORT` should be changed.

## Secure remote and in-car access

The app exposes media metadata, performs network lookups, and has state-changing
POST endpoints. Do not publish port 8475 directly to the internet.

Example nginx location:

```nginx
location ^~ /music/ {
    auth_basic           "restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;

    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_pass http://127.0.0.1:8475/;
}
```

Serve nginx over HTTPS, then open `https://your-host.example/music/` in the car.
For direct VPN access, bind `HTTP_BIND_ADDR` to the dedicated VPN interface rather
than every host interface. If a trusted proxy already provides authentication,
keep the backend binding on loopback.

## Data and privacy

Runtime files live under the ignored host directory `./data`, mounted at `/data`
inside the container.

| Data | Location | Notes |
| --- | --- | --- |
| Real deployment secrets | `.env` | Git-ignored; never commit or paste into issues |
| Musixmatch guest token | `data/mxm_token.json` | Provider cache, not a Tesla login |
| Legacy token file | `data/token.json` | Only with `TOKEN_SOURCE=file`; sensitive |
| Legacy preferences | `data/prefs.json` | Source/offset records from older versions |
| Current preferences | Browser `localStorage` | Keyed by normalized title and artist |
| Bad-match reports | `data/reports.jsonl` and `.1` | Local track metadata and feedback; no client IP |

Bad-match reports may contain the current title, artist, duration, selected source,
line count, timing offset, optional note, and timestamp. They stay on the host,
are created with mode `0600`, and rotate at approximately 10 MiB. Treat them as
private listening-history data even though they contain no network identifier.

There is no analytics service and reports are not uploaded by this project.
However, normal operation necessarily sends:

- Tesla credentials only to Tesla/TeslaMate infrastructure;
- track metadata to configured lyric providers and the iTunes catalog;
- lyric text to the translation endpoint when the user enables translation.

Default runtime files under `data/`, `.env` variants, JSONL reports, local OAuth
state, backups, and Python caches are ignored. Custom paths outside those defaults
may not be; review `git status` before every public push.

## Using the page

- **Lyrics information** shows the selected provider, matched track, duration,
  line count, and timing offset.
- **Alternative sources** searches supported providers and only displays
  candidates with usable lyrics that still match the requested recording.
- **Translation** appears only for lyrics that benefit from translation.
- **Timing `−` / `+`** advances/delays lyrics in 0.5-second steps, within ±10
  seconds: `−` advances and `+` delays.

Add `?mock=1` to the page URL for a fully synthetic UI/synchronization demo. The
mock mode contains only placeholder metadata and synthetic test text.

## Lyric matching behavior

Automatic matching prioritizes synchronized lyrics and validates title, artist,
duration, and provider identity before accepting a result. The broad flow is:

1. Probe Musixmatch for synchronized lyrics or a high-confidence instrumental
   result.
2. Recover native CJK metadata when Apple/Tesla supplies a translated title.
3. Query the remaining providers concurrently.
4. Prefer the first usable result according to provider priority, with a short
   grace period for higher-priority providers.
5. Cache successful selections by normalized track identity and duration bucket.

Provider availability and catalog coverage vary by region; an empty result can be
safer than a high-scoring but incorrect lyric.

## Operations

### Update

```bash
git pull --ff-only
docker compose up -d --build
docker compose ps
```

### Logs and health

```bash
docker compose logs --tail=200 nowplaying
curl --fail http://127.0.0.1:8475/healthz
```

The container health check calls `/healthz` every 30 seconds. The Compose service
uses `restart: unless-stopped`.

### Stop

```bash
docker compose down
```

`docker compose down` does not delete `./data`.

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| `车辆休眠中` | Wake the car and start media playback. Avoid aggressive polling just to wake it. |
| Database connection error | Verify `TM_DB_*`, the external network name, and that `database` resolves inside the service network. |
| Token decryption error | `TM_ENCRYPTION_KEY` must exactly match TeslaMate's `ENCRYPTION_KEY`. |
| Tesla API returns 401 | Re-authenticate TeslaMate. The app clears its short token cache and retries with TeslaMate's refreshed token later. |
| No lyrics | Open **Alternative sources**. The recording may be absent or provider APIs may be unavailable. |
| Wrong lyrics | Pick a better source and adjust timing. Operators can also submit a bounded record to `/api/report`. |
| Lyrics briefly lead playback | Small backward corrections now hold the current line. Use timing `+` to delay lyrics manually. |
| Service is unreachable remotely | Confirm nginx/VPN routing; Compose intentionally binds to `127.0.0.1`. |
| Translation is empty | Check outbound HTTPS access; translation is best-effort and bounded. |
| `429 busy` from an expensive API | Wait for current provider lookups to finish; concurrency is deliberately bounded. |

## HTTP API

These endpoints are intended for the bundled page, not as a stable public API.
They have no built-in authentication.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | In-car lyric page |
| `GET` | `/healthz` | Container health check |
| `GET` | `/api/state` | Current media state |
| `GET` | `/api/lyrics` | Matched lyrics and optional furigana |
| `GET` | `/api/candidates` | Alternative provider matches |
| `POST` | `/api/translate` | Translate a bounded list of lyric lines |
| `GET`, `POST` | `/api/prefs` | Legacy source/offset preference migration |
| `POST` | `/api/report` | Append a bounded local bad-match report |

`/api/lyrics` and `/api/candidates` require a `title` query value; `artist` and
`duration` are optional, and `/api/lyrics` also accepts an optional `source`.
`/api/translate` accepts JSON with a bounded `lines` array. The legacy preference
endpoint uses `title`/`artist` query values for reads and a JSON object for writes.
`/api/report` accepts a bounded JSON object containing track metadata and feedback.

API responses use `Cache-Control: no-store`. HTML responses include a restrictive
Content Security Policy and other browser security headers.

## Tests

The Python tests use only the application dependencies; the frontend
synchronization test uses Node's built-in modules and requires no npm install.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

python tests/run_candidate_filter_test.py
python tests/run_security_hardening_test.py
node tests/run_lyrics_sync_test.js
```

The synchronization test executes the embedded browser script with a small DOM
harness and covers:

- small backward corrections and catch-up;
- pause behavior;
- deliberate backward seeks;
- stale state timestamps;
- overlapping poll responses;
- offline/resume of the same recording;
- out-of-order lyric responses after a song change;
- out-of-order candidate and translation responses;
- manual timing offsets;
- removal of stale lyric highlighting before the first line;
- the fully synthetic mock path.

To validate the production image as well:

```bash
docker compose build nowplaying
docker compose run --rm --no-deps \
  -v "$PWD/tests:/app/tests:ro" \
  nowplaying python /app/tests/run_security_hardening_test.py
```

## Security notes

- The container runs as UID/GID `10001`, with a read-only root filesystem.
- Linux capabilities are dropped and `no-new-privileges` is enabled.
- Request bodies, metadata, LRC output, translations, caches, report files, and
  concurrent expensive operations are bounded.
- State refreshes are single-flight on the server. Late overlapping state,
  lyric, candidate, and translation responses are rejected in the browser.
- Upstream error details are logged server-side but generic errors are returned to
  clients.
- Security defaults do not replace authentication at the reverse proxy.

Please report security issues privately to the repository owner rather than
including secrets, VINs, tokens, database details, or listening history in a
public issue.

## License and acknowledgements

MIT licensed. Not affiliated with Tesla or TeslaMate. Tesla APIs and lyric
providers may change without notice and may have their own terms of service.

Contributions and focused pull requests are welcome.
