# teslamate-lyrics — deprecated

> [!WARNING]
> This project is no longer maintained and the repository is archived.
> It lives on as the lyrics service of **[tesla-hub](https://github.com/lyp04/tesla-hub)**
> (`lyrics/`), together with an in-car menu and other pages for the Tesla browser.

## Moving to tesla-hub

tesla-hub runs the same service with the same TeslaMate access. When moving an existing
installation:

- Copy `TM_DB_HOST`, `TM_DB_NAME`, `TM_DB_USER`, `TM_DB_PASS`, `TM_ENCRYPTION_KEY`,
  `TESLAMATE_NETWORK`, `TESLA_VIN` and `TRANSLATE_TARGET_LANG` into tesla-hub's `.env`.
  The other settings of this project are gone (the Tesla token file mode, the old
  `TESLAMATE_DB_*` / `DATABASE_*` names, the server-side preference file and the local
  report file).
- Move `data/mxm_token.json` (and `data/settings.json`, if present) to tesla-hub's
  `data/lyrics/`.
- Per-song lyric sources and offsets stay in the car browser and keep working.
- The service still listens on port 8475, so an existing reverse-proxy location keeps
  working.

The code here is left as it was for reference. MIT licensed.
