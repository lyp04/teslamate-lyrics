import importlib.util
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

os.environ["DISABLE_MXM_WARMUP"] = "1"

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
spec = importlib.util.spec_from_file_location("tesla_nowplaying_app", APP_PATH)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def test_public_defaults_have_no_track_specific_overrides():
    assert app._ARTIST_ALIASES == {}
    assert app._PLAIN_LYRIC_URLS == {}
    assert app._SONG_SOURCE_OVERRIDES == {}


def test_song_query_rejects_unbounded_or_nonfinite_input():
    client = app.app.test_client()
    with mock.patch.object(app, "get_lyrics") as get_lyrics:
        cases = [
            "/api/lyrics?title=" + ("x" * 201),
            "/api/lyrics?title=test&duration=nan",
            "/api/lyrics?title=test&duration=inf",
            "/api/lyrics?title=test&duration=-1",
            "/api/lyrics?title=test&source=unknown:payload",
        ]
        for url in cases:
            response = client.get(url)
            assert response.status_code == 400, (url, response.status_code, response.get_data(as_text=True))
        assert get_lyrics.call_count == 0


def test_bounded_ttl_cache_evicts_old_entries():
    cache = app.BoundedTTLCache(maxsize=2, ttl=60)
    cache["a"] = 1
    cache["b"] = 2
    assert cache["a"] == 1
    cache["c"] = 3
    assert len(cache) == 2
    assert "a" in cache and "c" in cache and "b" not in cache


def test_lrc_output_and_translation_work_are_strictly_bounded():
    many_stamps = "".join(f"[00:{i % 60:02d}.00]" for i in range(app.MAX_TIMESTAMPS_PER_LINE + 1)) + "boom"
    assert app.parse_lrc(many_stamps) == []
    too_many_lines = "\n".join(f"[{i // 60:02d}:{i % 60:02d}.00]line" for i in range(app.MAX_LRC_LINES + 1))
    assert app.parse_lrc(too_many_lines) == []

    with mock.patch.object(app, "_gt_batch", return_value=[]) as batch:
        translated = app._translate_raw(["line"] * app.MAX_TRANSLATE_LINES, "zh-CN")
    assert len(translated) == app.MAX_TRANSLATE_LINES
    assert batch.call_count <= app.MAX_TRANSLATE_NETWORK_CALLS


def test_duration_sensitive_cache_and_browser_local_preferences():
    first = [[0.0, "first"]] * 4
    second = [[0.0, "second"]] * 4
    app._auto_cache.clear()
    with mock.patch.object(app, "musixmatch_probe", return_value=("none", None)), \
         mock.patch.object(app, "recover_native_meta", return_value=[]), \
         mock.patch.object(app, "_try_sources", side_effect=[("lrclib", first), ("lrclib", second)]) as sources:
        a = app.get_lyrics("same", "artist", 100, "auto")
        a_cached = app.get_lyrics("same", "artist", 100, "auto")
        b = app.get_lyrics("same", "artist", 200, "auto")
    assert a == a_cached and a != b
    assert sources.call_count == 2

    page = app.app.test_client().get("/").get_data(as_text=True)
    assert "localStorage" in page
    assert 'fetch("api/prefs",{method:"POST"' not in page
    assert 'fetch("api/report"' not in page


def test_translate_requires_json_bounds_work_and_keys_cache_by_content():
    client = app.app.test_client()
    assert client.post("/api/translate", data="{}").status_code == 415
    assert client.post("/api/translate", json={"lines": ["x"] * 301}).status_code == 400
    assert client.post("/api/translate", json={"lines": ["x" * 1001]}).status_code == 400

    app._trans_cache.clear()
    with mock.patch.object(app, "translate_lines", side_effect=lambda lines, tl: ["T:" + x for x in lines]) as translate:
        a = client.post("/api/translate", json={"title": "same", "lines": ["alpha"]})
        b = client.post("/api/translate", json={"title": "same", "lines": ["bravo"]})
        b2 = client.post("/api/translate", json={"title": "same", "lines": ["bravo"]})
    assert a.status_code == b.status_code == b2.status_code == 200
    assert a.get_json()["trans"] == ["T:alpha"]
    assert b.get_json()["trans"] == ["T:bravo"]
    assert b2.get_json()["trans"] == ["T:bravo"]
    assert translate.call_count == 2

    app._trans_cache.clear()
    with mock.patch.object(app, "translate_lines", return_value=[""]) as failed_translate:
        first_failure = client.post("/api/translate", json={"lines": ["retry me"]})
        second_failure = client.post("/api/translate", json={"lines": ["retry me"]})
    assert first_failure.status_code == second_failure.status_code == 200
    assert failed_translate.call_count == 2


def test_prefs_and_reports_are_bounded_and_validated():
    client = app.app.test_client()
    with tempfile.TemporaryDirectory() as tmp:
        prefs = os.path.join(tmp, "prefs.json")
        reports = os.path.join(tmp, "reports.jsonl")
        with mock.patch.object(app, "PREFS_FILE", prefs), \
             mock.patch.object(app, "REPORTS_FILE", reports), \
             mock.patch.object(app, "MAX_PREFS_ENTRIES", 2), \
             mock.patch.object(app, "MAX_REPORT_BYTES", 250):
            assert client.post("/api/prefs", data="{}").status_code == 415
            assert client.post("/api/prefs", json={"title": "x", "offset": 10.1}).status_code == 400
            assert client.post("/api/prefs", json={"title": "x", "source": "bad:source"}).status_code == 400
            for title in ("a", "b", "c"):
                response = client.post("/api/prefs", json={"title": title, "source": "auto", "offset": 1})
                assert response.status_code == 200
            with open(prefs, encoding="utf-8") as f:
                saved = json.load(f)
            assert len(saved) == 2 and "a|" not in saved
            assert os.stat(prefs).st_mode & 0o777 == 0o600

            assert client.post("/api/report", data="{}").status_code == 415
            assert client.post("/api/report", json={"title": "x", "note": "x" * 501}).status_code == 400
            for _ in range(3):
                assert client.post("/api/report", json={"title": "song", "note": "ok"}).status_code == 200
            assert os.path.getsize(reports) <= app.MAX_REPORT_BYTES
            assert os.stat(reports).st_mode & 0o777 == 0o600
            with open(reports, encoding="utf-8") as f:
                records = [json.loads(line) for line in f if line.strip()]
            assert records and all("ip" not in record for record in records)


def test_expensive_routes_fail_fast_when_global_slots_are_full():
    client = app.app.test_client()
    with mock.patch.object(app._expensive_slots, "acquire", return_value=False), \
         mock.patch.object(app, "get_lyrics") as get_lyrics:
        response = client.get("/api/lyrics?title=test")
    assert response.status_code == 429
    assert get_lyrics.call_count == 0


def test_security_headers_cover_html_and_apis():
    client = app.app.test_client()
    html = client.get("/")
    assert "frame-ancestors 'none'" in html.headers.get("Content-Security-Policy", "")
    assert html.headers.get("X-Content-Type-Options") == "nosniff"
    with mock.patch.object(app, "_state_cache", {"data": {"ok": True}, "ts": time.time()}):
        state = client.get("/api/state")
    assert state.headers.get("Cache-Control") == "no-store"


def test_state_refresh_is_singleflight_and_errors_are_generic():
    app._state_cache.update(data=None, ts=0.0)
    entered = threading.Event()
    release = threading.Event()

    def fake_http(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return 200, json.dumps({"response": {"vehicle_state": {"media_info": {"now_playing_title": "Song"}}}})

    results = []
    with mock.patch.object(app, "get_access", return_value="token"), \
         mock.patch.object(app, "get_vin", return_value="VIN"), \
         mock.patch.object(app, "_http", side_effect=fake_http) as http:
        def request_state():
            results.append(app.app.test_client().get("/api/state"))

        first = threading.Thread(target=request_state)
        second = threading.Thread(target=request_state)
        first.start()
        assert entered.wait(3)
        second.start()
        time.sleep(0.1)
        release.set()
        first.join(3)
        second.join(3)
    assert len(results) == 2 and all(r.status_code == 200 for r in results)
    assert http.call_count == 1

    # A waiter must not revive an indefinitely old state when the request holding
    # the refresh lock fails without updating the cache.
    app._state_cache.update(data={"ok": True, "title": "ancient"}, ts=0.0)
    app._state_refresh_lock.acquire()
    waiting = []
    waiter = threading.Thread(target=lambda: waiting.append(app.app.test_client().get("/api/state")))
    waiter.start()
    time.sleep(0.1)
    app._state_refresh_lock.release()
    waiter.join(3)
    assert len(waiting) == 1 and waiting[0].status_code == 502

    app._state_cache.update(data=None, ts=0.0)
    with mock.patch.object(app, "get_access", side_effect=RuntimeError("SECRET_INTERNAL_VALUE")):
        response = app.app.test_client().get("/api/state")
    assert response.status_code == 502
    assert response.get_json() == {"ok": False, "error": "upstream_unavailable"}
    assert "SECRET_INTERNAL_VALUE" not in response.get_data(as_text=True)


if __name__ == "__main__":
    test_public_defaults_have_no_track_specific_overrides()
    test_song_query_rejects_unbounded_or_nonfinite_input()
    test_bounded_ttl_cache_evicts_old_entries()
    test_lrc_output_and_translation_work_are_strictly_bounded()
    test_duration_sensitive_cache_and_browser_local_preferences()
    test_translate_requires_json_bounds_work_and_keys_cache_by_content()
    test_prefs_and_reports_are_bounded_and_validated()
    test_expensive_routes_fail_fast_when_global_slots_are_full()
    test_security_headers_cover_html_and_apis()
    test_state_refresh_is_singleflight_and_errors_are_generic()
