import importlib.util
import os
from pathlib import Path
from unittest import mock

os.environ["DISABLE_MXM_WARMUP"] = "1"

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
spec = importlib.util.spec_from_file_location("tesla_nowplaying_app", APP_PATH)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def main():
    client = app.app.test_client()

    bad_lrc = "[00:00.00-1] 作词 : Example Writer\n[00:00.00-1] 作曲 : Example Composer\n"
    good_lrc = "\n".join(f"[00:{i:02d}.00]line {i}" for i in range(5))

    def fake_fetch_netease_id(song_id):
        return bad_lrc if song_id == "bad" else good_lrc

    with mock.patch.object(app, "recover_native_meta", lambda title, artist, duration: []), \
         mock.patch.object(app, "search_lrclib", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_petitlyrics", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_kugou", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_netease", lambda title, artist, duration, limit=5: [
             {
                 "id": "netease:bad",
                 "source": "netease",
                 "title": "Example Track",
                 "artist": "Example Artist",
                 "album": "Demo Album",
                 "duration": 240,
                 "score": 82,
             },
             {
                 "id": "netease:good",
                 "source": "netease",
                 "title": "Example Track",
                 "artist": "Example Artist",
                 "album": "Demo Album",
                 "duration": 240,
                 "score": 80,
             },
         ]), \
         mock.patch.object(app, "fetch_netease_id", fake_fetch_netease_id):
        response = client.get("/api/candidates?title=Example+Track&artist=Example+Artist&duration=240")

    assert response.status_code == 200, response.status_code
    data = response.get_json()
    got = [candidate["id"] for candidate in data["candidates"]]
    assert got == ["netease:good"], got

    petit_lrc = "\n".join(f"[00:{i:02d}.00]petit {i}" for i in range(5))
    petit_id = "petitlyrics:test-token"
    with mock.patch.object(app, "recover_native_meta", lambda title, artist, duration: []), \
         mock.patch.object(app, "search_lrclib", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_netease", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_kugou", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_petitlyrics", lambda title, artist, duration, limit=5: [
             {
                 "id": petit_id,
                 "source": "petitlyrics",
                 "title": "Example Track",
                 "artist": "Example Artist",
                 "album": "Demo Album",
                 "duration": 240,
                 "score": 92,
             }
         ]), \
         mock.patch.object(app, "fetch_petitlyrics_id", lambda token: petit_lrc):
        response = client.get("/api/candidates?title=Example+Track&artist=Example+Artist&duration=240")
        data = response.get_json()
        got = [candidate["id"] for candidate in data["candidates"]]
        assert got == [petit_id], got

        response = client.get("/api/lyrics?title=Example+Track&artist=Example+Artist&duration=240&source=" + petit_id)
        data = response.get_json()
        assert data["found"] is True, data
        assert data["source"] == petit_id, data
        assert len(data["lines"]) == 5, data["lines"]

    unrelated_lrc = "\n".join(f"[00:{i:02d}.00]wrong song {i}" for i in range(5))
    with mock.patch.object(app, "recover_native_meta", lambda title, artist, duration: []), \
         mock.patch.object(app, "search_lrclib", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_petitlyrics", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_kugou", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_netease", lambda title, artist, duration, limit=5: [
             {
                 "id": "netease:unrelated",
                 "source": "netease",
                 "title": "Unrelated Track",
                 "artist": "Unrelated Performer",
                 "album": "Other Album",
                 "duration": 180,
                 "score": 80,
             }
         ]), \
         mock.patch.object(app, "fetch_netease_id", lambda song_id: unrelated_lrc):
        response = client.get("/api/candidates?title=Example+Track&artist=Example+Artist&duration=240")
        data = response.get_json()
        assert data["candidates"] == [], data

    # Known title/artist mismatches must fail closed even when duration is close.
    aliases = ["Example Artist"]
    assert app._match_ok(
        "Example Track", "Example Artist", 240,
        "Example Track", "Unrelated Performer", 240, aliases,
    ) is False
    assert app._match_ok(
        "Example Track", "Example Artist", 240,
        "Unrelated Track", "Example Artist", 240, aliases,
    ) is False
    assert app._match_ok(
        "Example Track", "Example Artist", 240,
        "Example Track", "Example Artist", 240, aliases,
    ) is True

    # PetitLyrics can return multiple songs; automatic fetch must skip an
    # unrelated first row instead of accepting its usable lyric body.
    wrong_song = mock.Mock()
    correct_song = mock.Mock()
    correct_song.findtext.return_value = "encoded"
    root = mock.Mock()
    root.findall.return_value = [wrong_song, correct_song]
    wrong_meta = {
        "lyrics_id": "wrong",
        "title": "Example Track",
        "artist": "Unrelated Performer",
        "album": "Other Album",
        "duration": 240,
    }
    correct_meta = {
        "lyrics_id": "correct",
        "title": "Example Track",
        "artist": "Example Artist",
        "album": "Demo Album",
        "duration": 240,
    }
    with mock.patch.object(app, "_petit_call", return_value=root), \
         mock.patch.object(app, "_petit_song_meta", side_effect=[wrong_meta, correct_meta]), \
         mock.patch.object(app, "_petit_decode_lyrics_data", return_value="<wsy/>"), \
         mock.patch.object(app, "_petit_wordxml_to_lrc", return_value=petit_lrc), \
         mock.patch.object(app, "artist_query_aliases", return_value=aliases):
        assert app.fetch_petitlyrics("Example Track", "Example Artist", 240) == petit_lrc
    assert app._PICK["petitlyrics"]["id"] == "correct"

    # The source picker applies the same identity gate before probing lyrics.
    app._candidate_usable_cache.clear()
    with mock.patch.object(app, "recover_native_meta", lambda title, artist, duration: []), \
         mock.patch.object(app, "search_lrclib", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_netease", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_kugou", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_petitlyrics", lambda title, artist, duration, limit=5: [
             {
                 "id": "petitlyrics:unrelated",
                 "source": "petitlyrics",
                 "title": "Unrelated Track",
                 "artist": "Unrelated Performer",
                 "album": "Other Album",
                 "duration": 180,
                 "score": 90,
             }
         ]), \
         mock.patch.object(app, "fetch_petitlyrics_id", return_value=unrelated_lrc) as fetch:
        response = client.get("/api/candidates?title=Example+Track&artist=Example+Artist&duration=240")
    assert response.get_json()["candidates"] == []
    fetch.assert_not_called()

    app._candidate_usable_cache.clear()
    transient = {"id": "lrclib:transient", "source": "lrclib"}
    with mock.patch.object(app, "fetch_lrclib_id", side_effect=TimeoutError("temporary")) as fetch:
        assert app.candidate_has_usable_lyrics(transient) is False
        assert app.candidate_has_usable_lyrics(transient) is False
    assert fetch.call_count == 2
    assert "lrclib:transient" not in app._candidate_usable_cache


if __name__ == "__main__":
    main()
