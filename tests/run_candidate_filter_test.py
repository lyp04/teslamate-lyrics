import os
import sys
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import app


def main():
    client = app.app.test_client()

    bad_lrc = "[00:00.00-1] 作词 : Layla.\n[00:00.00-1] 作曲 : 日向空\n"
    good_lrc = "\n".join(f"[00:{i:02d}.00]line {i}" for i in range(5))

    def fake_fetch_netease_id(song_id):
        return bad_lrc if song_id == "bad" else good_lrc

    with mock.patch.object(app, "recover_native_meta", lambda title, artist, duration: []), \
         mock.patch.object(app, "search_lrclib", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_kugou", lambda title, artist, duration, limit=5: []), \
         mock.patch.object(app, "search_netease", lambda title, artist, duration, limit=5: [
             {
                 "id": "netease:bad",
                 "source": "netease",
                 "title": "Lemon.",
                 "artist": "Layla.",
                 "album": "episode",
                 "duration": 286,
                 "score": 82,
             },
             {
                 "id": "netease:good",
                 "source": "netease",
                 "title": "Lemon.",
                 "artist": "Layla.",
                 "album": "episode",
                 "duration": 286,
                 "score": 80,
             },
         ]), \
         mock.patch.object(app, "fetch_netease_id", fake_fetch_netease_id):
        response = client.get("/api/candidates?title=Lemon.&artist=Layla.&duration=286")

    assert response.status_code == 200, response.status_code
    data = response.get_json()
    got = [candidate["id"] for candidate in data["candidates"]]
    assert got == ["netease:good"], got


if __name__ == "__main__":
    main()
