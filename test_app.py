from pathlib import Path
from email.utils import format_datetime
from datetime import datetime, timezone
from tempfile import TemporaryDirectory
from unittest.mock import patch

import app
from outputs.wos_avatar_cache import AvatarCache, avatar_epoch


def test_user_live_session_reuses_private_capture():
    app.LIVE_SESSIONS.clear()
    session = object()
    saved = {"user_id": 7, "uid": 42, "capture": b"pcap"}
    bot = {"id": "42-1642000001", "state": 1642}
    with patch.object(app, "saved_user_bot", return_value=(saved, bot)), patch.object(app, "WosSession", return_value=session) as constructor:
        assert app.user_live_session({"id": 7}, bot["id"]) is session
        assert app.user_live_session({"id": 7}, bot["id"]) is session
        assert constructor.call_count == 1


def test_bot_without_name_has_visible_label():
    with patch.object(app, "fpnn_auth_frame", return_value=b"\0" * 16), patch.object(app, "msgpack_value", return_value={"token": "x" * 20, "uid": 42, "pid": 8}), patch.object(app, "fpnn_alliance_id", return_value=1642000001), patch.object(app, "bot_name_from_capture", return_value=None), patch.object(app, "login_frame"), patch.object(app, "endpoint", return_value=("127.0.0.1", 13321)):
        assert app.bot_from_capture(b"pcap")["label"] == "Bot UID 42"


def test_bot_ids_are_scoped_to_the_signed_in_user():
    with patch.object(app, "bot_from_capture", return_value={"id": "42-1642000001"}):
        assert app.owned_bot_from_capture({"id": 7}, b"pcap")["id"] == "7:42-1642000001"
        assert app.owned_bot_from_capture({"id": 8}, b"pcap")["id"] == "8:42-1642000001"


def test_primary_actions_do_not_open_confirmations():
    dashboard = Path(__file__).with_name("outputs").joinpath("wos_search_dashboard.html").read_text(encoding="utf-8")
    assert "if(!confirm(`Server reports" not in dashboard
    assert "if(enabled&&!confirm(" not in dashboard


def test_roster_and_details_render_player_profile_pictures():
    dashboard = Path(__file__).with_name("outputs").joinpath("wos_search_dashboard.html").read_text(encoding="utf-8")
    assert "function playerAvatar(player,large=false)" in dashboard
    assert "player.avatar_url" in dashboard
    assert "profile picture" in dashboard
    assert "playerAvatar(p)" in dashboard
    assert "playerAvatar(player,true)" in dashboard


def test_avatar_cache_matches_protocol_timestamp_without_player_hardcoding(tmp_path):
    epoch = 1741285985
    entry = tmp_path / "any-cache-key"
    entry.mkdir()
    modified = format_datetime(datetime.fromtimestamp(epoch + 1, timezone.utc), usegmt=True)
    (entry / "headers.cache").write_bytes(f"Last-Modified:{modified}\n".encode("ascii"))
    image = b"\x89PNG\r\n\x1a\nplayer-photo"
    (entry / "content.cache").write_bytes(image)

    cache = AvatarCache(local_root=tmp_path, adb="missing-adb")
    assert cache.resolve(f"2025/03/06/rqOPrW_{epoch}.png") == image
    assert cache.resolve("../../private.png") is None
    assert avatar_epoch(f"2025/03/06/rqOPrW_{epoch}.png") == epoch


def test_player_avatar_url_is_same_origin_and_path_based():
    player = app.with_local_avatar({"rid": 7, "avatar_path": "2025/03/06/rqOPrW_1741285985.png"})
    assert player["avatar_url"].startswith("/avatar?path=")
    assert "gof-formal-avatar" not in player["avatar_url"]


def test_alliance_search_chooses_a_game_bot_automatically():
    dashboard = Path(__file__).with_name("outputs").joinpath("wos_search_dashboard.html").read_text(encoding="utf-8")
    assert "stateBot" not in dashboard
    assert "function automaticGameBot(state)" in dashboard
    assert "bot.state===Number(state)" in dashboard
    assert "start+=10" in dashboard
    assert "count=10" in dashboard


def test_no_sample_mode_remains():
    root = Path(__file__).parent
    for path in (root / "app.py", root / "outputs" / "wos_search_dashboard.html"):
        assert "de" + "mo" not in path.read_text(encoding="utf-8").lower()


if __name__ == "__main__":
    test_user_live_session_reuses_private_capture()
    test_bot_without_name_has_visible_label()
    test_bot_ids_are_scoped_to_the_signed_in_user()
    test_primary_actions_do_not_open_confirmations()
    test_roster_and_details_render_player_profile_pictures()
    with TemporaryDirectory() as directory:
        test_avatar_cache_matches_protocol_timestamp_without_player_hardcoding(Path(directory))
    test_player_avatar_url_is_same_origin_and_path_based()
    test_alliance_search_chooses_a_game_bot_automatically()
    test_no_sample_mode_remains()
