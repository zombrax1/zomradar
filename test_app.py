from pathlib import Path
from unittest.mock import patch

import app


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


def test_primary_actions_do_not_open_confirmations():
    dashboard = Path(__file__).with_name("outputs").joinpath("wos_search_dashboard.html").read_text(encoding="utf-8")
    assert "if(!confirm(`Server reports" not in dashboard
    assert "if(enabled&&!confirm(" not in dashboard


def test_no_sample_mode_remains():
    root = Path(__file__).parent
    for path in (root / "app.py", root / "outputs" / "wos_search_dashboard.html"):
        assert "de" + "mo" not in path.read_text(encoding="utf-8").lower()


if __name__ == "__main__":
    test_user_live_session_reuses_private_capture()
    test_bot_without_name_has_visible_label()
    test_primary_actions_do_not_open_confirmations()
    test_no_sample_mode_remains()
