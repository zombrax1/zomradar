from unittest.mock import patch

import app


class SavedCapture:
    def bot_captures(self):
        return [{"user_id": 7, "uid": 42, "capture": b"pcap"}]


def test_user_live_session_reuses_private_capture():
    app.LIVE_SESSIONS.clear()
    session = object()
    with patch.object(app, "STORE", SavedCapture()), patch.object(app, "WosSession", return_value=session) as constructor:
        assert app.user_live_session({"id": 7}) is session
        assert app.user_live_session({"id": 7}) is session
        assert constructor.call_count == 1


def test_bot_without_name_has_visible_label():
    with patch.object(app, "fpnn_auth_frame", return_value=b"\0" * 16), patch.object(app, "msgpack_value", return_value={"token": "x" * 20, "uid": 42, "pid": 8}), patch.object(app, "fpnn_alliance_id", return_value=1642000001), patch.object(app, "bot_name_from_capture", return_value=None), patch.object(app, "login_frame"), patch.object(app, "endpoint", return_value=("127.0.0.1", 13321)):
        assert app.bot_from_capture(b"pcap")["label"] == "Bot UID 42"


if __name__ == "__main__":
    test_user_live_session_reuses_private_capture()
    test_bot_without_name_has_visible_label()
