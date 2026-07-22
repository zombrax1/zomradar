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


if __name__ == "__main__":
    test_user_live_session_reuses_private_capture()
