#!/usr/bin/env python3
"""Private ZomRadar web server with PCAP-backed live fetch."""

import json
import os
import tempfile
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from urllib.parse import parse_qs, urlparse

from outputs.wos_saas import SESSION_SECONDS, SaaSStore
from outputs.wos_gather_scheduler import GatherScheduler

os.environ["WOS_DISABLE_DEFAULT_CAPTURES"] = "1"
from outputs.wos_live_roster import WosSession, bot_name_from_capture, endpoint, fpnn_alliance_id, fpnn_auth_frame, login_frame, msgpack_value


ROOT = Path(__file__).parent
DATA_DIR = Path(os.getenv("ZOMRADAR_DATA_DIR", ROOT / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
STORE = SaaSStore(DATA_DIR / "zomradar.db")
STORE.initialize()
ALL_FEATURES = ["alliance_search", "state_search", "gather", "auto_shield"]
LIVE_SESSIONS = {}
LIVE_SESSIONS_LOCK = Lock()
SCHEDULER_BOTS = {}

ALLIANCES = []
PLAYERS = []


def valid_state(value):
    return value.isdigit() and 1 <= int(value) <= 9999


def public_user(user):
    return {**user, "subscription": None, "features": ALL_FEATURES}


def bot_from_capture(capture):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as output:
            output.write(capture)
            temporary = Path(output.name)
        frame = fpnn_auth_frame(temporary)
        auth = msgpack_value(frame[16 + frame[7] :])
        token = auth.get("token")
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        if not isinstance(token, str) or len(token) < 20:
            raise ValueError("capture has no valid bot session")
        alliance_id = fpnn_alliance_id(temporary)
        uid = int(auth["uid"])
        try:
            name = bot_name_from_capture(temporary, uid)
        except (KeyError, OSError, TypeError, ValueError):
            name = None
        try:
            login_frame(temporary)
            gather_ready = True
        except (OSError, ValueError):
            gather_ready = False
        return {"id": f"{uid}-{alliance_id}", "name": name, "label": name or f"Bot UID {uid}", "uid": uid, "pid": int(auth["pid"]), "alliance_id": alliance_id, "state": alliance_id // 1_000_000, "remote": endpoint(temporary, 13321), "gather_ready": gather_ready}
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def owned_bot_from_capture(user, capture):
    bot = {**bot_from_capture(capture)}
    bot["id"] = f"{user['id']}:{bot['id']}"
    return bot


def user_bots(user):
    bots = []
    for saved in STORE.bot_captures():
        if saved["user_id"] == user["id"]:
            try:
                bot = owned_bot_from_capture(user, saved["capture"])
                SCHEDULER_BOTS[bot["id"]] = {**bot, "owner_id": user["id"]}
                bots.append(bot)
            except (KeyError, OSError, TypeError, ValueError, UnicodeDecodeError):
                pass
    return bots


def saved_user_bot(user, bot_id=None):
    for saved in STORE.bot_captures():
        if saved["user_id"] != user["id"]:
            continue
        bot = owned_bot_from_capture(user, saved["capture"])
        if bot_id is None or bot["id"] == bot_id:
            return saved, bot
    raise ValueError("select a valid uploaded bot")


def user_live_session(user, bot_id=None):
    with LIVE_SESSIONS_LOCK:
        saved, bot = saved_user_bot(user, bot_id)
        key = (user["id"], saved["uid"])
        if key in LIVE_SESSIONS:
            return LIVE_SESSIONS[key]
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as output:
                output.write(saved["capture"])
                temporary = Path(output.name)
            session = WosSession(temporary, rid=saved["uid"], state=bot["state"], bot=bot["id"])
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)
        LIVE_SESSIONS[key] = session
        return session


def scheduler_session(bot_id):
    bot = SCHEDULER_BOTS.get(bot_id)
    if not bot:
        raise ValueError("select a valid uploaded bot")
    return user_live_session({"id": bot["owner_id"]}, bot_id)


def scheduler_disconnect(bot_id):
    bot = SCHEDULER_BOTS.get(bot_id)
    session = LIVE_SESSIONS.get((bot["owner_id"], bot["uid"])) if bot else None
    if session:
        session.disconnect_gather()


def scheduler_start(bot_id, resource):
    session = scheduler_session(bot_id)
    return session.start_gather(resource, session.state, bot_id)


GATHER_SCHEDULER = GatherScheduler(
    STORE,
    SCHEDULER_BOTS,
    lambda bot_id, refresh: scheduler_session(bot_id).list_gathers(refresh),
    scheduler_start,
    scheduler_disconnect,
)


class Handler(BaseHTTPRequestHandler):
    server_version = "ZomRadar/1.0"

    def send_json(self, status, payload, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def current_user(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie["wos_session"].value if "wos_session" in cookie else None
        return STORE.session_user(token)

    def session_cookie(self, token, age=SESSION_SECONDS):
        secure = os.getenv("ZOMRADAR_SECURE_COOKIES") == "1" or self.headers.get("X-Forwarded-Proto") == "https"
        return f"wos_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{'; Secure' if secure else ''}"

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if self.headers.get_content_type() != "application/json" or not 0 < length <= 8192:
            raise ValueError("invalid JSON request")
        return json.loads(self.rfile.read(length))

    def require_user(self):
        user = self.current_user()
        if not user:
            self.send_json(401, {"error": "sign in required"})
        return user

    def do_POST(self):
        path = urlparse(self.path).path
        origin, host = self.headers.get("Origin"), self.headers.get("Host")
        if origin and origin not in {f"http://{host}", f"https://{host}"}:
            self.send_json(403, {"error": "request must come from this dashboard"})
            return
        if path in {"/api/auth/register", "/api/auth/login"}:
            try:
                data = self.read_json()
                user = STORE.register(data.get("email"), data.get("password"), data.get("display_name")) if path.endswith("register") else STORE.authenticate(data.get("email"), data.get("password"))
                self.send_json(200, {"user": public_user(user)}, {"Set-Cookie": self.session_cookie(STORE.create_session(user["id"]))})
            except (json.JSONDecodeError, TypeError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        user = self.require_user()
        if not user:
            return
        try:
            if path == "/api/auth/logout":
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
                STORE.logout(cookie["wos_session"].value if "wos_session" in cookie else None)
                self.send_json(200, {"signed_out": True}, {"Set-Cookie": self.session_cookie("", 0)})
            elif path == "/add-bot":
                length = int(self.headers.get("Content-Length", "0"))
                if self.headers.get_content_type() != "application/octet-stream" or not 0 < length <= 128 * 1024 * 1024:
                    raise ValueError("select a classic PCAP file up to 128 MB")
                capture = self.rfile.read(length)
                bot = owned_bot_from_capture(user, capture)
                STORE.save_bot_capture(user["id"], bot["uid"], capture)
                with LIVE_SESSIONS_LOCK:
                    old_session = LIVE_SESSIONS.pop((user["id"], bot["uid"]), None)
                    if old_session and old_session.connection:
                        old_session.connection.close()
                self.send_json(200, {"added": True, "bot": bot, "count": len(user_bots(user))})
            elif path == "/start-gather":
                data = self.read_json()
                bot = data.get("bot")
                session = user_live_session(user, bot)
                self.send_json(200, {"started": True, "gather": session.start_gather(data.get("resource"), session.state, bot)})
            elif path == "/recall-gather":
                data = self.read_json()
                bot, march_id = data.get("bot"), data.get("march_id")
                if not isinstance(march_id, int) or march_id <= 0:
                    raise ValueError("march_id must be a positive number")
                self.send_json(200, {"recalled": True, "gather": user_live_session(user, bot).recall_gather(march_id)})
            elif path == "/auto-shield":
                data = self.read_json()
                if not isinstance(data.get("enabled"), bool):
                    raise ValueError("enabled must be true or false")
                session = user_live_session(user, data.get("bot"))
                self.send_json(200, session.set_auto_shield(session.rid, data["enabled"]))
            elif path == "/gather-automation":
                data = self.read_json()
                bot_id = data.get("bot")
                _, bot = saved_user_bot(user, bot_id)
                if not bot["gather_ready"]:
                    raise ValueError("this bot needs a PCAP containing its game login")
                action = data.get("action")
                if action == "pause":
                    schedule = STORE.pause_gather_schedule(user["id"], bot_id)
                elif action == "start":
                    existing = STORE.gather_schedule(user["id"], bot_id)
                    if existing and existing["status"] == "active":
                        raise ValueError("pause the active gather schedule before starting a new one")
                    schedule = STORE.save_gather_schedule(
                        user["id"], bot_id, data.get("resources"), data.get("march_limit"),
                        data.get("total_cycles"), data.get("connection_mode"), data.get("infinite", False),
                    )
                    Thread(target=GATHER_SCHEDULER.tick, name="gather-start", daemon=True).start()
                else:
                    raise ValueError("action must be start or pause")
                self.send_json(200, {"schedule": schedule, "runs": STORE.gather_runs(schedule["id"]), "cooldown_seconds": 300})
            else:
                self.send_json(404, {"error": "not found"})
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            self.send_json(400, {"error": str(error)})
        except (ConnectionError, OSError, RuntimeError) as error:
            self.send_json(502, {"error": str(error)})

    def do_GET(self):
        request = urlparse(self.path)
        path, query = request.path, parse_qs(request.query)
        if path in {"/", "/dashboard", "/wos_search_dashboard.html"}:
            body = (ROOT / "outputs" / "wos_search_dashboard.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if path == "/health":
            self.send_json(200, {"ok": True, "mode": "private-live", "pcap_upload_enabled": True})
            return
        user = self.require_user()
        if not user:
            return
        if path == "/api/session":
            self.send_json(200, {"user": public_user(user)})
        elif path in {"/bots", "/gather-bots"}:
            self.send_json(200, {"results": user_bots(user)})
        elif path == "/gathers":
            bot = query.get("bot", [""])[0]
            try:
                session = user_live_session(user, bot)
                self.send_json(200, {"live": True, "bot": bot, "connection": {"game_connected": bool(session.connection), "chat_connected": False}, "results": session.list_gathers(query.get("refresh", ["0"])[0] == "1")})
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                self.send_json(502, {"error": str(error)})
        elif path == "/gather-automation":
            bot = query.get("bot", [""])[0]
            try:
                session = user_live_session(user, bot)
                schedule = STORE.gather_schedule(user["id"], bot)
                runs = STORE.gather_runs(schedule["id"]) if schedule else []
                self.send_json(200, {"schedule": schedule, "connection": {"game_connected": bool(session.connection), "chat_connected": False}, "runs": runs, "cooldown_seconds": 300})
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                self.send_json(502, {"error": str(error)})
        elif path == "/auto-shield":
            bot = query.get("bot", [""])[0]
            try:
                session = user_live_session(user, bot)
                self.send_json(200, {"bot": next(row for row in user_bots(user) if row["id"] == bot), **session.auto_shield_status()})
            except (ConnectionError, OSError, RuntimeError, StopIteration, ValueError) as error:
                self.send_json(502, {"error": str(error)})
        elif path in {"/scout-reports", "/live-attacks"}:
            self.send_json(200, {"results": []})
        elif path == "/state-cache":
            state = query.get("state", [""])[0]
            if not valid_state(state):
                self.send_json(400, {"error": "state must be a number from 1 to 9999"})
                return
            rows = []
            self.send_json(200, {"cached": False, "storage": "saved", "state": int(state), "complete": True, "results": rows})
        elif path in {"/alliances", "/players", "/profiles"}:
            self.send_json(200, {"results": ALLIANCES if path == "/alliances" else PLAYERS})
        elif path == "/alliance-details":
            alliance = next((row for row in ALLIANCES if str(row["id"]) == query.get("id", [""])[0]), None)
            self.send_json(200 if alliance else 404, {"stored": True, "alliance": alliance} if alliance else {"error": "alliance not found"})
        elif path == "/roster":
            alliance_id = query.get("id", [""])[0]
            members = []
            self.send_json(200, {"stored": True, "alliance_id": int(alliance_id) if alliance_id.isdigit() else None, "members": members, "coordinates_available": bool(members)})
        elif path == "/details-2":
            value = query.get("rid", [""])[0]
            if not value.isdigit():
                self.send_json(400, {"error": "rid must contain digits only"})
                return
            rid = int(value)
            player = next((row for row in PLAYERS if row["rid"] == rid), None)
            self.send_json(200, {"stored": True, "rid": rid, "power": {"position": PLAYERS.index(player) + 1, "value": player["power"], "alliance_rank": player["rank"]}, "ko": None, "daily_contribution": None, "restricted_reason": "No saved details"} if player else {"error": "player not found"})
        elif path == "/live-state":
            state, start, count, bot = query.get("state", [""])[0], query.get("start", ["0"])[0], query.get("count", ["40"])[0], query.get("bot", [""])[0]
            if not valid_state(state) or not start.isdigit() or not 0 <= int(start) <= 1600 or not count.isdigit() or not 1 <= int(count) <= 100:
                self.send_json(400, {"error": "state, start, or count is outside the supported range"})
                return
            try:
                batch = user_live_session(user, bot).fetch_alliances(int(state), int(start), int(count))
                self.send_json(200, {"live": True, "stored": False, "state": int(state), **batch})
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                self.send_json(502, {"error": str(error)})
        elif path in {"/live-alliance-details", "/live-roster"}:
            alliance_id, bot = query.get("id", [""])[0], query.get("bot", [""])[0]
            if not alliance_id.isdigit():
                self.send_json(400, {"error": "id must contain digits only"})
                return
            alliance_id = int(alliance_id)
            try:
                session = user_live_session(user, bot)
                if path == "/live-alliance-details":
                    self.send_json(200, {"live": True, "stored": False, "protocol": 5138, "alliance": session.fetch_alliance_details(alliance_id, alliance_id // 1_000_000)})
                else:
                    members = session.fetch_roster(alliance_id, alliance_id // 1_000_000)
                    self.send_json(200, {"live": True, "stored": False, "alliance_id": alliance_id, "members": members, "coordinates_available": any(member.get("x") is not None and member.get("y") is not None for member in members)})
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                self.send_json(502, {"error": str(error)})
        elif path == "/live-details-2":
            rid, bot = query.get("rid", [""])[0], query.get("bot", [""])[0]
            if not rid.isdigit():
                self.send_json(400, {"error": "rid must contain digits only"})
                return
            try:
                self.send_json(200, {"live": True, "stored": False, **user_live_session(user, bot).fetch_details2(int(rid))})
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                self.send_json(502, {"error": str(error)})
        elif path.startswith("/live-"):
            self.send_json(503, {"error": "this live action is not connected to the uploaded PCAP yet"})
        else:
            self.send_json(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    print(f"ZomRadar: http://127.0.0.1:{port}")
    for saved in STORE.bot_captures():
        try:
            bot = owned_bot_from_capture({"id": saved["user_id"]}, saved["capture"])
            SCHEDULER_BOTS[bot["id"]] = {**bot, "owner_id": saved["user_id"]}
        except (KeyError, OSError, TypeError, ValueError, UnicodeDecodeError):
            pass
    GATHER_SCHEDULER.start()
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
