#!/usr/bin/env python3
"""Local WOS search and authenticated bot-control API."""

import argparse
import ipaddress
import json
import os
import tempfile
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from urllib.parse import parse_qs, urlparse

from wos_live_roster import HANDSHAKE, add_map_data, bot_connection_state, bot_name_from_capture, cached_map_players, current_alliance_id, disconnect_gather_session, endpoint, fetch_alliance_details, fetch_alliances as fetch_state_alliances, fetch_attacks, fetch_auto_shield, fetch_chat_metadata, fetch_details2, fetch_dm_conversations, fetch_dm_history, fetch_gathers, fetch_reinforcements, fetch_roster, fetch_scout_reports, fpnn_alliance_id, fpnn_auth_frame, msgpack_value, recall_gather, register_chat_bot, register_gather_session, restore_gather_runs, restore_map_players, set_auto_shield, set_gather_identity, start_gather
from wos_gather_scheduler import GatherScheduler
from wos_mysql import configured_store
from wos_saas import SESSION_SECONDS, SaaSStore


DATA = json.loads(Path(__file__).with_name("wos_observed_data.json").read_text(encoding="utf-8"))
CACHE_PATH = Path(__file__).with_name("wos_state_cache.json")
try:
    STATE_CACHE = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
except (FileNotFoundError, json.JSONDecodeError, OSError):
    STATE_CACHE = {}
for cached_state, entry in STATE_CACHE.items():
    if isinstance(entry, dict):
        restore_map_players(cached_state, entry.get("map_players", []))
GATHER_HISTORY = STATE_CACHE.setdefault("gather_history", [])
GATHER_LOGGED = {(item.get("bot"), item.get("march_id")) for item in GATHER_HISTORY if isinstance(item, dict)}


def save_state_cache():
    temporary = CACHE_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(STATE_CACHE, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    temporary.replace(CACHE_PATH)


def clean(text):
    for _ in range(2):
        try:
            candidate = text.encode("latin1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            break
        if candidate.count("�") > text.count("�"):
            break
        text = candidate
    return text.replace("\u00a0", " ")


def bot_from_capture(path, bot_id=None):
    frame = fpnn_auth_frame(path)
    auth = msgpack_value(frame[16 + frame[7] :])
    token = auth.get("token")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    if not isinstance(token, str) or len(token) < 20:
        raise ValueError("capture has no valid FPNN bot token")
    alliance_id = fpnn_alliance_id(path)
    uid = int(auth["uid"])
    return {
        "id": bot_id or f"{uid}-{alliance_id}",
        "name": bot_name_from_capture(path, uid),
        "uid": uid,
        "pid": int(auth["pid"]),
        "alliance_id": alliance_id,
        "state": alliance_id // 1_000_000,
        "auth": frame,
        "remote": endpoint(path, 13321),
    }


def public_bot(bot):
    return {**{key: bot.get(key) for key in ("id", "name", "uid", "pid", "alliance_id", "state")}, "gather_ready": bool(bot.get("gather_ready"))}


def owned_bot(bot, user):
    return user is None or bot.get("owner_id") == user["id"]


def user_bots(user):
    return [bot for bot in BOTS.values() if owned_bot(bot, user)]


DEFAULT_BOT = bot_from_capture(HANDSHAKE, "default")
DEFAULT_BOT["gather_ready"] = True
BOTS = {"default": DEFAULT_BOT}
set_gather_identity("default", DEFAULT_BOT["uid"])

SAAS = SaaSStore(Path(os.getenv("WOS_SAAS_DATABASE", Path(__file__).with_name("wos_saas.db"))))
SAAS.initialize()


def restore_saved_bots():
    for saved in SAAS.bot_captures():
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as output:
                temporary = Path(output.name)
                output.write(saved["capture"])
            bot = bot_from_capture(temporary)
            bot["id"] = f"{saved['user_id']}:{bot['id']}"
            bot["owner_id"] = saved["user_id"]
            register_chat_bot(bot["id"], bot["auth"], bot["remote"], bot["alliance_id"])
            try:
                register_gather_session(bot["id"], temporary, bot["state"], bot["uid"])
                bot["gather_ready"] = True
            except (OSError, ValueError):
                bot["gather_ready"] = False
            BOTS[bot["id"]] = bot
        except (KeyError, OSError, TypeError, ValueError):
            pass
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)


restore_saved_bots()
for saved_schedule in SAAS.active_gather_schedules():
    if saved_schedule["bot_id"] in BOTS:
        restore_gather_runs(saved_schedule["bot_id"], SAAS.gather_runs(saved_schedule["id"], 500))
FEATURES = {
    "/alliances": "alliance_search", "/alliance": "alliance_search", "/alliance-details": "alliance_search",
    "/roster": "alliance_search", "/players": "alliance_search", "/profiles": "alliance_search",
    "/player": "alliance_search", "/details-2": "alliance_search", "/live-attacks": "alliance_search",
    "/scout-reports": "alliance_search", "/live-dms": "alliance_search", "/live-dm": "alliance_search",
    "/state-cache": "state_search", "/live-state": "state_search", "/live-alliance-details": "state_search",
    "/live-roster": "state_search", "/live-details-2": "state_search", "/live-reinforcements": "state_search",
    "/gathers": "gather", "/start-gather": "gather", "/recall-gather": "gather",
    "/gather-automation": "gather",
    "/auto-shield": "auto_shield",
}


def bot_token_from_capture(path):
    frame = fpnn_auth_frame(path)
    token = msgpack_value(frame[16 + frame[7] :]).get("token")
    return token.decode("utf-8") if isinstance(token, bytes) else token


CAPTURE = {
    "source": DATA["source"],
    "live": False,
    "capture_only": True,
    "protocol_query_proven": True,
    "live_bridge": "requires MuMu's current authenticated session; no token is stored here",
}

ALLIANCES = [{**a, "name": clean(a["name"]), "leader_name": clean(a.get("leader_name", ""))}
             for a in DATA["alliances"]]
PROFILES = [{**p, "name": clean(p["name"]), "alliance_name": clean(p["alliance_name"])}
            for p in DATA["profiles"]]
PLAYERS = {str(p["player_id"]): p for p in PROFILES}
LIVE_ROSTERS = {}
LIVE_METADATA = {}
LIVE_STATES = {}
LIVE_LOCK = Lock()
TRANSFER_STATE_MIN = 1492
TRANSFER_STATE_MAX = 1894
MYSQL_STORE = None
MYSQL_ERROR = None


def initialize_mysql():
    global MYSQL_STORE, MYSQL_ERROR
    try:
        MYSQL_STORE = configured_store()
        if MYSQL_STORE:
            MYSQL_STORE.initialize()
        MYSQL_ERROR = None
    except Exception as error:
        MYSQL_STORE = None
        MYSQL_ERROR = str(error)


def mysql_call(method, *args):
    global MYSQL_ERROR
    if not MYSQL_STORE:
        return None
    try:
        result = getattr(MYSQL_STORE, method)(*args)
        MYSQL_ERROR = None
        return result
    except Exception as error:
        MYSQL_ERROR = str(error)
        return None


def log_returned_gather(item):
    key = (item.get("bot"), item.get("march_id"))
    if key in GATHER_LOGGED:
        return
    GATHER_LOGGED.add(key)
    entry = {**item, "logged_at": int(time.time())}
    GATHER_HISTORY.append(entry)
    mysql_call("save_gather", entry)
    save_state_cache()


GATHER_SCHEDULER = GatherScheduler(SAAS, BOTS, fetch_gathers, start_gather, disconnect_gather_session, log_returned_gather)


def valid_transfer_state(value):
    return value.isdigit() and TRANSFER_STATE_MIN <= int(value) <= TRANSFER_STATE_MAX


def match(value, query):
    return not query or query.casefold() in str(value).casefold()


def roster_power_rank(members, rid):
    for position, member in enumerate(sorted(members, key=lambda row: row["power"], reverse=True), 1):
        if member["rid"] == rid:
            return {"position": position, "value": member["power"], "alliance_rank": member.get("rank")}
    return None


def alliance_result(abbr, query=""):
    alliance = next((a for a in ALLIANCES if a["tag"].casefold() == abbr.casefold()), None)
    if not alliance:
        return None
    members = [p for p in PROFILES if p["alliance_id"] == alliance["id"] and match(p["name"], query)]
    result = {k: v for k, v in alliance.items() if k not in {"id"}}
    result["alliance_id"] = alliance["id"]
    result["members"] = members
    result["members_returned"] = len(members)
    return result


def response(path, query, user=None):
    if path == "/":
        return 200, {"name": "WOS capture search API", "endpoints": [
            "/health", "/live-attacks", "/live-dms", "/live-dm?rid=61586536", "/alliances?q=bdl", "/alliance?abbr=BDL&q=lady", "/players?q=katak", "/player?id=245773508"
        ]}
    if path == "/health":
        return 200, {"ok": True, **CAPTURE, "alliances": len(ALLIANCES), "profiles": len(PROFILES), "transfer_state_min": TRANSFER_STATE_MIN, "transfer_state_max": TRANSFER_STATE_MAX, "mysql": {"configured": MYSQL_STORE is not None, "error": MYSQL_ERROR}}
    if path == "/bots":
        return 200, {"selection": "automatic by matching state, exact alliance preferred", "results": [public_bot(bot) for bot in user_bots(user)]}
    if path == "/gather-bots":
        return 200, {"results": [{**public_bot(bot), "label": f"{bot.get('name') or ('Bot UID ' + str(bot['uid']))} · State {bot['state']}"} for bot in user_bots(user)]}
    if path == "/scout-reports":
        return 200, {"capture_only": True, "results": fetch_scout_reports()}
    if path == "/gathers":
        bot = query.get("bot", [""])[0]
        if bot and (bot not in BOTS or not owned_bot(BOTS[bot], user)):
            return 400, {"error": "unknown gather bot"}
        schedule = SAAS.gather_schedule(user["id"], bot) if user and bot else None
        items = fetch_gathers(bot or None, query.get("refresh", ["0"])[0] == "1")
        for item in items:
            if item.get("status") == "returned":
                log_returned_gather(item)
        if schedule and schedule["status"] == "active" and schedule["connection_mode"] == "disconnect":
            disconnect_gather_session(bot)
        return 200, {"live": True, "bot": bot or None, "connection": bot_connection_state(bot) if bot else None, "results": [item for item in items if item.get("status") != "returned"]}
    if path == "/gather-automation":
        bot = query.get("bot", [""])[0]
        if bot not in BOTS or not owned_bot(BOTS[bot], user):
            return 400, {"error": "select a valid game bot"}
        schedule = SAAS.gather_schedule(user["id"], bot)
        runs = [run for run in SAAS.gather_runs(schedule["id"]) if run["status"] != "returned"] if schedule else []
        return 200, {"schedule": schedule, "connection": bot_connection_state(bot), "runs": runs, "cooldown_seconds": 300}
    if path == "/auto-shield":
        bot = query.get("bot", [""])[0]
        if bot not in BOTS or not owned_bot(BOTS[bot], user) or not BOTS[bot].get("gather_ready"):
            return 400, {"error": "select a valid game bot"}
        return 200, {"bot": public_bot(BOTS[bot]), **fetch_auto_shield(bot)}
    if path == "/alliances":
        q = query.get("q", [""])[0]
        rows = [a for a in ALLIANCES if match(a["tag"], q) or match(a["name"], q)]
        return 200, {"capture": CAPTURE, "results": rows}
    if path == "/live-attacks":
        alliance_id = query.get("alliance_id", [""])[0]
        if alliance_id and not alliance_id.isdigit():
            return 400, {"error": "alliance_id must contain digits only"}
        alliance_id = int(alliance_id) if alliance_id else None
        with LIVE_LOCK:
            known_profiles = {
                member["rid"]: member
                for member in PROFILES + [member for members in LIVE_ROSTERS.values() for member in members]
            }
            known_alliances = {
                alliance["id"]: alliance
                for alliance in (
                    ALLIANCES
                    + [row for rows in LIVE_STATES.values() for row in rows]
                    + [row for entry in STATE_CACHE.values() if isinstance(entry, dict) for row in entry.get("results", [])]
                )
            }
        selected_alliance = known_alliances.get(alliance_id, {})
        results = []
        for event in fetch_attacks():
            item = dict(event)
            for role in ("attacker", "target"):
                player = known_profiles.get(item.get(f"{role}_rid"), {})
                for field in ("name", "player_id", "power", "alliance_id", "alliance_tag", "alliance_name"):
                    if field in player:
                        item[f"{role}_{field}"] = clean(player[field]) if isinstance(player[field], str) else player[field]
            alliance = known_alliances.get(item.get("target_alliance_id"), {})
            item.setdefault("target_alliance_tag", clean(alliance.get("tag", "")))
            item.setdefault("target_alliance_name", clean(alliance.get("name", "")))
            tag_match = (
                selected_alliance.get("state") == item.get("state")
                and selected_alliance.get("tag") in (item.get("attacker_alliance_tag"), item.get("target_alliance_tag"))
            )
            if alliance_id is not None and alliance_id not in (item.get("attacker_alliance_id"), item.get("target_alliance_id")) and not tag_match:
                continue
            results.append(item)
        return 200, {"live": True, "capture_seeded": True, "alliance_id": alliance_id, "results": results}
    if path == "/live-dms":
        bot = query.get("bot", ["default"])[0] or "default"
        if bot not in BOTS or not owned_bot(BOTS[bot], user):
            return 400, {"error": "unknown chat bot"}
        try:
            rows = fetch_dm_conversations(bot)
        except (ConnectionError, OSError, RuntimeError, ValueError) as error:
            return 502, {"error": str(error)}
        return 200, {"live": True, "scope": "selected authenticated account only", "bot": public_bot(BOTS[bot]), "results": rows}
    if path == "/live-dm":
        bot = query.get("bot", ["default"])[0] or "default"
        if bot not in BOTS or not owned_bot(BOTS[bot], user):
            return 400, {"error": "unknown chat bot"}
        rid = query.get("rid", [""])[0]
        last_id = query.get("lastid", ["0"])[0]
        if not rid.isdigit() or not last_id.isdigit():
            return 400, {"error": "rid and lastid must contain digits only"}
        rid, last_id = int(rid), int(last_id)
        if not 0 < rid <= 0xFFFFFFFF or not 0 <= last_id <= 0xFFFFFFFF:
            return 400, {"error": "rid or lastid is outside the supported range"}
        try:
            result = fetch_dm_history(rid, last_id, bot)
        except (ConnectionError, OSError, RuntimeError, ValueError) as error:
            return 502, {"error": str(error)}
        return 200, {"live": True, "scope": "selected authenticated account only", "bot": public_bot(BOTS[bot]), **result}
    if path == "/live-alliance-details":
        alliance_id = query.get("id", [""])[0]
        if not alliance_id.isdigit():
            return 400, {"error": "id must contain digits only"}
        alliance_id = int(alliance_id)
        with LIVE_LOCK:
            try:
                details = fetch_alliance_details(alliance_id, alliance_id // 1_000_000)
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                return 502, {"error": str(error)}
        mysql_call("save_alliance", details)
        return 200, {"live": True, "stored": MYSQL_STORE is not None and MYSQL_ERROR is None, "protocol": 5138, "alliance": details}
    if path == "/alliance-details":
        alliance_id = query.get("id", [""])[0]
        if not alliance_id.isdigit():
            return 400, {"error": "id must contain digits only"}
        result = mysql_call("latest", "alliance", None, None, int(alliance_id))
        return (200, {"stored": True, "alliance": result}) if result else (404, {"error": "alliance details are not stored; click Live fetch"})
    if path == "/live-roster":
        alliance_id = query.get("id", [""])[0]
        refresh = query.get("refresh", ["0"])[0] == "1"
        if not alliance_id.isdigit():
            return 400, {"error": "id must contain digits only"}
        known = (
            ALLIANCES
            + [a for rows in LIVE_STATES.values() for a in rows]
            + [a for entry in STATE_CACHE.values() if isinstance(entry, dict) for a in entry.get("results", [])]
        )
        alliance = next((a for a in known if a["id"] == int(alliance_id)), None)
        if not alliance:
            alliance = mysql_call("latest", "alliance", None, None, int(alliance_id))
        if not alliance:
            return 404, {"error": "alliance not in captured directory"}
        with LIVE_LOCK:
            metadata_error = None
            try:
                if refresh:
                    LIVE_ROSTERS.pop(alliance["id"], None)
                    LIVE_METADATA.pop(alliance["id"], None)
                if alliance["id"] not in LIVE_ROSTERS:
                    LIVE_ROSTERS[alliance["id"]] = fetch_roster(alliance["id"], alliance["state"])
                members = LIVE_ROSTERS[alliance["id"]]
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                return 502, {"error": str(error)}
            try:
                if alliance["id"] not in LIVE_METADATA:
                    LIVE_METADATA[alliance["id"]] = fetch_chat_metadata(alliance["id"], alliance["tag"])
                metadata = LIVE_METADATA[alliance["id"]]
                for member in members:
                    member.update(metadata.get(clean(member["name"]).casefold(), {}))
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                metadata_error = str(error)
        stored_members = mysql_call("save_roster", alliance["id"], alliance["state"], members, metadata_error)
        saved_members = stored_members or members
        coordinates_available = any(member.get("x") is not None and member.get("y") is not None for member in saved_members)
        if MYSQL_STORE is None:
            state_cache = STATE_CACHE.setdefault(str(alliance["state"]), {})
            state_cache.setdefault("rosters", {})[str(alliance["id"])] = {
                "alliance_id": alliance["id"],
                "members": saved_members,
                "metadata_error": metadata_error,
                "coordinates_available": coordinates_available,
                "stored_at": int(time.time()),
            }
            save_state_cache()
        return 200, {
            "live": True,
            "stored": True,
            "storage": "mysql" if MYSQL_STORE is not None and MYSQL_ERROR is None else "json",
            "alliance_id": alliance["id"],
            "members": saved_members,
            "metadata_matches": len(LIVE_METADATA.get(alliance["id"], {})),
            "metadata_error": metadata_error,
            "coordinates_available": coordinates_available,
        }
    if path == "/roster":
        alliance_id = query.get("id", [""])[0]
        if not alliance_id.isdigit():
            return 400, {"error": "id must contain digits only"}
        alliance_id = int(alliance_id)
        result = mysql_call("latest", "roster", None, alliance_id, alliance_id)
        if not result and MYSQL_STORE is None:
            result = STATE_CACHE.get(str(alliance_id // 1_000_000), {}).get("rosters", {}).get(str(alliance_id))
        if result:
            result = dict(result)
            result["members"] = add_map_data([dict(member) for member in result.get("members", [])], alliance_id // 1_000_000)
            result["coordinates_available"] = any(member.get("x") is not None and member.get("y") is not None for member in result["members"])
        return (200, {"stored": True, **result}) if result else (404, {"error": "alliance roster is not stored; click Live fetch"})
    if path == "/live-details-2":
        rid = query.get("rid", [""])[0]
        alliance_id = query.get("alliance_id", [""])[0]
        if not rid.isdigit() or not alliance_id.isdigit():
            return 400, {"error": "rid and alliance_id must contain digits only"}
        rid, alliance_id = int(rid), int(alliance_id)
        members = LIVE_ROSTERS.get(alliance_id)
        if members is None:
            return 409, {"error": "load this alliance roster before opening Details 2"}
        power = roster_power_rank(members, rid)
        if power is None:
            return 404, {"error": "player is not in this alliance roster"}
        with LIVE_LOCK:
            try:
                result = fetch_details2(rid) if alliance_id == current_alliance_id() else {
                    "rid": rid,
                    "power": power,
                    "ko": None,
                    "daily_contribution": None,
                    "restricted_reason": "Current-alliance-only protocol; unavailable for external alliances.",
                    "protocols": {"power": "5123 + 1029", "ko": None, "daily_contribution": None},
                }
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                return 502, {"error": str(error)}
        mysql_call("save_details2", alliance_id, result)
        return 200, {"live": True, "stored": MYSQL_STORE is not None and MYSQL_ERROR is None, **result}
    if path == "/details-2":
        rid = query.get("rid", [""])[0]
        alliance_id = query.get("alliance_id", [""])[0]
        if not rid.isdigit() or not alliance_id.isdigit():
            return 400, {"error": "rid and alliance_id must contain digits only"}
        result = mysql_call("latest", "details2", None, int(alliance_id), int(rid))
        return (200, {"stored": True, **result}) if result else (404, {"error": "these player details are not stored; use Live fetch"})
    if path == "/live-reinforcements":
        rid = query.get("rid", [""])[0]
        alliance_id = query.get("alliance_id", [""])[0]
        if not rid.isdigit() or not alliance_id.isdigit():
            return 400, {"error": "rid and alliance_id must contain digits only"}
        rid, alliance_id = int(rid), int(alliance_id)
        members = LIVE_ROSTERS.get(alliance_id)
        player = next((member for member in members or [] if member["rid"] == rid), None)
        if members is None:
            return 409, {"error": "Live fetch this alliance before checking reinforcements"}
        if player is None:
            return 404, {"error": "player is not in this alliance roster"}
        with LIVE_LOCK:
            try:
                result = fetch_reinforcements(rid, alliance_id // 1_000_000)
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                return 502, {"error": str(error)}
        player.update({key: result[key] for key in ("reinforced", "reinforcement_count", "reinforcement_troops")})
        return 200, {"live": True, **result}
    if path == "/state-cache":
        state = query.get("state", [""])[0]
        if not valid_transfer_state(state):
            return 400, {"error": f"state must be inside this scanner's transfer range: {TRANSFER_STATE_MIN}-{TRANSFER_STATE_MAX}"}
        stored = mysql_call("latest", "state", int(state))
        if stored:
            return 200, {"cached": True, "storage": "mysql", **stored}
        entry = STATE_CACHE.get(state, {}) if MYSQL_STORE is None else {}
        return 200, {
            "cached": bool(entry.get("results")), "storage": "json" if entry.get("results") else "mysql",
            "state": int(state), "updated": entry.get("updated"), "complete": entry.get("complete", False),
            "results": entry.get("results", []),
        }
    if path == "/live-state":
        state = query.get("state", [""])[0]
        if not valid_transfer_state(state):
            return 400, {"error": f"state must be inside this scanner's transfer range: {TRANSFER_STATE_MIN}-{TRANSFER_STATE_MAX}"}
        start = query.get("start", ["0"])[0]
        if not start.isdigit() or not 0 <= int(start) <= 1600:
            return 400, {"error": "start must be a number from 0 to 1600"}
        count = query.get("count", ["40"])[0]
        if not count.isdigit() or not 1 <= int(count) <= 100:
            return 400, {"error": "count must be a number from 1 to 100"}
        state = int(state)
        start = int(start)
        count = int(count)
        with LIVE_LOCK:
            try:
                batch = fetch_state_alliances(state, start, count)
                LIVE_STATES[state] = batch["results"]
                key = str(state)
                cached = STATE_CACHE.get(key)
                if batch["done"] or not cached or not cached.get("complete"):
                    STATE_CACHE[key] = {
                        "updated": int(time.time()),
                        "complete": batch["done"],
                        "results": batch["results"],
                        "map_players": cached_map_players(state),
                        "rosters": (cached or {}).get("rosters", {}),
                    }
                    save_state_cache()
                if batch["done"]:
                    mysql_call("save_state", state, batch["results"], True)
            except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                return 502, {"error": str(error)}
        return 200, {"live": True, "stored": MYSQL_STORE is not None and MYSQL_ERROR is None, "storage_error": MYSQL_ERROR, "state": state, **batch}
    if path in {"/players", "/profiles"}:
        q = query.get("q", [""])[0]
        rows = [p for p in PROFILES if match(p["name"], q) or match(p["player_id"], q) or match(p["alliance_tag"], q)]
        return 200, {"capture": CAPTURE, "results": rows}
    if path == "/player":
        player_id = query.get("id", [""])[0]
        if not player_id.isdigit():
            return 400, {"error": "id must contain digits only"}
        player = PLAYERS.get(player_id)
        return (200, {"capture": CAPTURE, "player": player}) if player else (404, {"error": "player not in capture"})
    if path == "/alliance":
        abbr = query.get("abbr", [""])[0]
        if not abbr or len(abbr) > 8 or not abbr.isalnum():
            return 400, {"error": "abbr must be 1-8 letters or digits"}
        result = alliance_result(abbr, query.get("q", [""])[0])
        return (200, {"capture": CAPTURE, "alliance": result}) if result else (404, {"error": "alliance not in capture"})
    return 404, {"error": "not found"}


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def session_token(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        return cookie["wos_session"].value if "wos_session" in cookie else None

    def current_user(self):
        user = SAAS.session_user(self.session_token())
        if user and user["role"] == "admin" and DEFAULT_BOT.get("owner_id") is None:
            DEFAULT_BOT["owner_id"] = user["id"]
        return user

    def same_origin(self):
        origin = self.headers.get("Origin", "")
        host = self.headers.get("Host", "")
        return origin in {f"http://{host}", f"https://{host}"}

    def read_json(self, maximum=8192):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("invalid request length") from error
        if self.headers.get_content_type() != "application/json" or not 0 < length <= maximum:
            raise ValueError("invalid JSON request")
        return json.loads(self.rfile.read(length))

    def session_cookie(self, token, maximum_age=SESSION_SECONDS):
        secure = os.getenv("WOS_SECURE_COOKIES") == "1" or self.headers.get("X-Forwarded-Proto") == "https"
        return f"wos_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={maximum_age}{'; Secure' if secure else ''}"

    def require_user(self, path):
        user = self.current_user()
        if not user:
            self.send_json(401, {"error": "sign in required"})
            return None
        feature = FEATURES.get(path)
        if feature and feature not in user["features"]:
            self.send_json(403, {"error": "your package does not include this feature", "feature": feature})
            return None
        return user

    def do_POST(self):
        path = urlparse(self.path).path
        if not self.same_origin():
            self.send_json(403, {"error": "request must come from this dashboard"})
            return
        if path in {"/api/auth/register", "/api/auth/login"}:
            try:
                payload = self.read_json()
                user = SAAS.register(payload.get("email"), payload.get("password"), payload.get("display_name")) if path.endswith("register") else SAAS.authenticate(payload.get("email"), payload.get("password"))
                token = SAAS.create_session(user["id"])
                self.send_json(200, {"user": user}, {"Set-Cookie": self.session_cookie(token)})
            except (json.JSONDecodeError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        user = self.require_user(path)
        if not user:
            return
        if path == "/api/auth/logout":
            SAAS.logout(self.session_token())
            self.send_json(200, {"signed_out": True}, {"Set-Cookie": self.session_cookie("", 0)})
            return
        if path == "/api/billing/test-checkout":
            if not ipaddress.ip_address(self.client_address[0]).is_loopback:
                self.send_json(403, {"error": "test checkout is local-only"})
                return
            try:
                payload = self.read_json()
                self.send_json(200, {"test_mode": True, "user": SAAS.activate(user["id"], payload.get("plan"), "test_checkout")})
            except (json.JSONDecodeError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        if path == "/api/admin/activate":
            if user["role"] != "admin":
                self.send_json(403, {"error": "administrator access required"})
                return
            try:
                payload = self.read_json()
                activated = SAAS.activate(int(payload.get("user_id")), payload.get("plan"), "admin", int(payload.get("days", 30)))
                self.send_json(200, {"user": activated})
            except (json.JSONDecodeError, TypeError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        if path not in {"/add-bot", "/start-gather", "/recall-gather", "/auto-shield", "/gather-automation"}:
            self.send_json(404, {"error": "not found"})
            return
        if not ipaddress.ip_address(self.client_address[0]).is_loopback:
            self.send_json(403, {"error": "bot controls are local-only"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if path in {"/start-gather", "/recall-gather", "/auto-shield", "/gather-automation"}:
            if not 0 < length <= 2048:
                self.send_json(400, {"error": "invalid gather request"})
                return
            try:
                payload = json.loads(self.rfile.read(length))
                bot = payload.get("bot")
                if bot not in BOTS or not owned_bot(BOTS[bot], user):
                    raise ValueError("select a valid game bot")
                if not BOTS[bot].get("gather_ready"):
                    raise ValueError("this bot is chat-only; add a PCAP containing its TCP 30101 game login")
                if path == "/gather-automation":
                    action = payload.get("action")
                    if action == "pause":
                        schedule = SAAS.pause_gather_schedule(user["id"], bot)
                    elif action == "start":
                        existing = SAAS.gather_schedule(user["id"], bot)
                        if existing and existing["status"] == "active":
                            raise ValueError("pause the active gather schedule before starting a new one")
                        schedule = SAAS.save_gather_schedule(
                            user["id"], bot, payload.get("resources"), payload.get("march_limit"),
                            payload.get("total_cycles"), payload.get("connection_mode"), payload.get("infinite", False),
                        )
                        Thread(target=GATHER_SCHEDULER.tick, name="gather-start", daemon=True).start()
                    else:
                        raise ValueError("action must be start or pause")
                    runs = [run for run in SAAS.gather_runs(schedule["id"]) if run["status"] != "returned"]
                    self.send_json(200, {"schedule": schedule, "runs": runs, "cooldown_seconds": 300})
                elif path == "/auto-shield":
                    enabled = payload.get("enabled")
                    if type(enabled) is not bool:
                        raise ValueError("enabled must be true or false")
                    self.send_json(200, {"bot": public_bot(BOTS[bot]), **set_auto_shield(bot, BOTS[bot]["uid"], enabled)})
                elif path == "/start-gather":
                    self.send_json(200, {"started": True, "gather": start_gather(bot, payload.get("resource"))})
                else:
                    march_id = payload.get("march_id")
                    if type(march_id) is not int or march_id <= 0:
                        raise ValueError("march_id must be a positive integer")
                    gather = recall_gather(bot, march_id)
                    if not gather:
                        raise ValueError("gather march was not found")
                    schedule = SAAS.gather_schedule(user["id"], bot)
                    if schedule and schedule["status"] == "active" and schedule["connection_mode"] == "disconnect":
                        disconnect_gather_session(bot)
                    self.send_json(200, {"recalled": True, "gather": gather})
            except (ConnectionError, json.JSONDecodeError, OSError, RuntimeError, TypeError, ValueError) as error:
                self.send_json(409, {"error": str(error)})
            return
        if not 0 < length <= 128 * 1024 * 1024:
            self.send_json(400, {"error": "select a classic PCAP file up to 128 MB"})
            return
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as output:
                temporary = Path(output.name)
                output.write(self.rfile.read(length))
            bot = bot_from_capture(temporary)
            existing = next((key for key, item in BOTS.items() if item.get("owner_id") == user["id"] and item["uid"] == bot["uid"]), None)
            bot["id"] = existing or f"{user['id']}:{bot['id']}"
            bot["owner_id"] = user["id"]
            if existing:
                bot["name"] = bot["name"] or BOTS[existing].get("name")
            register_chat_bot(bot["id"], bot["auth"], bot["remote"], bot["alliance_id"])
            try:
                register_gather_session(bot["id"], temporary, bot["state"], bot["uid"])
                bot["gather_ready"] = True
            except (OSError, ValueError):
                bot["gather_ready"] = False
            BOTS[bot["id"]] = bot
            SAAS.save_bot_capture(user["id"], bot["uid"], temporary.read_bytes())
            self.send_json(200, {"added": True, "bot": public_bot(bot), "count": len(user_bots(user))})
        except Exception as error:
            self.send_json(400, {"error": str(error)})
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)

    def do_GET(self):
        request = urlparse(self.path)
        if request.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if request.path in {"/dashboard", "/wos_search_dashboard.html"}:
            body = Path(__file__).with_name("wos_search_dashboard.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if request.path == "/api/plans":
            self.send_json(200, {"test_mode": True, "currency": "USD", "results": SAAS.plans()})
            return
        user = self.require_user(request.path)
        if not user:
            return
        if request.path == "/api/session":
            self.send_json(200, {"user": user})
            return
        if request.path == "/api/admin/users":
            try:
                self.send_json(200, {"results": SAAS.admin_users(user["id"])})
            except PermissionError as error:
                self.send_json(403, {"error": str(error)})
            return
        status, payload = response(request.path, parse_qs(request.query), user)
        self.send_json(status, payload)


def self_test():
    token = bot_token_from_capture(Path(__file__).resolve().parents[1] / "work" / "wos_handshake_20260715.pcap")
    assert len(token) >= 20
    assert DEFAULT_BOT["uid"] == 60116543 and DEFAULT_BOT["alliance_id"] == 1642000531
    assert response("/bots", {})[1]["results"][0]["id"] == "default"
    assert response("/bots", {})[1]["results"][0]["gather_ready"] is True
    assert response("/scout-reports", {})[1]["results"][0]["troop_total"] == 53870
    assert response("/gather-bots", {})[1]["results"][0]["id"] == "default"
    assert response("/gathers", {})[1]["bot"] is None
    assert response("/gathers", {"bot": ["bad"]})[0] == 400
    assert response("/auto-shield", {"bot": ["default"]})[1]["enabled"] is False
    assert response("/auto-shield", {"bot": ["bad"]})[0] == 400
    assert response("/health", {})[1]["profiles"] == 144
    assert response("/health", {})[1]["alliances"] == 96
    assert len(response("/alliances", {})[1]["results"]) == len(ALLIANCES)
    assert len({a["id"] for a in ALLIANCES}) == len(ALLIANCES)
    assert sum(bool(a.get("directory_listed")) for a in ALLIANCES) == 93
    assert response("/alliances", {"q": ["bdl"]})[1]["results"][0]["tag"] == "BDL"
    assert response("/alliance", {"abbr": ["BDL"], "q": ["Lady"]})[1]["alliance"]["members_returned"] == 1
    assert response("/players", {"q": ["katak"]})[1]["results"][0]["power"] == 288_956_327
    assert response("/player", {"id": ["bad"]})[0] == 400
    assert response("/live-alliance-details", {"id": ["bad"]})[0] == 400
    assert response("/alliance-details", {"id": ["bad"]})[0] == 400
    assert response("/roster", {"id": ["bad"]})[0] == 400
    assert response("/live-details-2", {"rid": ["bad"], "alliance_id": ["1"]})[0] == 400
    assert response("/live-reinforcements", {"rid": ["bad"], "alliance_id": ["1"]})[0] == 400
    assert roster_power_rank([{"rid": 2, "power": 10, "rank": 1}, {"rid": 1, "power": 20, "rank": 3}], 2) == {"position": 2, "value": 10, "alliance_rank": 1}
    assert response("/live-state", {"state": ["bad"]})[0] == 400
    assert response("/live-state", {"state": ["1755"], "start": ["bad"]})[0] == 400
    assert response("/live-state", {"state": ["1755"], "count": ["101"]})[0] == 400
    assert response("/state-cache", {"state": ["bad"]})[0] == 400
    assert valid_transfer_state("1492") and valid_transfer_state("1894")
    assert not valid_transfer_state("1491") and not valid_transfer_state("4022")
    attacks = response("/live-attacks", {})[1]["results"]
    assert any(item["march_id"] == 12667 and item["status"] == "returning" for item in attacks)
    assert any(item.get("report_id") == "1929844729679185" and item["status"] == "completed" for item in attacks)
    assert len(response("/live-attacks", {"alliance_id": ["1755000001"]})[1]["results"]) == 2
    assert response("/live-attacks", {"alliance_id": ["1"]})[1]["results"] == []
    assert response("/live-attacks", {"alliance_id": ["bad"]})[0] == 400
    assert response("/live-dms", {"bot": ["bad"]})[0] == 400
    assert response("/live-dm", {"bot": ["bad"], "rid": ["1"]})[0] == 400
    assert response("/live-dm", {"rid": ["bad"]})[0] == 400
    assert response("/live-dm", {"rid": ["4294967296"]})[0] == 400
    print("self-test passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        initialize_mysql()
        if MYSQL_STORE:
            print(f"MySQL storage: {MYSQL_STORE.database}")
        elif MYSQL_ERROR:
            print(f"MySQL storage unavailable: {MYSQL_ERROR}")
        else:
            print("MySQL storage disabled: set WOS_MYSQL_DATABASE")
        print(f"WOS API: http://{args.host}:{args.port}")
        GATHER_SCHEDULER.start()
        ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
