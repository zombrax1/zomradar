#!/usr/bin/env python3
"""Small local SaaS account, session, plan, and entitlement store."""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path


PLANS = (
    ("explorer", "Explorer", 900, ("alliance_search", "state_search")),
    ("gatherer", "Gatherer", 1900, ("alliance_search", "state_search", "gather")),
    ("guardian", "Guardian", 2900, ("alliance_search", "state_search", "gather", "auto_shield")),
)
SESSION_SECONDS = 7 * 24 * 60 * 60


class SaaSStore:
    def __init__(self, path):
        self.path = str(path)

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def initialize(self):
        with self.connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    password_hash BLOB NOT NULL,
                    password_salt BLOB NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash BLOB PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS plans (
                    slug TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    price_cents INTEGER NOT NULL,
                    features TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS subscriptions (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    plan_slug TEXT NOT NULL REFERENCES plans(slug),
                    status TEXT NOT NULL CHECK(status IN ('active','expired','cancelled')),
                    source TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gather_schedules (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    bot_id TEXT NOT NULL,
                    resources TEXT NOT NULL,
                    march_limit INTEGER NOT NULL CHECK(march_limit BETWEEN 1 AND 5),
                    detected_limit INTEGER,
                    total_cycles INTEGER NOT NULL CHECK(total_cycles BETWEEN 1 AND 100),
                    infinite INTEGER NOT NULL DEFAULT 0 CHECK(infinite IN (0,1)),
                    cycles_started INTEGER NOT NULL DEFAULT 0,
                    connection_mode TEXT NOT NULL CHECK(connection_mode IN ('keep_alive','disconnect')),
                    status TEXT NOT NULL CHECK(status IN ('active','paused','completed','error')),
                    phase TEXT NOT NULL CHECK(phase IN ('ready','waiting','cooldown')),
                    next_run_at INTEGER NOT NULL,
                    last_run_at INTEGER,
                    last_error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(user_id, bot_id)
                );
                CREATE TABLE IF NOT EXISTS gather_runs (
                    id INTEGER PRIMARY KEY,
                    schedule_id INTEGER NOT NULL REFERENCES gather_schedules(id) ON DELETE CASCADE,
                    cycle_no INTEGER NOT NULL,
                    resource TEXT NOT NULL,
                    march_id INTEGER NOT NULL,
                    formation_id INTEGER,
                    state INTEGER,
                    x INTEGER,
                    y INTEGER,
                    started_at INTEGER NOT NULL,
                    arrives_at INTEGER,
                    finish_at INTEGER,
                    return_at INTEGER,
                    status TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(schedule_id, march_id)
                );
                CREATE TABLE IF NOT EXISTS bot_captures (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    uid INTEGER NOT NULL,
                    capture BLOB NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(user_id, uid)
                );
            """)
            connection.executemany(
                "INSERT OR IGNORE INTO plans(slug,name,price_cents,features) VALUES(?,?,?,?)",
                ((slug, name, price, json.dumps(features)) for slug, name, price, features in PLANS),
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(gather_schedules)")}
            if "infinite" not in columns:
                connection.execute("ALTER TABLE gather_schedules ADD COLUMN infinite INTEGER NOT NULL DEFAULT 0 CHECK(infinite IN (0,1))")
            run_columns = {row[1] for row in connection.execute("PRAGMA table_info(gather_runs)")}
            if "formation_id" not in run_columns:
                connection.execute("ALTER TABLE gather_runs ADD COLUMN formation_id INTEGER")

    @staticmethod
    def normalize_email(value):
        email = str(value or "").strip().casefold()
        if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("enter a valid email address")
        return email

    @staticmethod
    def password_digest(password, salt):
        return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    def register(self, email, password, display_name):
        email = self.normalize_email(email)
        password = str(password or "")
        display_name = str(display_name or "").strip()
        if not 2 <= len(display_name) <= 50:
            raise ValueError("display name must be 2-50 characters")
        if not 10 <= len(password) <= 128:
            raise ValueError("password must be 10-128 characters")
        salt = secrets.token_bytes(16)
        with self.connect() as connection:
            role = "admin" if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 else "user"
            try:
                cursor = connection.execute(
                    "INSERT INTO users(email,display_name,password_hash,password_salt,role,created_at) VALUES(?,?,?,?,?,?)",
                    (email, display_name, self.password_digest(password, salt), salt, role, int(time.time())),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("an account with this email already exists") from error
        return self.user(cursor.lastrowid)

    def authenticate(self, email, password):
        email = self.normalize_email(email)
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row or not hmac.compare_digest(row["password_hash"], self.password_digest(str(password or ""), row["password_salt"])):
            raise ValueError("incorrect email or password")
        return self.user(row["id"])

    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
            connection.execute(
                "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                (hashlib.sha256(token.encode()).digest(), user_id, now + SESSION_SECONDS),
            )
        return token

    def session_user(self, token):
        if not token:
            return None
        now = int(time.time())
        with self.connect() as connection:
            row = connection.execute(
                "SELECT user_id FROM sessions WHERE token_hash=? AND expires_at>?",
                (hashlib.sha256(token.encode()).digest(), now),
            ).fetchone()
        return self.user(row["user_id"]) if row else None

    def logout(self, token):
        if token:
            with self.connect() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).digest(),))

    def plans(self):
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM plans ORDER BY price_cents").fetchall()
        return [{**dict(row), "features": json.loads(row["features"])} for row in rows]

    def user(self, user_id):
        now = int(time.time())
        with self.connect() as connection:
            row = connection.execute("SELECT id,email,display_name,role,created_at FROM users WHERE id=?", (user_id,)).fetchone()
            subscription = connection.execute(
                """SELECT s.plan_slug,p.name plan_name,s.status,s.source,s.expires_at,p.features
                   FROM subscriptions s JOIN plans p ON p.slug=s.plan_slug WHERE s.user_id=?""",
                (user_id,),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        if subscription:
            current = dict(subscription)
            if current["expires_at"] <= now and current["status"] == "active":
                current["status"] = "expired"
            current["features"] = json.loads(current["features"]) if current["status"] == "active" else []
            result["subscription"] = current
            result["features"] = current["features"]
        else:
            result["subscription"] = None
            result["features"] = []
        return result

    def activate(self, user_id, plan_slug, source, days=30):
        if not 1 <= int(days) <= 366:
            raise ValueError("activation days must be between 1 and 366")
        if plan_slug not in {plan[0] for plan in PLANS}:
            raise ValueError("unknown package")
        now = int(time.time())
        expires_at = now + int(days) * 86400
        with self.connect() as connection:
            if not connection.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
                raise ValueError("unknown user")
            connection.execute(
                """INSERT INTO subscriptions(user_id,plan_slug,status,source,expires_at,updated_at)
                   VALUES(?,?,'active',?,?,?)
                   ON CONFLICT(user_id) DO UPDATE SET plan_slug=excluded.plan_slug,status='active',
                   source=excluded.source,expires_at=excluded.expires_at,updated_at=excluded.updated_at""",
                (user_id, plan_slug, source, expires_at, now),
            )
        return self.user(user_id)

    def admin_users(self, actor_id):
        actor = self.user(actor_id)
        if not actor or actor["role"] != "admin":
            raise PermissionError("administrator access required")
        with self.connect() as connection:
            ids = [row[0] for row in connection.execute("SELECT id FROM users ORDER BY id")]
        return [self.user(user_id) for user_id in ids]

    @staticmethod
    def decoded_schedule(row):
        if not row:
            return None
        result = dict(row)
        result["resources"] = json.loads(result["resources"])
        return result

    def save_gather_schedule(self, user_id, bot_id, resources, march_limit, total_cycles, connection_mode, infinite=False):
        resources = list(dict.fromkeys(resources or []))
        if type(infinite) is not bool:
            raise ValueError("infinite must be true or false")
        total_cycles = 1 if infinite else int(total_cycles)
        if not resources or any(resource not in {"meat", "wood", "iron", "coal"} for resource in resources):
            raise ValueError("select at least one valid resource")
        if not 1 <= int(march_limit) <= 5:
            raise ValueError("march limit must be between 1 and 5")
        if not 1 <= total_cycles <= 100:
            raise ValueError("loop count must be between 1 and 100")
        if connection_mode not in {"keep_alive", "disconnect"}:
            raise ValueError("select keep connected or disconnect after sending")
        now = int(time.time())
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO gather_schedules(user_id,bot_id,resources,march_limit,detected_limit,total_cycles,infinite,
                   cycles_started,connection_mode,status,phase,next_run_at,last_run_at,last_error,created_at,updated_at)
                   VALUES(?,?,?,?,NULL,?,?,0,?,'active','ready',?,NULL,NULL,?,?)
                   ON CONFLICT(user_id,bot_id) DO UPDATE SET resources=excluded.resources,
                   march_limit=excluded.march_limit,detected_limit=NULL,total_cycles=excluded.total_cycles,
                   infinite=excluded.infinite,cycles_started=0,connection_mode=excluded.connection_mode,status='active',phase='ready',
                   next_run_at=excluded.next_run_at,last_run_at=NULL,last_error=NULL,updated_at=excluded.updated_at""",
                (user_id, str(bot_id), json.dumps(resources), int(march_limit), total_cycles, int(infinite), connection_mode, now, now, now),
            )
            row = connection.execute("SELECT * FROM gather_schedules WHERE user_id=? AND bot_id=?", (user_id, str(bot_id))).fetchone()
        return self.decoded_schedule(row)

    def gather_schedule(self, user_id, bot_id):
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM gather_schedules WHERE user_id=? AND bot_id=?", (user_id, str(bot_id))).fetchone()
        return self.decoded_schedule(row)

    def active_gather_schedules(self):
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM gather_schedules WHERE status='active' ORDER BY id").fetchall()
        return [self.decoded_schedule(row) for row in rows]

    def update_gather_schedule(self, schedule_id, **changes):
        allowed = {"detected_limit", "cycles_started", "status", "phase", "next_run_at", "last_run_at", "last_error"}
        changes = {key: value for key, value in changes.items() if key in allowed}
        if not changes:
            return
        changes["updated_at"] = int(time.time())
        with self.connect() as connection:
            connection.execute(
                f"UPDATE gather_schedules SET {','.join(f'{key}=?' for key in changes)} WHERE id=?",
                (*changes.values(), schedule_id),
            )

    def pause_gather_schedule(self, user_id, bot_id):
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE gather_schedules SET status='paused',updated_at=? WHERE user_id=? AND bot_id=?",
                (int(time.time()), user_id, str(bot_id)),
            )
        if not cursor.rowcount:
            raise ValueError("automatic gather schedule was not found")
        return self.gather_schedule(user_id, bot_id)

    def log_gather_run(self, schedule_id, cycle_no, item):
        now = int(time.time())
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO gather_runs(schedule_id,cycle_no,resource,march_id,formation_id,state,x,y,started_at,arrives_at,
                   finish_at,return_at,status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(schedule_id,march_id) DO UPDATE SET
                   formation_id=COALESCE(excluded.formation_id,gather_runs.formation_id),
                   arrives_at=COALESCE(excluded.arrives_at,gather_runs.arrives_at),
                   finish_at=COALESCE(excluded.finish_at,gather_runs.finish_at),
                   return_at=COALESCE(excluded.return_at,gather_runs.return_at),
                   status=excluded.status,updated_at=excluded.updated_at""",
                (schedule_id, cycle_no, item["resource"], item["march_id"], item.get("formation_id"), item.get("state"), item.get("x"), item.get("y"),
                 item.get("started_at", now), item.get("arrives_at"), item.get("finish_at"), item.get("return_at"), item.get("status", "marching"), now),
            )

    def gather_runs(self, schedule_id, limit=50):
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM gather_runs WHERE schedule_id=? ORDER BY id DESC LIMIT ?", (schedule_id, int(limit))
            ).fetchall()
        return [dict(row) for row in rows]

    def save_bot_capture(self, user_id, uid, capture):
        if not isinstance(capture, bytes) or not 0 < len(capture) <= 128 * 1024 * 1024:
            raise ValueError("bot capture must be a PCAP up to 128 MB")
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO bot_captures(user_id,uid,capture,updated_at) VALUES(?,?,?,?)
                   ON CONFLICT(user_id,uid) DO UPDATE SET capture=excluded.capture,updated_at=excluded.updated_at""",
                (user_id, int(uid), capture, int(time.time())),
            )

    def bot_captures(self):
        with self.connect() as connection:
            return [dict(row) for row in connection.execute("SELECT user_id,uid,capture FROM bot_captures ORDER BY user_id,uid")]


def self_test():
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        store = SaaSStore(Path(directory) / "test.db")
        store.initialize()
        admin = store.register("admin@example.test", "correct horse battery", "Administrator")
        member = store.register("member@example.test", "correct horse staple", "Member")
        assert admin["role"] == "admin" and member["role"] == "user"
        assert store.authenticate("ADMIN@example.test", "correct horse battery")["id"] == admin["id"]
        token = store.create_session(member["id"])
        assert store.session_user(token)["id"] == member["id"]
        assert store.activate(member["id"], "gatherer", "test_checkout")["features"][-1] == "gather"
        assert len(store.admin_users(admin["id"])) == 2
        schedule = store.save_gather_schedule(member["id"], "bot-1", ["meat", "wood"], 3, 0, "disconnect", True)
        assert schedule["resources"] == ["meat", "wood"] and schedule["march_limit"] == 3 and schedule["infinite"] == 1 and schedule["total_cycles"] == 1
        store.log_gather_run(schedule["id"], 1, {"resource": "meat", "march_id": 7, "started_at": 10, "status": "marching"})
        assert store.gather_runs(schedule["id"])[0]["march_id"] == 7
        store.save_bot_capture(member["id"], 7, b"pcap")
        assert store.bot_captures()[0]["capture"] == b"pcap"
        assert store.pause_gather_schedule(member["id"], "bot-1")["status"] == "paused"
        store.logout(token)
        assert store.session_user(token) is None
    print("saas self-test passed")


if __name__ == "__main__":
    self_test()
