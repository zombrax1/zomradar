#!/usr/bin/env python3
"""Minimal append-only MySQL storage for WOS snapshots and observed events."""

import json
import os
import re

import mysql.connector


def configured_store():
    database = os.getenv("WOS_MYSQL_DATABASE", "").strip()
    if not database:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_]+", database):
        raise ValueError("WOS_MYSQL_DATABASE may contain only letters, digits, and underscores")
    return Store(
        host=os.getenv("WOS_MYSQL_HOST", "127.0.0.1"),
        port=int(os.getenv("WOS_MYSQL_PORT", "3306")),
        user=os.getenv("WOS_MYSQL_USER", "root"),
        password=os.getenv("WOS_MYSQL_PASSWORD", ""),
        database=database,
    )


class Store:
    def __init__(self, host, port, user, password, database):
        self.config = {"host": host, "port": port, "user": user, "password": password}
        self.database = database

    def connect(self, database=True):
        options = dict(self.config)
        if database:
            options["database"] = self.database
        return mysql.connector.connect(**options)

    def initialize(self):
        connection = self.connect(False)
        cursor = connection.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{self.database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        cursor.close()
        connection.close()
        connection = self.connect()
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wos_snapshots (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                kind VARCHAR(24) NOT NULL,
                state INT NULL,
                alliance_id BIGINT UNSIGNED NULL,
                entity_id BIGINT UNSIGNED NULL,
                captured_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
                power BIGINT NULL,
                online TINYINT(1) NULL,
                payload JSON NOT NULL,
                INDEX latest_snapshot (kind, state, alliance_id, entity_id, id)
            ) ENGINE=InnoDB
        """)
        connection.commit()
        cursor.close()
        connection.close()

    @staticmethod
    def encoded(value):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def decoded(value):
        return json.loads(value) if isinstance(value, (str, bytes, bytearray)) else value

    def snapshot(self, kind, payload, state=None, alliance_id=None, entity_id=None, power=None, online=None, cursor=None):
        own_connection = cursor is None
        connection = self.connect() if own_connection else None
        cursor = connection.cursor() if own_connection else cursor
        cursor.execute(
            "INSERT INTO wos_snapshots(kind,state,alliance_id,entity_id,power,online,payload) VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (kind, state, alliance_id, entity_id, power, online, self.encoded(payload)),
        )
        if own_connection:
            connection.commit()
            cursor.close()
            connection.close()

    def latest(self, kind, state=None, alliance_id=None, entity_id=None):
        clauses = ["kind=%s"]
        values = [kind]
        for column, value in (("state", state), ("alliance_id", alliance_id), ("entity_id", entity_id)):
            if value is not None:
                clauses.append(f"{column}=%s")
                values.append(value)
        connection = self.connect()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            f"SELECT captured_at,payload FROM wos_snapshots WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT 1",
            values,
        )
        row = cursor.fetchone()
        cursor.close()
        connection.close()
        if not row:
            return None
        payload = self.decoded(row["payload"])
        payload["stored_at"] = row["captured_at"].isoformat()
        return payload

    def save_state(self, state, results, complete=True):
        connection = self.connect()
        cursor = connection.cursor()
        payload = {"state": state, "complete": complete, "results": results}
        self.snapshot("state", payload, state=state, cursor=cursor)
        for alliance in results:
            self.snapshot(
                "alliance", alliance, state=state, alliance_id=alliance["id"],
                entity_id=alliance["id"], power=alliance.get("exact_power"), cursor=cursor,
            )
        connection.commit()
        cursor.close()
        connection.close()

    def save_alliance(self, alliance):
        self.snapshot(
            "alliance", alliance, state=alliance.get("state"), alliance_id=alliance["id"],
            entity_id=alliance["id"], power=alliance.get("exact_power"),
        )

    def save_roster(self, alliance_id, state, members, metadata_error=None):
        connection = self.connect()
        cursor = connection.cursor(dictionary=True)
        previous = {}
        ids = [member["rid"] for member in members]
        if ids:
            placeholders = ",".join(["%s"] * len(ids))
            cursor.execute(
                f"""SELECT snapshot.entity_id,snapshot.power FROM wos_snapshots snapshot
                    JOIN (SELECT entity_id,MAX(id) id FROM wos_snapshots
                          WHERE kind='player' AND entity_id IN ({placeholders}) GROUP BY entity_id) latest
                    ON latest.id=snapshot.id""",
                ids,
            )
            previous = {row["entity_id"]: row["power"] for row in cursor.fetchall()}
        enriched = []
        for member in members:
            player = dict(member)
            old_power = previous.get(player["rid"])
            player["power_change"] = None if old_power is None else player.get("power", 0) - old_power
            enriched.append(player)
        payload = {"alliance_id": alliance_id, "members": enriched, "metadata_error": metadata_error}
        self.snapshot("roster", payload, state=state, alliance_id=alliance_id, entity_id=alliance_id, cursor=cursor)
        for player in enriched:
            self.snapshot(
                "player", player, state=state, alliance_id=alliance_id, entity_id=player["rid"],
                power=player.get("power"), online=player.get("online"), cursor=cursor,
            )
        connection.commit()
        cursor.close()
        connection.close()
        return enriched

    def save_details2(self, alliance_id, result):
        self.snapshot("details2", result, alliance_id=alliance_id, entity_id=result["rid"], power=(result.get("power") or {}).get("value"))

    def save_gather(self, gather):
        self.snapshot("gather", gather, state=gather.get("state"), entity_id=gather.get("march_id"))

def self_test():
    assert Store.decoded(Store.encoded({"name": "DÉD"})) == {"name": "DÉD"}
    print("mysql storage self-test passed")


if __name__ == "__main__":
    self_test()
