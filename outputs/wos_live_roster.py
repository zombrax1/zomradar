import json
import socket
import struct
import sys
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "work"))

import analyze_wos_pcap as wire
from extract_wos_observed import fields, int_array, number, profile, records, text


HANDSHAKE = ROOT / "work" / "wos_handshake_20260715.pcap"
GAME_HANDSHAKE = ROOT / "work" / "wos_handshake_location_20260715.pcap"
GAME_HANDSHAKE_1755 = ROOT / "work" / "wos_handshake_1755_20260715.pcap"
ATTACK_CAPTURE = ROOT / "work" / "wos_attack_20260715.pcap"
REPORT_CAPTURE = ROOT / "work" / "wos_report_20260715.pcap"
SCOUT_CAPTURE = ROOT / "work" / "wos_scout_20260717.pcap"
DM_CAPTURE = ROOT / "work" / "wos_dm_20260715.pcap"

GATHER_RESOURCES = {
    "meat": (102, 50003),
    "wood": (103, 50000),
    "coal": (104, 50002),
    "iron": (105, 50001),
}
# ponytail: the game account's four gather slots share the live troop pool.
GATHER_MARCH_SLOTS = 4
GEM_TWO_HOUR_SHIELD = tuple(
    bytes.fromhex(value)
    for value in (
        "05000800480000000100020004000000474e0f00000000000000",
        "05000400460000000100040004000000c3470f00000000000000",
        "05000400500000000100040004000000d7470f00000000000000",
    )
)


def valid_bot_state(state):
    return isinstance(state, int) and state > 0


def pack_sproto(raw):
    assert len(raw) % 8 == 0
    packed = bytearray()
    for offset in range(0, len(raw), 8):
        block = raw[offset : offset + 8]
        mask = sum(1 << index for index, value in enumerate(block) if value)
        if mask == 0xFF:
            packed.extend(b"\xff\x00" + block)
        else:
            packed.append(mask)
            packed.extend(value for value in block if value)
    return bytes(packed)


def request(protocol, session, body):
    raw = struct.pack("<HHH", 2, (protocol + 1) * 2, (session + 1) * 2) + body
    return pack_sproto(raw + b"\0" * (-len(raw) % 8))


def bytes_field(value):
    return struct.pack("<HHI", 1, 0, len(value)) + value


def direct_field(value):
    return struct.pack("<HH", 1, (value + 1) * 2)


def gather_search_body(resource, level=8):
    resource_id, _ = GATHER_RESOURCES[resource]
    return struct.pack("<6H", 5, 6, (level + 1) * 2, (level + 1) * 2, (resource_id + 1) * 2, 4)


def point_body(point, state):
    return struct.pack("<HHHI", 2, 0, (state + 1) * 2, len(point)) + point


def sproto_record(values):
    headers, extra = [], bytearray()
    for value in values:
        if 0 <= value < 32767:
            headers.append((value + 1) * 2)
        else:
            headers.append(0)
            extra.extend(struct.pack("<II", 4, value))
    return struct.pack("<H", len(headers)) + struct.pack(f"<{len(headers)}H", *headers) + extra


def record_list(rows):
    return b"".join(struct.pack("<I", len(row)) + row for row in rows)


def gather_formation(resource, inventory, preset, slots=GATHER_MARCH_SLOTS):
    divisor = max(1, int(slots))
    troops = [(troop, min(count, inventory.get(troop, 0)) // divisor) for troop, count in preset]
    troops = [(troop, count) for troop, count in troops if count > 0]
    if not troops:
        troops = [(troop, available // divisor) for troop, available in inventory.items() if available // divisor]
    if not troops:
        raise RuntimeError("the bot has no available troops for gathering")
    # A gathering march does not require a specialist hero. Forcing one makes
    # small accounts fail when that hero is missing or already on another march.
    heroes = b""
    soldiers = record_list([sproto_record(row) for row in troops])
    return struct.pack("<3H", 2, 0, 0) + struct.pack("<I", len(heroes)) + heroes + struct.pack("<I", len(soldiers)) + soldiers


def gather_body(point, formation):
    return struct.pack("<4HI", 3, 10, 0, 0, len(point)) + point + struct.pack("<I", len(formation)) + formation


def occupied_formation(row, bot, state):
    formation_id = number(row.get(0, 0))
    if not formation_id:
        return None
    return {
        "march_id": None,
        "formation_id": formation_id,
        "bot": bot,
        "resource": "occupied march",
        "state": state,
        "x": None,
        "y": None,
        "started_at": 0,
        "arrives_at": 0,
        "status": "occupied",
        "protocols": [4001],
        "source": "server",
    }


def ranking_entry(rows, rid):
    for position, row in enumerate(rows, 1):
        if number(row[0]) == rid:
            return {
                "position": position,
                "value": number(row[1]),
                "alliance_rank": number(row[2]),
            }
    return None


def add_presence(members):
    if any(member.get("last_active_at", 0) > 0 for member in members):
        for member in members:
            member["online"] = not member.get("last_active_at", 0)


def decode_attack_push(events, frame, captured_at=None, source="live"):
    if frame[:2] != b"\x01\x00":
        return
    protocol = int.from_bytes(frame[2:4], "little") // 2 - 1
    if protocol not in {5658, 5753, 7052}:
        return
    try:
        payload = fields(frame[4:])
        if protocol == 5658:
            for outer in records(payload[0]):
                route = fields(outer[1])
                if number(route.get(9, 0)) != 2:
                    continue
                origin = fields(route[2])
                target = fields(route[3])
                alliance_id = number(route.get(16, 0))
                events.append({
                    "march_id": number(route[0]),
                    "attacker_rid": number(route[1]),
                    "source_x": number(origin[0]),
                    "source_y": number(origin[1]),
                    "target_x": number(target[0]),
                    "target_y": number(target[1]),
                    "started_at": number(route[6]),
                    "arrives_at": number(route[7]),
                    "observed_at": captured_at or time.time(),
                    "target_alliance_id": alliance_id or None,
                    "state": alliance_id // 1_000_000 if alliance_id else None,
                    "status": "incoming",
                    "source": source,
                    "protocols": [5658],
                })
        elif protocol == 7052:
            for row in records(payload[1]):
                march_id = number(row[0])
                event = next((item for item in reversed(events) if item["march_id"] == march_id), None)
                if event:
                    event["target_rid"] = number(fields(row[14])[0])
                    if protocol not in event["protocols"]:
                        event["protocols"].append(protocol)
        else:
            march_id = number(payload[0])
            event = next((item for item in reversed(events) if item["march_id"] == march_id), None)
            if event:
                event["status"] = "returning"
                event["updated_at"] = captured_at or time.time()
                if protocol not in event["protocols"]:
                    event["protocols"].append(protocol)
        del events[:-100]
    except (AssertionError, KeyError, TypeError, ValueError):
        return


def incoming_attack(event, rid):
    return event.get("target_rid") == rid and bool(event.get("march_id"))


def attacks_from_capture(path):
    if not path.exists():
        return []
    events = []
    captured = list(wire.packets(path))
    stream, origins, _ = wire.stream(captured, "S")
    for _, packed, origin in wire.frames(stream, origins):
        try:
            decode_attack_push(
                events,
                wire.unpack_sproto(packed),
                origin["time"] if origin else None,
                path.name,
            )
        except ValueError:
            continue
    return events


def battle_reports_from_capture(path):
    if not path.exists():
        return []
    requests = {}
    responses = {}
    captured = list(wire.packets(path))
    for direction in "CS":
        stream, origins, _ = wire.stream(captured, direction)
        for _, packed, origin in wire.frames(stream, origins):
            try:
                frame = wire.unpack_sproto(packed)
                count = int.from_bytes(frame[:2], "little")
                headers = [int.from_bytes(frame[2 + 2 * i : 4 + 2 * i], "little") for i in range(count)]
                body = frame[2 + 2 * count :]
                if direction == "C" and count >= 2 and headers[0] != 1:
                    protocol = (headers[0] - 2) // 2
                    if protocol == 2508:
                        requests[(headers[1] - 2) // 2] = text(fields(body)[1])
                elif direction == "S" and count >= 2 and headers[0] == 1:
                    responses[(headers[1] - 2) // 2] = (fields(body), origin["time"] if origin else None)
            except (KeyError, TypeError, ValueError):
                continue

    events = []
    for session, report_id in requests.items():
        try:
            response, observed_at = responses[session]
            document = msgpack_value(response[1], raw=True)
            battle = fields(wire.unpack_sproto(document[b"content"][b"battle_result"]))
            location = fields(battle[0])
            result = fields(battle[1])
            target_route = fields(location[2])
            source_route = fields(location[3])
            target_point = fields(target_route[5])
            source_point = fields(source_route[5])

            def side(raw):
                row = next(records(fields(raw)[0]))
                identity = fields(row[1])
                return {
                    "rid": number(row[0]),
                    "name": text(identity[2]).replace("\u00a0", " "),
                    "alliance_tag": text(identity[4]),
                    "power": number(identity[5]),
                }

            target = side(result[2])
            attacker = side(result[3])
            events.append({
                "report_id": report_id,
                "march_id": None,
                "attacker_rid": attacker["rid"],
                "attacker_name": attacker["name"],
                "attacker_alliance_tag": attacker["alliance_tag"],
                "attacker_power": attacker["power"],
                "attacker_power_loss": number(source_route[6]),
                "target_rid": target["rid"],
                "target_name": target["name"],
                "target_alliance_tag": target["alliance_tag"],
                "target_power": target["power"],
                "target_power_loss": number(target_route[6]),
                "source_x": number(source_point[0]),
                "source_y": number(source_point[1]),
                "target_x": number(target_point[0]),
                "target_y": number(target_point[1]),
                "started_at": number(result[1]),
                "arrives_at": None,
                "observed_at": observed_at or number(result[1]),
                "state": number(location[1]),
                "status": "completed",
                "source": path.name,
                "protocols": [2508],
            })
        except (KeyError, StopIteration, TypeError, ValueError):
            continue
    return events


def scout_reports_from_capture(path):
    if not path.exists():
        return []
    requests, responses = {}, {}
    captured = list(wire.packets(path))
    for direction in "CS":
        stream, origins, _ = wire.stream(captured, direction)
        for _, packed, origin in wire.frames(stream, origins):
            try:
                frame = wire.unpack_sproto(packed)
                count = int.from_bytes(frame[:2], "little")
                headers = [int.from_bytes(frame[2 + 2 * i : 4 + 2 * i], "little") for i in range(count)]
                body = frame[2 + 2 * count :]
                if direction == "C" and count >= 2 and headers[0] != 1 and (headers[0] - 2) // 2 == 2508:
                    requests[(headers[1] - 2) // 2] = text(fields(body)[1])
                elif direction == "S" and count >= 2 and headers[0] == 1:
                    responses[(headers[1] - 2) // 2] = (fields(body), origin["time"] if origin else None)
            except (KeyError, TypeError, ValueError):
                continue

    reports = []
    for session, report_id in requests.items():
        try:
            response, observed_at = responses[session]
            content = msgpack_value(response[1], raw=True)[b"content"]
            recon = fields(wire.unpack_sproto(content[b"recon_result"]))
            target, city, point = fields(recon[0]), fields(recon[1]), content[b"point"]
            defenders = []
            for group in records(recon[2]):
                identity = fields(group[0])
                heroes = []
                for hero in records(group.get(1, b"")):
                    loadout = fields(hero.get(5, b""))
                    heroes.append({
                        "slot": number(hero[0]),
                        "id": number(hero[1]),
                        "level": number(hero.get(3, 0)),
                        "skills": [{"id": number(skill[0]), "level": number(skill.get(1, 0))} for skill in records(hero.get(4, b""))],
                        "gear": [{"id": number(item.get(1, 0)), "level": number(item.get(0, 0)), "slot": number(item.get(5, 0))} for item in records(loadout.get(1, b""))],
                    })
                troops = [
                    {
                        "id": number(row[0]),
                        "type": {1: "Infantry", 2: "Lancer", 3: "Marksman"}.get(number(row[0]) // 10000, "Troop"),
                        "tier": number(row[0]) % 10000 // 100,
                        "count": number(row.get(2, 0)),
                    }
                    for row in records(group.get(2, b""))
                ]
                defenders.append({
                    "rid": number(identity[0]),
                    "name": text(identity[2]).replace("\u00a0", " "),
                    "alliance_tag": text(identity.get(4, b"")).replace("\u00a0", " "),
                    "power": number(identity.get(5, 0)),
                    "troop_total": sum(row["count"] for row in troops),
                    "heroes": heroes,
                    "troops": troops,
                })
            resources = {number(row[0]): number(row[1]) for row in records(city.get(2, b""))}
            bonuses = {number(row[0]): number(row[1]) for row in records(recon.get(3, b""))}
            universal = {"Attack": 10113, "Defense": 10114, "Lethality": 10115, "Health": 10116}
            stats = []
            for troop, start in (("Infantry", 10101), ("Lancer", 10105), ("Marksman", 10109)):
                for offset, stat in enumerate(("Attack", "Defense", "Lethality", "Health")):
                    stats.append({"label": f"{troop} {stat}", "value": (bonuses.get(start + offset, 0) + bonuses.get(universal[stat], 0)) / 100})
            reports.append({
                "report_id": report_id,
                "observed_at": observed_at,
                "state": int(content[b"kid"]),
                "x": int(point[b"x"]),
                "y": int(point[b"y"]),
                "target_rid": number(target[0]),
                "target_name": text(target[2]).replace("\u00a0", " "),
                "target_alliance_tag": text(target.get(4, b"")).replace("\u00a0", " "),
                "target_power": number(target.get(5, 0)),
                "wall_current": max(0, number(city.get(0, 0)) - number(city.get(1, 0))),
                "wall_max": number(city.get(0, 0)),
                "resources": {"meat": resources.get(101, 0), "wood": resources.get(102, 0), "coal": resources.get(104, 0), "iron": resources.get(103, 0)},
                "troop_total": sum(group["troop_total"] for group in defenders),
                "defenders": defenders,
                "stats": stats,
                "protocols": [2501, 2508],
            })
        except (KeyError, StopIteration, TypeError, ValueError):
            continue
    return sorted(reports, key=lambda report: report["observed_at"] or 0, reverse=True)


def roster_body(state, alliance_id):
    return struct.pack("<HHHI", 2, 0, (state + 1) * 2, 4) + struct.pack("<I", alliance_id)


def map_body(state, x1, y1, x2, y2, sequence):
    nested = (
        bytes.fromhex("1c000000030000000000")
        + struct.pack("<H", (state + 1) * 2)
        + bytes.fromhex("060000000200")
        + struct.pack("<HH", (x1 + 1) * 2, (y1 + 1) * 2)
        + bytes.fromhex("060000000200")
        + struct.pack("<HH", (x2 + 1) * 2, (y2 + 1) * 2)
    )
    return struct.pack("<HHHHHI", 4, 0, (sequence + 1) * 2, 2, 2, len(nested)) + nested


MAP_TILE_ORDER = sorted(
    range(1600),
    key=lambda tile: ((tile % 40) - 19.5) ** 2 + ((tile // 40) - 19.5) ** 2,
)


def map_position(index):
    tile = MAP_TILE_ORDER[index]
    return tile % 40 * 30, tile // 40 * 30


MAP_ALLIANCE_FIELDS = {2: 3, 3: 2, 8: 1, 9: 1, 10: 0, 11: 0, 12: 0, 15: 1, 17: 3}
MAP_PLAYERS = {}


def cached_map_players(state):
    return list(MAP_PLAYERS.get(int(state), {}).values())


def restore_map_players(state, players):
    restored = {}
    for player in players or []:
        if not isinstance(player, dict) or not str(player.get("rid", "")).isdigit():
            continue
        restored[int(player["rid"])] = dict(player)
    MAP_PLAYERS[int(state)] = restored


def add_map_data(members, state):
    now = int(time.time())
    for member in members:
        if city := MAP_PLAYERS.get(int(state), {}).get(member["rid"]):
            member.update(city)
            member["shielded"] = member["shield_end"] > now
    return members


def map_city(row, observed_at=None):
    try:
        position, marker = fields(row[0]), fields(row[2])
        if not (isinstance(marker.get(0), bytes) and isinstance(marker.get(2), bytes)):
            return None
        observed_at = int(observed_at or time.time())
        alliance_id = number(marker.get(3, 0))
        shield_end = number(marker.get(7, 0))
        return {
            "rid": number(marker[0]),
            "x": number(position[0]),
            "y": number(position[1]),
            "coordinate_state": number(marker.get(12, 0)) or alliance_id // 1_000_000,
            "furnace_level": number(marker.get(1, 0)),
            "shield_end": shield_end,
            "shielded": shield_end > observed_at,
            "map_observed_at": observed_at,
        }
    except (KeyError, TypeError, ValueError):
        return None


def reinforcement_report(summary, detail_rows=()):
    members = []
    for row in detail_rows:
        troops = [
            {"unit_id": number(item[0]), "count": number(item.get(2, 0))}
            for item in records(row.get(3, b""))
        ]
        heroes = []
        for item in records(row.get(2, b"")):
            hero = fields(item[1])
            heroes.append({"slot": number(item[0]), "hero_id": number(hero[0]), "level": number(hero.get(1, 0))})
        members.append({
            "rid": number(row[0]),
            "march_id": number(row.get(1, 0)),
            "name": text(row.get(7, b"")).replace("\u00a0", " "),
            "alliance_tag": text(row.get(8, b"")).replace("\u00a0", " "),
            "alliance_id": number(row.get(9, 0)),
            "troops": troops,
            "total_troops": number(row.get(12, 0)) or sum(item["count"] for item in troops),
            "heroes": heroes,
        })
    troop_total = number(summary.get(2, 0))
    count = number(summary.get(3, 0))
    return {
        "capacity": number(summary.get(1, 0)),
        "reinforcement_troops": troop_total,
        "reinforcement_count": count,
        "reinforced": count > 0 or troop_total > 0,
        "reinforcers": members,
        "protocols": [10101, 10102] if count else [10101],
    }


def alliance_details(row):
    alliance_id = number(row[0])
    return {
        "id": alliance_id,
        "name": text(row[1]).replace("\u00a0", " "),
        "tag": text(row[2]).replace("\u00a0", " "),
        "state": alliance_id // 1_000_000,
        "member_count": number(row[8]),
        "capacity": number(row[20]),
        "leader_rid": number(row[13]),
        "leader_name": text(row[15]).replace("\u00a0", " "),
        "exact_power": number(row[16]),
        "announcement": text(row[9]),
        "description": text(row[10]),
        "map_visible": True,
    }


def tcp_segments(path, port, client=True):
    raw = path.read_bytes()
    ip_offset = wire.pcap_ip_offset(raw)
    ether_type_offset = ip_offset - 2
    offset = 24
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from("<IIII", raw, offset)
        packet = raw[offset + 16 : offset + 16 + captured]
        offset += 16 + captured
        ipv4 = packet[:4] in (b"\x02\x00\x00\x00", b"\x00\x00\x00\x02") if ip_offset == 4 else packet[ether_type_offset:ip_offset] == b"\x08\x00"
        if len(packet) < ip_offset + 40 or not ipv4:
            continue
        ip = packet[ip_offset:]
        header = (ip[0] & 15) * 4
        if ip[9] != 6:
            continue
        source, destination = struct.unpack_from("!HH", ip, header)
        tcp_header = (ip[header + 12] >> 4) * 4
        payload = ip[header + tcp_header : struct.unpack_from("!H", ip, 2)[0]]
        if payload and ((client and destination == port) or (not client and source == port)):
            remote_ip = socket.inet_ntoa(ip[16:20] if client else ip[12:16])
            yield struct.unpack_from("!I", ip, header + 4)[0], payload, remote_ip, source if client else destination


def endpoint(path, port=30101):
    captured = list(tcp_segments(path, port))
    if not captured:
        raise ValueError(f"handshake capture has no TCP {port} connection") from None
    connection = max({item[3] for item in captured}, key=lambda value: sum(len(item[1]) for item in captured if item[3] == value))
    return next(item[2] for item in captured if item[3] == connection), port


def tcp_stream(path, port, client=True):
    captured = list(tcp_segments(path, port, client))
    if not captured:
        return b""
    connection = max({item[3] for item in captured}, key=lambda value: sum(len(item[1]) for item in captured if item[3] == value))
    segments = sorted((item for item in captured if item[3] == connection), key=lambda item: item[0])
    if not segments:
        return b""
    base = segments[0][0]
    output = bytearray()
    for sequence, payload, _, _ in segments:
        start = sequence - base
        if start > len(output):
            raise ValueError(f"handshake capture has a TCP {port} gap")
        output.extend(payload[max(0, len(output) - start) :])
    return bytes(output)


def login_frame(path):
    captured = list(wire.packets(path))
    stream, origins, gaps = wire.stream(captured, "C")
    for _, frame, _ in wire.frames(stream, origins):
        if wire.unpack_sproto(frame)[:4] == b"\x02\x00\x04\x00":
            return frame
    if gaps:
        raise ValueError("handshake capture has TCP gaps before a complete game login")
    raise ValueError("handshake capture has no game login request")


class WosSession:
    def __init__(self, handshake=GAME_HANDSHAKE, timeout=15, rid=None, state=None, bot=None):
        self.handshake = handshake
        self.remote = endpoint(handshake)
        self.login = login_frame(handshake)
        self.timeout = timeout
        self.connection = None
        self.buffer = b""
        self.session = 1
        self.scan = None
        self.attacks = []
        self.gathers = {}
        self.rid, self.state, self.bot = rid, state, bot
        self.troops = {}
        self.formation_troops = []
        self.auto_shield = {"enabled": False, "rid": None, "pending": None, "last_attack": None, "last_shield": None, "last_error": None}
        self.lock = threading.Lock()
        threading.Thread(target=self._keepalive, daemon=True).start()

    def _connect(self):
        self.buffer = b""
        self.session = 1
        try:
            self.connection = socket.create_connection(self.remote, self.timeout)
            self.connection.settimeout(self.timeout)
            self._send(self.login)
            self._response(1, required=False)
            self._request(21, required=False)
        except Exception:
            if self.connection:
                self.connection.close()
            self.connection = None
            self.buffer = b""
            raise

    def _send(self, packed):
        self.connection.sendall(struct.pack(">H", len(packed)) + packed)

    def _receive(self):
        while len(self.buffer) < 2 or len(self.buffer) < 2 + int.from_bytes(self.buffer[:2], "big"):
            chunk = self.connection.recv(65536)
            if not chunk:
                raise ConnectionError("game server closed the connection")
            self.buffer += chunk
        size = int.from_bytes(self.buffer[:2], "big")
        packed, self.buffer = self.buffer[2 : 2 + size], self.buffer[2 + size :]
        return wire.unpack_sproto(packed)

    def _response(self, session, required=True, pushes=None):
        expected = struct.pack("<H", (session + 1) * 2)
        while True:
            frame = self._receive()
            if frame[:2] == b"\x01\x00":
                self._formation_push(frame)
                decode_attack_push(self.attacks, frame)
                if self.attacks:
                    self._queue_auto_shield(self.attacks[-1])
                self._gather_push(frame)
                if pushes is not None and int.from_bytes(frame[2:4], "little") // 2 - 1 == 5652:
                    pushes.append(frame)
            if frame[:4] == b"\x02\x00\x01\x00" and frame[4:6] == expected:
                body = fields(frame[6:])
                if required and not isinstance(body.get(1), bytes):
                    raise RuntimeError("game server rejected the authenticated request")
                return body

    def _request(self, protocol, body=b"", required=True, pushes=None):
        self.session += 1
        self._send(request(protocol, self.session, body))
        return self._response(self.session, required, pushes)

    def _keepalive(self):
        while True:
            threading.Event().wait(3)
            with self.lock:
                if self.auto_shield["enabled"] and not self.connection:
                    try:
                        self._connect()
                        self.auto_shield["last_error"] = None
                    except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                        self.auto_shield["last_error"] = str(error)
                        if self.connection:
                            self.connection.close()
                        self.connection = None
                if self.connection:
                    try:
                        self._request(22, required=False)
                        if self.auto_shield["pending"]:
                            self._activate_auto_shield()
                    except (ConnectionError, OSError, RuntimeError, ValueError):
                        self.connection.close()
                        self.connection = None

    def _queue_auto_shield(self, event):
        if not self.auto_shield["enabled"] or not incoming_attack(event, self.auto_shield["rid"]):
            return
        attack = {key: event.get(key) for key in ("march_id", "attacker_rid", "target_rid", "source_x", "source_y", "target_x", "target_y", "arrives_at", "observed_at")}
        self.auto_shield.update(pending=attack, last_attack=attack)

    def _activate_auto_shield(self):
        attack = self.auto_shield["pending"]
        self.auto_shield.update(enabled=False, pending=None)
        try:
            response = self._request(7201, struct.pack("<3H", 2, 4, 4), required=False)
            code = number(response.get(0, 0))
            if code == 8501:
                for step, body in enumerate(GEM_TWO_HOUR_SHIELD, 1):
                    fallback = self._request(8501, body, required=False)
                    fallback_code = number(fallback.get(0, 0))
                    if fallback_code:
                        raise RuntimeError(f"400-gem shield step {step} rejected (code {fallback_code})")
                protocol = "8501 x3 (400 gems, 2h)"
            elif code:
                raise RuntimeError(f"shield request rejected (code {code})")
            else:
                protocol = 7201
            self.auto_shield.update(last_shield={"at": int(time.time()), "march_id": attack["march_id"], "protocol": protocol}, last_error=None)
        except (ConnectionError, OSError, RuntimeError, ValueError) as error:
            self.auto_shield["last_error"] = str(error)
            if isinstance(error, (ConnectionError, OSError)):
                if self.connection:
                    self.connection.close()
                self.connection = None

    def set_auto_shield(self, rid, enabled):
        with self.lock:
            self.auto_shield.update(enabled=enabled, rid=rid, pending=None, last_error=None)
            if enabled and not self.connection:
                try:
                    self._connect()
                except (ConnectionError, OSError, RuntimeError, ValueError):
                    self.auto_shield["enabled"] = False
                    if self.connection:
                        self.connection.close()
                    self.connection = None
                    raise
            return self.auto_shield_status(locked=True)

    def auto_shield_status(self, locked=False):
        def status():
            return {**self.auto_shield, "monitoring": bool(self.connection), "mode": "one_shot", "protocol": "7201 + 8501 gem fallback"}
        if locked:
            return status()
        with self.lock:
            return status()

    def _gather_push(self, frame):
        if int.from_bytes(frame[2:4], "little") // 2 - 1 != 5756:
            return
        try:
            payload = fields(frame[4:])
            item = self.gathers.get(number(payload[0]))
            if not item:
                return
            update = fields(payload[2])
            mode, end = number(update.get(9, 0)), number(update.get(7, 0))
            if mode == 3:
                item.update(status="gathering", finish_at=end)
            elif mode == 4:
                item.update(status="returning", return_at=end)
        except (KeyError, TypeError, ValueError):
            pass

    def _formation_push(self, frame):
        if int.from_bytes(frame[2:4], "little") // 2 - 1 != 4001:
            return
        try:
            payload = fields(frame[4:])
            self.gathers = {key: item for key, item in self.gathers.items() if not str(key).startswith("slot:")}
            server_ids = set()
            for row in records(payload.get(0, b"")):
                item = occupied_formation(row, self.bot, self.state)
                if item:
                    server_ids.add(item["formation_id"])
                tracked = item and any(
                    local.get("formation_id") == item["formation_id"] and local.get("status") != "returned"
                    for local in self.gathers.values()
                )
                if item and not tracked:
                    self.gathers[f"slot:{item['formation_id']}"] = item
            now = int(time.time())
            for item in self.gathers.values():
                if item.get("status") not in {"marching", "gathering", "returning"}:
                    continue
                formation_id = item.get("formation_id")
                if (formation_id and formation_id not in server_ids) or (not formation_id and not server_ids):
                    item.update(status="returned", return_at=item.get("return_at") or now)
            self.troops = {number(row[0]): number(row[1]) for row in records(payload[1])}
            presets = list(records(payload.get(2, b"")))
            if presets:
                formation = fields(presets[0][1])
                self.formation_troops = [(number(row[0]), number(row[1])) for row in records(formation[1])]
        except (KeyError, TypeError, ValueError):
            self.troops = {}
            self.formation_troops = []

    def _refresh_gathers(self):
        now = time.time()
        for item in self.gathers.values():
            if item.get("status") == "marching" and item.get("arrives_at", now + 1) <= now:
                item["status"] = "gathering"
            if item.get("status") == "returning" and item.get("return_at", now + 1) <= now:
                item["status"] = "returned"

    def list_gathers(self, refresh=False):
        with self.lock:
            if refresh:
                if self.connection:
                    self._request(21, required=False)
                else:
                    self._connect()
                arrivals = [
                    item["arrives_at"] for item in self.gathers.values()
                    if item.get("status") == "marching" and time.time() < item.get("arrives_at", 0) <= time.time() + 8
                ]
                if arrivals:
                    deadline = min(arrivals) + 2
                    while time.time() < deadline:
                        self._request(22, required=False)
                        time.sleep(min(1, max(0, deadline - time.time())))
            self._refresh_gathers()
            return sorted((dict(item) for item in self.gathers.values()), key=lambda item: item["started_at"], reverse=True)

    def disconnect_gather(self):
        with self.lock:
            if self.auto_shield["enabled"]:
                return False
            if self.connection:
                self.connection.close()
                self.connection = None
                self.buffer = b""
            return True

    def start_gather(self, resource, state=1755, bot=None):
        if not valid_bot_state(state) or resource not in GATHER_RESOURCES:
            raise ValueError("select a valid bot and meat, wood, iron, or coal")
        with self.lock:
            self._refresh_gathers()
            if self.connection:
                self._request(21, required=False)
            else:
                self._connect()
            search = self._request(5615, gather_search_body(resource), required=False)
            code = number(search.get(0, 0))
            if code:
                raise RuntimeError(f"resource search rejected (code {code})")
            point = search.get(1)
            if not isinstance(point, bytes) or len(point) != 6:
                raise RuntimeError(f"no available level 8 {resource} tile was returned")
            position = fields(point)
            x, y = number(position[0]), number(position[1])
            if not (0 <= x <= 1200 and 0 <= y <= 1200):
                raise RuntimeError("server returned an invalid resource coordinate")
            self._request(5607, point_body(point, state))
            formation = gather_formation(resource, self.troops, self.formation_troops)
            deploy = self._request(5701, gather_body(point, formation), required=False)
            code = number(deploy.get(0, 0))
            if code or not isinstance(deploy.get(1), bytes):
                if code == 2878:
                    raise RuntimeError("no march slot is available on this account (server code 2878)")
                raise RuntimeError(f"gather deployment rejected (code {code})")
            march = fields(deploy[1])
            march_id = number(march[0])
            started_at = number(march.get(6, int(time.time())))
            item = {
                "march_id": march_id,
                "formation_id": number(march.get(14, 0)) or None,
                "bot": bot or str(state),
                "resource": resource,
                "state": state,
                "x": x,
                "y": y,
                "started_at": started_at,
                "arrives_at": number(march.get(7, started_at)),
                "status": "marching",
                "protocols": [5615, 5607, 5701, 5704],
            }
            self.gathers[march_id] = item
            return dict(item)

    def recall_gather(self, march_id):
        with self.lock:
            item = self.gathers.get(march_id)
            if not item or item["status"] in {"returned", "returning"}:
                return dict(item) if item else None
            if not self.connection:
                self._connect()
            response = self._request(5704, direct_field(march_id), required=False)
            if number(response.get(0, 0)) != 0:
                raise RuntimeError("server rejected the gather recall")
            item.update(status="returning", recall_sent_at=int(time.time()))
            return dict(item)

    def fetch_roster(self, alliance_id, state):
        with self.lock:
            if not self.connection:
                self._connect()
            roster = [
                (number(row[0]), number(row[1]))
                for row in records(self._request(5123, roster_body(state, alliance_id))[1])
            ]
            ranks = dict(roster)
            ids = b"\x04" + b"".join(struct.pack("<I", rid) for rid, _ in roster)
            members = []
            full_profiles = struct.pack("<HHHI", 2, 0, 4, len(ids)) + ids
            for row in records(self._request(1029, full_profiles)[1]):
                member = profile(row)
                if member and member["rid"] in ranks:
                    member["rank"] = ranks[member["rid"]]
                    members.append(member)
        if len(members) != len(roster):
            raise RuntimeError(f"received {len(members)} profiles for {len(roster)} roster members")
        add_map_data(members, state)
        add_presence(members)
        return sorted(members, key=lambda member: member["power"], reverse=True)

    def fetch_alliances(self, state, start=0, count=10):
        with self.lock:
            if not self.connection:
                self._connect()
            if start == 0:
                self._request(5616, direct_field(state), required=False)
                self.scan = {"state": state, "next": 0, "found": {}}
                MAP_PLAYERS[state] = {}
            if not self.scan or self.scan["state"] != state or self.scan["next"] != start:
                raise ValueError("state scan must continue from the returned position")

            total = 1600
            end = min(start + count, total)
            pushes = []
            for index in range(start, end):
                x, y = map_position(index)
                self._request(
                    5601,
                    map_body(state, x, y, x + 29, y + 29, index + 1),
                    required=False,
                    pushes=pushes,
                )
            alliance_ids = set()
            for frame in pushes:
                payload = fields(frame[4:]).get(1)
                if not isinstance(payload, bytes):
                    continue
                for row in records(payload):
                    if city := map_city(row):
                        if city["coordinate_state"] == state:
                            MAP_PLAYERS[state][city["rid"]] = city
                    for marker_field, alliance_field in MAP_ALLIANCE_FIELDS.items():
                        marker = row.get(marker_field)
                        if not isinstance(marker, bytes):
                            continue
                        alliance_id = fields(marker).get(alliance_field)
                        if isinstance(alliance_id, bytes) and len(alliance_id) == 4:
                            alliance_id = number(alliance_id)
                            if alliance_id // 1_000_000 == state:
                                alliance_ids.add(alliance_id)
            found = self.scan["found"]

            def add(row):
                details = alliance_details(row)
                found[details["id"]] = details

            alliance_ids = sorted(alliance_ids)
            for alliance_id in alliance_ids:
                if alliance_id not in found:
                    add(fields(self._request(5138, roster_body(state, alliance_id))[1]))
            self.scan["next"] = end

        return {
            "results": sorted(found.values(), key=lambda alliance: alliance["exact_power"], reverse=True),
            "scanned": end,
            "total": total,
            "done": end == total,
        }

    def fetch_alliance_details(self, alliance_id, state):
        with self.lock:
            if not self.connection:
                self._connect()
            return alliance_details(fields(self._request(5138, roster_body(state, alliance_id))[1]))

    def fetch_details2(self, rid):
        with self.lock:
            if not self.connection:
                self._connect()
            power = ranking_entry(records(self._request(5404)[1]), rid)
            ko = ranking_entry(records(self._request(5405)[1]), rid)
            contribution_response = self._request(5402, direct_field(20001))
            contribution = None
            for position, row in enumerate(records(contribution_response[1]), 1):
                if number(row[0]) == rid:
                    score, updated_at, _ = int_array(row[1])
                    contribution = {
                        "position": position,
                        "value": score,
                        "updated_at": updated_at,
                        "alliance_rank": number(row[2]),
                    }
                    break
            if contribution is None:
                for row in records(contribution_response.get(2, b"")):
                    if number(row[0]) == rid:
                        contribution = {"position": None, "value": number(row[1]), "updated_at": None}
                        break
        return {
            "rid": rid,
            "power": power,
            "ko": ko,
            "daily_contribution": contribution,
            "protocols": {"power": 5404, "ko": 5405, "daily_contribution": "5402 selector 20001"},
        }

    def fetch_reinforcements(self, rid):
        with self.lock:
            if not self.connection:
                self._connect()
            body = bytes_field(struct.pack("<I", rid))
            summary = self._request(10101, body)
            rows = records(self._request(10102, body)[1]) if number(summary.get(3, 0)) else ()
            return {"rid": rid, **reinforcement_report(summary, rows)}


def fpnn_frames(data):
    offset = 0
    while offset + 16 <= len(data):
        if data[offset : offset + 4] != b"FPNN":
            raise ValueError("invalid FPNN frame")
        message_type = data[offset + 6]
        method_size = data[offset + 7] if message_type == 1 else 0
        payload_size = struct.unpack_from("<I", data, offset + 8)[0]
        end = offset + 16 + method_size + payload_size
        if end > len(data):
            break
        yield data[offset:end]
        offset = end


def fpnn_auth_frame(path):
    for frame in fpnn_frames(tcp_stream(path, 13321)):
        if frame[6] == 1 and frame[16 : 16 + frame[7]] == b"auth":
            return frame
    raise ValueError("handshake capture has no FPNN auth request")


def fpnn_alliance_id(path):
    for frame in fpnn_frames(tcp_stream(path, 13321)):
        method_size = frame[7]
        if frame[6] != 1 or frame[16 : 16 + method_size] != b"getgroupmsg":
            continue
        payload = frame[16 + method_size :]
        offset = payload.find(b"\xa3gid") + 4
        if offset < 4 or offset >= len(payload):
            continue
        marker = payload[offset]
        if marker == 0xCD:
            value = int.from_bytes(payload[offset + 1 : offset + 3], "big")
        elif marker == 0xCE:
            value = int.from_bytes(payload[offset + 1 : offset + 5], "big")
        else:
            continue
        if value >= 1_000_000:
            return value
    raise ValueError("handshake capture has no alliance chat group")


def chat_group(alliance_id, handshake=HANDSHAKE):
    own_alliance = fpnn_alliance_id(handshake)
    own_state = own_alliance // 1_000_000
    if alliance_id == own_alliance:
        return alliance_id
    return own_state if alliance_id // 1_000_000 == own_state else None


def json_objects(payload):
    for offset, marker in enumerate(payload):
        if 0xA0 <= marker <= 0xBF:
            size, header = marker & 31, 1
        elif marker == 0xD9 and offset + 2 <= len(payload):
            size, header = payload[offset + 1], 2
        elif marker == 0xDA and offset + 3 <= len(payload):
            size, header = int.from_bytes(payload[offset + 1 : offset + 3], "big"), 3
        elif marker == 0xDB and offset + 5 <= len(payload):
            size, header = int.from_bytes(payload[offset + 1 : offset + 5], "big"), 5
        else:
            continue
        value = payload[offset + header : offset + header + size]
        if len(value) == size and value[:1] == b"{":
            try:
                yield json.loads(value)
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass


def msgpack_value(data, raw=False):
    offset = 0

    def take(size):
        nonlocal offset
        value = data[offset : offset + size]
        if len(value) != size:
            raise ValueError("truncated MessagePack value")
        offset += size
        return value

    def decode():
        marker = take(1)[0]
        if marker <= 0x7F:
            return marker
        if marker >= 0xE0:
            return marker - 256
        if 0xA0 <= marker <= 0xBF:
            value = take(marker & 31)
            return value if raw else value.decode("utf-8", "replace")
        if 0x90 <= marker <= 0x9F:
            return [decode() for _ in range(marker & 15)]
        if 0x80 <= marker <= 0x8F:
            return {decode(): decode() for _ in range(marker & 15)}
        if marker == 0xC0:
            return None
        if marker in (0xC2, 0xC3):
            return marker == 0xC3
        numbers = {
            0xCC: (1, ">B"), 0xCD: (2, ">H"), 0xCE: (4, ">I"), 0xCF: (8, ">Q"),
            0xD0: (1, ">b"), 0xD1: (2, ">h"), 0xD2: (4, ">i"), 0xD3: (8, ">q"),
        }
        if marker in numbers:
            size, format_ = numbers[marker]
            return struct.unpack(format_, take(size))[0]
        if marker in (0xCA, 0xCB):
            return struct.unpack(">f" if marker == 0xCA else ">d", take(4 if marker == 0xCA else 8))[0]
        if marker in (0xC4, 0xC5, 0xC6):
            return take(int.from_bytes(take({0xC4: 1, 0xC5: 2, 0xC6: 4}[marker]), "big"))
        if marker in (0xD9, 0xDA, 0xDB):
            size = int.from_bytes(take({0xD9: 1, 0xDA: 2, 0xDB: 4}[marker]), "big")
            value = take(size)
            return value if raw else value.decode("utf-8", "replace")
        if marker in (0xDC, 0xDD):
            return [decode() for _ in range(int.from_bytes(take(2 if marker == 0xDC else 4), "big"))]
        if marker in (0xDE, 0xDF):
            return {decode(): decode() for _ in range(int.from_bytes(take(2 if marker == 0xDE else 4), "big"))}
        raise ValueError(f"unsupported MessagePack marker {marker:#x}")

    return decode()


def chat_objects(payload):
    try:
        decoded = msgpack_value(payload)
        rows = decoded.get("msgs", []) if isinstance(decoded, dict) else []
    except (ValueError, struct.error):
        rows = []
    if not rows:
        yield from json_objects(payload)
        return
    for row in rows:
        if not isinstance(row, list) or len(row) < 8 or not isinstance(row[6], str):
            continue
        try:
            message = json.loads(row[6])
        except json.JSONDecodeError:
            continue
        message["_chat"] = {
            "id": row[0],
            "sender_rid": row[1],
            "transport_type": row[2],
            "mid": str(row[3]),
            "text": row[5] if isinstance(row[5], str) else "",
            "time_ms": row[7],
        }
        yield message


def bot_name_from_capture(path, uid):
    for client in (False, True):
        try:
            for frame in fpnn_frames(tcp_stream(path, 13321, client)):
                payload = frame[16 + (frame[7] if frame[6] == 1 else 0) :]
                for message in chat_objects(payload):
                    chat = message.get("_chat", {})
                    other = message.get("other") if isinstance(message.get("other"), dict) else {}
                    name = other.get("nickName") or message.get("nickName")
                    message_uid = other.get("uid") or other.get("rid") or message.get("uid") or message.get("rid")
                    if uid in (chat.get("sender_rid"), message_uid) and name:
                        return str(name).replace("\u00a0", " ")
        except (OSError, ValueError, struct.error):
            pass
    return None


def direct_message(row, conversation_rid, unread=0):
    if (
        type(conversation_rid) is not int
        or not 0 < conversation_rid <= 0xFFFFFFFF
        or type(unread) is not int
        or unread < 0
    ):
        return None
    if not isinstance(row, list) or len(row) < 8 or not isinstance(row[6], str):
        return None
    try:
        message = json.loads(row[6])
    except json.JSONDecodeError:
        message = {}
    other = message.get("other") if isinstance(message.get("other"), dict) else {}
    body = row[5] if isinstance(row[5], str) else ""
    message_type = message.get("msgtype")
    return {
        "conversation_rid": conversation_rid,
        "unread": unread,
        "message_id": row[0],
        "direction": "sent" if row[1] == 1 else "received",
        "transport_type": row[2],
        "mid": str(row[3]),
        "text": body,
        "preview": body or f"System message {message_type or 'unknown'}",
        "time_ms": row[7],
        "sender_name": str(other.get("nickName") or message.get("nickName") or "").replace("\u00a0", " "),
        "state": other.get("kid") or message.get("sender_kid") or message.get("kid"),
        "alliance_tag": other.get("abbr") or message.get("abbr"),
        "vip": other.get("vip"),
        "message_type": message_type,
        "reply_mid": message.get("replyMid"),
        "mentions": list(message.get("atDic", {}).values()) if isinstance(message.get("atDic"), dict) else [],
    }


def dm_conversation_payload(mtime=None):
    mtime = int(time.time() * 1000) if mtime is None else mtime
    if type(mtime) is not int or not 0 <= mtime <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("mtime must be an unsigned 64-bit integer")
    return b"\x81\xa5mtime\xcf" + struct.pack(">Q", mtime)


def checked_chat_response(response):
    if code := response.get("code"):
        raise RuntimeError(f"chat session rejected by server (code {code}); add a fresh PCAP for this bot in Settings")
    return response


def message_coordinates(message):
    other = message.get("other") if isinstance(message.get("other"), dict) else {}
    return next(
        ((value["x"], value["y"]) for value in (message, message.get("point"), message.get("city_point"), other.get("city_point"))
         if isinstance(value, dict) and isinstance(value.get("x"), int) and isinstance(value.get("y"), int)),
        (None, None),
    )


class FpnnSession:
    def __init__(self, handshake=HANDSHAKE, timeout=15, auth=None, remote=None, alliance_id=None):
        self.handshake = handshake
        self.timeout = timeout
        self.auth = auth
        self.remote = remote
        self.alliance_id = alliance_id
        self.connection = None
        self.buffer = b""
        self.sequence = 1
        self.lock = threading.Lock()

    def _receive(self):
        while len(self.buffer) < 12:
            self.buffer += self.connection.recv(65536)
        method_size = self.buffer[7] if self.buffer[6] == 1 else 0
        total = 16 + method_size + struct.unpack_from("<I", self.buffer, 8)[0]
        while len(self.buffer) < total:
            chunk = self.connection.recv(65536)
            if not chunk:
                raise ConnectionError("chat server closed the connection")
            self.buffer += chunk
        frame, self.buffer = self.buffer[:total], self.buffer[total:]
        return frame

    def _response(self, sequence):
        while True:
            frame = self._receive()
            if frame[6] == 1:
                reply = b"FPNN\x01\x80\x02\x00\x01\x00\x00\x00" + frame[12:16] + b"\x80"
                self.connection.sendall(reply)
            elif frame[6] == 2 and int.from_bytes(frame[12:16], "little") == sequence:
                return frame[16:]

    def _connect(self):
        auth = self.auth or fpnn_auth_frame(self.handshake)
        self.sequence = int.from_bytes(auth[12:16], "little")
        self.connection = socket.create_connection(self.remote or endpoint(self.handshake, 13321), self.timeout)
        self.connection.settimeout(self.timeout)
        self.connection.sendall(auth)
        self._response(self.sequence)

    def _call(self, method, payload):
        for attempt in range(2):
            try:
                if not self.connection:
                    self._connect()
                self.sequence += 1
                request = (
                    b"FPNN\x01\x80\x01"
                    + bytes((len(method),))
                    + struct.pack("<II", len(payload), self.sequence)
                    + method
                    + payload
                )
                self.connection.sendall(request)
                return self._response(self.sequence)
            except (ConnectionError, OSError):
                if self.connection:
                    self.connection.close()
                self.connection = None
                self.buffer = b""
                if attempt:
                    raise

    def fetch_metadata(self, alliance_id, alliance_tag=None):
        own_alliance = self.alliance_id or fpnn_alliance_id(self.handshake)
        group_id = alliance_id if alliance_id == own_alliance else own_alliance // 1_000_000 if alliance_id // 1_000_000 == own_alliance // 1_000_000 else None
        if group_id is None:
            return {}
        with self.lock:
            method = b"getgroupmsg"
            payload = (
                b"\x87\xa3gid\xce"
                + struct.pack(">I", group_id)
                + b"\xa4desc\xc3\xa3num\x14\xa5begin\x00\xa3end\x00\xa6lastid\x00"
                + b"\xa6mtypes\x96\x1e\x20\x28\x29\x2a\x32"
            )
            response = self._call(method, payload)

        found = {}
        for message in chat_objects(response):
            other = message.get("other") if isinstance(message.get("other"), dict) else {}
            name = other.get("nickName") or message.get("nickName")
            if not name:
                continue
            tag = other.get("abbr") or message.get("abbr")
            if alliance_tag and tag and str(tag).casefold() != str(alliance_tag).casefold():
                continue
            item = found.setdefault(str(name).replace("\u00a0", " ").casefold(), {})
            if "show_vip" in other:
                item["show_vip"] = bool(other["show_vip"])
            if "vip" in other:
                item["vip"] = other["vip"]
            item.update(
                chat_state=other.get("kid") or message.get("sender_kid") or message.get("kid"),
                chat_alliance_tag=tag,
                chat_protocol="FPNN getgroupmsg / TCP 13321",
                chat_scope="alliance" if group_id == alliance_id else "state",
                chat_group_id=group_id,
            )
            if isinstance(message.get("msgtype"), int):
                types = item.setdefault("chat_message_types", [])
                if message["msgtype"] not in types:
                    types.append(message["msgtype"])
            chat = message.get("_chat")
            if isinstance(chat, dict) and len(item.setdefault("chat_messages", [])) < 5:
                item["chat_messages"].append({
                    **chat,
                    "message_type": message.get("msgtype"),
                    "reply_mid": message.get("replyMid"),
                    "mentions": list(message.get("atDic", {}).values()) if isinstance(message.get("atDic"), dict) else [],
                    "broadcast": message.get("broadcast"),
                    "has_skin": bool(message.get("skin") or message.get("equipedskin")),
                })
            x, y = message_coordinates(message)
            if x is not None:
                item.update(
                    x=x,
                    y=y,
                    coordinate_state=other.get("kid") or message.get("sender_kid") or message.get("kid"),
                    coordinate_message_type=message.get("msgtype"),
                )
        return found

    def fetch_dm_conversations(self):
        with self.lock:
            response = checked_chat_response(msgpack_value(self._call(b"getp2pconversationlist", dm_conversation_payload())))
        conversations = response.get("conversations", [])
        unread = response.get("unreads", [])
        messages = response.get("msgs", [])
        return [
            message
            for rid, count, row in zip(conversations, unread, messages)
            if (message := direct_message(row, rid, count))
        ]

    def fetch_dm_history(self, rid, last_id=0):
        payload = (
            b"\x87\xa4ouid\xce" + struct.pack(">I", rid)
            + b"\xa4desc\xc3\xa3num\x14\xa5begin\x00\xa3end\x00\xa6lastid\xce"
            + struct.pack(">I", last_id)
            + b"\xa6mtypes\x96\x1e\x20\x28\x29\x2a\x32"
        )
        with self.lock:
            response = checked_chat_response(msgpack_value(self._call(b"getp2pmsg", payload)))
        return {
            "conversation_rid": rid,
            "last_id": response.get("lastid", 0),
            "messages": [
                message
                for row in response.get("msgs", [])
                if (message := direct_message(row, rid))
            ],
        }


SESSION = WosSession()
SESSION_1755 = WosSession(GAME_HANDSHAKE_1755)
CHAT = FpnnSession()
CHAT_BOTS = {"default": CHAT}
CAPTURED_ATTACKS = attacks_from_capture(ATTACK_CAPTURE) + battle_reports_from_capture(REPORT_CAPTURE)
CAPTURED_SCOUTS = scout_reports_from_capture(SCOUT_CAPTURE)


def fetch_roster(alliance_id, state):
    return (SESSION_1755 if state == 1755 else SESSION).fetch_roster(alliance_id, state)


def fetch_alliances(state, start=0, count=10):
    return SESSION.fetch_alliances(state, start, count)


def fetch_alliance_details(alliance_id, state):
    return SESSION.fetch_alliance_details(alliance_id, state)


def fetch_attacks():
    combined = CAPTURED_ATTACKS + list(SESSION.attacks) + list(SESSION_1755.attacks)
    unique = {}
    for event in combined:
        unique[(event.get("march_id") or event.get("report_id"), event["started_at"])] = event
    return sorted(unique.values(), key=lambda event: event["observed_at"], reverse=True)


def fetch_scout_reports():
    return CAPTURED_SCOUTS


GATHER_SESSIONS = {"default": (SESSION, 1642)}


def register_gather_session(bot, capture, state, rid=None):
    if not valid_bot_state(state):
        raise ValueError("bot state is invalid")
    old = GATHER_SESSIONS.get(bot)
    if old and old[0].connection:
        old[0].connection.close()
        old[0].connection = None
    GATHER_SESSIONS[bot] = (WosSession(capture, rid=rid, state=state, bot=bot), state)


def set_gather_identity(bot, rid):
    session, state = GATHER_SESSIONS[bot]
    session.rid, session.state, session.bot = rid, state, bot


def fetch_gathers(bot=None, refresh=False):
    sessions = [GATHER_SESSIONS[bot]] if bot in GATHER_SESSIONS else GATHER_SESSIONS.values()
    return sorted((item for session, _ in sessions for item in session.list_gathers(refresh)), key=lambda item: item["started_at"], reverse=True)


def restore_gather_runs(bot, runs):
    session = GATHER_SESSIONS[bot][0]
    with session.lock:
        session.gathers.update({run["march_id"]: {**run, "bot": bot} for run in runs if run.get("status") in {"marching", "gathering", "returning"}})


def start_gather(bot, resource):
    session, state = GATHER_SESSIONS[bot]
    return session.start_gather(resource, state, bot)


def recall_gather(bot, march_id):
    return GATHER_SESSIONS[bot][0].recall_gather(march_id)


def disconnect_gather_session(bot):
    game_disconnected = GATHER_SESSIONS[bot][0].disconnect_gather()
    chat = CHAT_BOTS.get(bot)
    if chat:
        with chat.lock:
            if chat.connection:
                chat.connection.close()
                chat.connection = None
                chat.buffer = b""
    return game_disconnected


def bot_connection_state(bot):
    return {
        "game_connected": bool(GATHER_SESSIONS[bot][0].connection),
        "chat_connected": bool(CHAT_BOTS.get(bot) and CHAT_BOTS[bot].connection),
    }


def fetch_auto_shield(bot):
    return GATHER_SESSIONS[bot][0].auto_shield_status()


def set_auto_shield(bot, rid, enabled):
    return GATHER_SESSIONS[bot][0].set_auto_shield(rid, enabled)


def fetch_details2(rid):
    return SESSION.fetch_details2(rid)


def fetch_reinforcements(rid, state):
    return (SESSION_1755 if state == 1755 else SESSION).fetch_reinforcements(rid)


def current_alliance_id():
    return fpnn_alliance_id(HANDSHAKE)


def fetch_chat_metadata(alliance_id, alliance_tag=None):
    candidates = [CHAT, *CHAT_BOTS.values()]
    candidates = [session for session in candidates if (session.alliance_id or fpnn_alliance_id(session.handshake)) // 1_000_000 == alliance_id // 1_000_000]
    candidates.sort(key=lambda session: (session.alliance_id or fpnn_alliance_id(session.handshake)) != alliance_id)
    error = None
    for session in candidates:
        try:
            if result := session.fetch_metadata(alliance_id, alliance_tag):
                return result
        except (ConnectionError, OSError, RuntimeError, ValueError) as caught:
            error = caught
    if error:
        raise error
    return {}


def register_chat_bot(bot_id, auth, remote, alliance_id):
    CHAT_BOTS[bot_id] = FpnnSession(auth=auth, remote=remote, alliance_id=alliance_id)


def chat_bot_session(bot_id="default"):
    if bot_id not in CHAT_BOTS:
        raise ValueError("unknown chat bot")
    return CHAT_BOTS[bot_id]


def fetch_dm_conversations(bot_id="default"):
    return chat_bot_session(bot_id).fetch_dm_conversations()


def fetch_dm_history(rid, last_id=0, bot_id="default"):
    return chat_bot_session(bot_id).fetch_dm_history(rid, last_id)


def chat_metadata_available(alliance_id):
    try:
        return chat_group(alliance_id) is not None
    except ValueError:
        return False


def self_test():
    assert wire.unpack_sproto(login_frame(GAME_HANDSHAKE))[:4] == b"\x02\x00\x04\x00"
    alliance = alliance_details({0: struct.pack("<I", 1755000001), 1: b"DeathAcademy", 2: b"DeD", 8: 99, 9: b"Hello", 10: b"Protected", 13: 1, 15: b"Leader", 16: struct.pack("<Q", 1), 20: 100})
    assert (alliance["state"], alliance["announcement"], alliance["description"]) == (1755, "Hello", "Protected")
    assert ranking_entry([{0: 7, 1: 99, 2: 3}], 7) == {"position": 1, "value": 99, "alliance_rank": 3}
    raw = bytes.fromhex("02000828ea1a02000000d60c040000009df0de6100000000")
    assert wire.unpack_sproto(pack_sproto(raw)) == raw
    assert map_body(1344, 586, 586, 615, 615, 3).hex() == (
        "04000000080002000200200000001c000000030000000000820a060000000200"
        "96049604060000000200d004d004"
    )
    assert MAP_ALLIANCE_FIELDS[2] == 3 and MAP_ALLIANCE_FIELDS[17] == 3
    position = struct.pack("<HHH", 2, (708 + 1) * 2, (757 + 1) * 2)
    marker = struct.pack("<H7H", 7, 0, 40, 0, 0, 0, 3, 0)
    for value in (struct.pack("<I", 197038045), b"Mini me twin", struct.pack("<I", 1755001062), b"deD", struct.pack("<I", 1784280483)):
        marker += struct.pack("<I", len(value)) + value
    city = map_city({0: position, 2: marker}, 1784251683)
    assert (city["rid"], city["x"], city["y"], city["furnace_level"], city["shielded"]) == (197038045, 708, 757, 19, True)
    restore_map_players(9999, [city, {"bad": True}])
    assert cached_map_players(9999) == [city]
    assert add_map_data([{"rid": city["rid"]}], 9999)[0]["x"] == 708
    MAP_PLAYERS.pop(9999)
    reinforcement = reinforcement_report({1: struct.pack("<I", 165000), 2: 30555, 3: 1})
    assert (reinforcement["reinforced"], reinforcement["capacity"], reinforcement["reinforcement_troops"]) == (True, 165000, 30555)
    assert map_position(0) == (570, 570) and map_position(1599) == (1170, 1170)
    assert gather_search_body("wood").hex() == "0500060012001200d0000400"
    assert valid_bot_state(4022) and not valid_bot_state(0)
    formation = gather_formation("meat", {10100: 10, 20100: 8}, [(10100, 8), (20100, 6)], slots=2)
    assert fields(gather_body(bytes.fromhex("02006205d005"), formation))[0] == 4
    assert list(records(fields(formation)[0])) == []
    assert sum(number(row[1]) for row in records(fields(formation)[1])) == 7
    equalized = gather_formation("iron", {10100: 10, 20100: 8}, [])
    assert [tuple(number(row[key]) for key in (0, 1)) for row in records(fields(equalized)[1])] == [(10100, 2), (20100, 2)]
    occupied = occupied_formation({0: 321}, "bot", 1755)
    assert (occupied["formation_id"], occupied["status"], occupied["source"]) == (321, "occupied", "server")
    assert occupied_formation({0: 0}, "bot", 1755) is None
    alliance = struct.pack("<HHHH", 3, 4, 0, 0) + struct.pack("<I", 3) + b"TAG" + struct.pack("<I", 4) + b"Name"
    player = {0: b"Test", 2: 1, 4: 1, 5: alliance, 9: 1, 10: 1}
    assert "vip" not in profile(player) and profile({**player, 7: 9})["vip"] == 9
    assert profile({**player, 3: 123})["last_active_at"] == 123
    presence = [{"last_active_at": 123}, {"last_active_at": 0}]
    add_presence(presence)
    assert presence == [{"last_active_at": 123, "online": False}, {"last_active_at": 0, "online": True}]
    details = profile({**player, 8: b"en", 11: 80, 12: b"avatar.png"})
    assert (details["language"], details["level"], details["avatar_url"]) == (
        "en", 80, "https://gof-formal-avatar.akamaized.net/avatar.png"
    )
    assert (struct.pack("<HHHI", 2, 0, 4, 5) + b"\x04\x01\0\0\0").hex() == "020000000400050000000401000000"
    assert endpoint(GAME_HANDSHAKE)[1] == 30101
    chat_capture = ROOT / "work" / "wos_alliance_scroll_20260714_235858.pcap"
    assert fpnn_auth_frame(chat_capture)[16:20] == b"auth"
    assert fpnn_alliance_id(chat_capture) == 1642000531
    assert chat_group(1642000119) == 1642 and chat_group(1755000001) is None
    messages = [
        message
        for frame in fpnn_frames(tcp_stream(chat_capture, 13321, False))
        for message in json_objects(frame[16:])
    ]
    assert any(message.get("x") == 663 and message.get("y") == 426 for message in messages)
    assert message_coordinates({"msgtype": 504, "point": {"x": 770, "y": 698}}) == (770, 698)
    assert any(message.get("other", {}).get("vip") == 9 for message in messages)
    details_capture = ROOT / "work" / "wos_chat_details_20260715.pcap"
    chat = [
        message
        for frame in fpnn_frames(tcp_stream(details_capture, 13321, False))
        if frame[6] == 2
        for message in chat_objects(frame[16:])
    ]
    assert any(message.get("_chat", {}).get("text") == "I prefer tennis xD" for message in chat)
    assert msgpack_value(b"\x81\xa1k\xa1v", raw=True) == {b"k": b"v"}
    attacks = attacks_from_capture(ATTACK_CAPTURE)
    assert attacks and attacks[0]["march_id"] == 12667
    assert attacks[0]["attacker_rid"] == 61675684 and attacks[0]["target_rid"] == 197038045
    assert incoming_attack(attacks[0], 197038045) and not incoming_attack(attacks[0], 61675684)
    probe = WosSession.__new__(WosSession)
    probe.auto_shield = {"enabled": True, "rid": 197038045, "pending": None, "last_attack": None}
    probe._queue_auto_shield(attacks[0])
    assert probe.auto_shield["pending"]["march_id"] == 12667
    probe.auto_shield["enabled"] = False
    probe.connection, probe.buffer, probe.lock = type("Socket", (), {"close": lambda self: None})(), b"stale", threading.Lock()
    assert probe.disconnect_gather() and probe.connection is None and probe.buffer == b""
    assert wire.unpack_sproto(request(7201, 1194, struct.pack("<3H", 2, 4, 4))).hex() == "02004438560902000400040000000000"
    assert [{key: number(value) for key, value in fields(body).items()} for body in GEM_TWO_HOUR_SHIELD] == [
        {0: 3, 1: 35, 2: 1003079, 4: 0},
        {0: 1, 1: 34, 2: 1001411, 4: 1},
        {0: 1, 1: 39, 2: 1001431, 4: 1},
    ]
    assert (attacks[0]["source_x"], attacks[0]["source_y"]) == (722, 742)
    assert (attacks[0]["target_x"], attacks[0]["target_y"]) == (708, 757)
    assert attacks[0]["status"] == "returning"
    reports = battle_reports_from_capture(REPORT_CAPTURE)
    assert len(reports) == 1 and reports[0]["report_id"] == "1929844729679185"
    assert (reports[0]["attacker_rid"], reports[0]["target_rid"]) == (197038045, 61675684)
    assert (reports[0]["source_x"], reports[0]["source_y"]) == (708, 757)
    assert (reports[0]["target_x"], reports[0]["target_y"]) == (722, 742)
    assert reports[0]["status"] == "completed" and reports[0]["started_at"] == 1784092273
    assert (reports[0]["attacker_power_loss"], reports[0]["target_power_loss"]) == (9, 110)
    scouts = scout_reports_from_capture(SCOUT_CAPTURE)
    assert scouts[0]["target_name"] == "Hayshiteru" and scouts[0]["troop_total"] == 53870
    assert fpnn_auth_frame(DM_CAPTURE)[16:20] == b"auth"
    dm = direct_message([1, 1, 30, 2, 0, "hello", '{"msgtype":30}', 3], 4, 5)
    assert msgpack_value(dm_conversation_payload(1784067527000))["mtime"] == 1784067527000
    try:
        checked_chat_response({"code": 200022})
        assert False
    except RuntimeError as error:
        assert "200022" in str(error)
    assert dm["direction"] == "sent" and dm["text"] == "hello" and dm["unread"] == 5
    assert direct_message([1, 1, 30, 2, 0, "hello", "{}", 3], '"><img onerror=1>', 0) is None
    assert chat_bot_session() is CHAT
    print("self-test passed")


if __name__ == "__main__":
    self_test()
