import json
import sys
from collections import Counter
from pathlib import Path

import analyze_wos_pcap as pcap


def fields(raw):
    count = int.from_bytes(raw[:2], "little")
    headers = [int.from_bytes(raw[2 + 2 * i : 4 + 2 * i], "little") for i in range(count)]
    offset = 2 + 2 * count
    tag = 0
    result = {}
    for header in headers:
        if header & 1:
            tag += (header + 1) // 2
            continue
        if header:
            result[tag] = (header - 2) // 2
        else:
            size = int.from_bytes(raw[offset : offset + 4], "little")
            result[tag] = raw[offset + 4 : offset + 4 + size]
            offset += 4 + size
        tag += 1
    return result


def records(raw):
    offset = 0
    while offset + 4 <= len(raw):
        size = int.from_bytes(raw[offset : offset + 4], "little")
        item = raw[offset + 4 : offset + 4 + size]
        if not size or len(item) != size:
            break
        yield fields(item)
        offset += 4 + size


def number(value):
    return value if isinstance(value, int) else int.from_bytes(value, "little")


def text(value):
    return value.decode("utf-8", "replace")


def int_array(value):
    assert value[:1] in (b"\x04", b"\x08")
    width = value[0]
    return [int.from_bytes(value[i : i + width], "little") for i in range(1, len(value), width)]


def profile(record):
    if not all(tag in record for tag in (0, 2, 4, 5, 9, 10)):
        return None
    alliance = fields(record[5])
    avatar_path = text(record[12]) if 12 in record else None
    return {
        "rid": number(record[2]),
        "player_id": number(record[10]),
        "name": text(record[0]),
        "state": number(record[9]),
        "power": number(record[4]),
        **({"last_active_at": number(record[3])} if 3 in record else {}),
        **({"vip": number(record[7])} if 7 in record else {}),
        **({"language": text(record[8])} if 8 in record else {}),
        **({"level": number(record[11])} if 11 in record else {}),
        **({"avatar_path": avatar_path} if avatar_path else {}),
        "profile_field_tags": sorted(record),
        "alliance_id": number(alliance[0]),
        "alliance_tag": text(alliance[1]),
        "alliance_name": text(alliance[2]),
    }


def main(source, target):
    packets = list(pcap.packets(source))
    requests = {}
    responses = {}
    order = 0
    for direction in "CS":
        stream, origins, _ = pcap.stream(packets, direction)
        for _, packed, _ in pcap.frames(stream, origins):
            order += 1
            unpacked = pcap.unpack_sproto(packed)
            count = int.from_bytes(unpacked[:2], "little")
            headers = [
                int.from_bytes(unpacked[2 + 2 * i : 4 + 2 * i], "little")
                for i in range(count)
            ]
            if direction == "C" and count >= 2 and headers[0] != 1:
                requests[(headers[1] - 2) // 2] = {
                    "order": order,
                    "type": (headers[0] - 2) // 2,
                    "body": unpacked[2 + 2 * count :],
                }
            elif direction == "S" and count >= 2 and headers[0] == 1:
                responses[(headers[1] - 2) // 2] = unpacked[2 + 2 * count :]

    alliances = {}
    profiles = {}
    rosters = {}

    def alliance(alliance_id, **values):
        item = alliances.setdefault(alliance_id, {"id": alliance_id})
        item.update({key: value for key, value in values.items() if value is not None})
        return item

    for session, request in sorted(requests.items(), key=lambda item: item[1]["order"]):
        if session not in responses:
            continue
        protocol = request["type"]
        request_fields = fields(request["body"])
        response_fields = fields(responses[session])
        payload = response_fields.get(1)
        if not isinstance(payload, bytes):
            continue

        if protocol == 5139:
            for item in records(payload):
                alliance(
                    number(item[0]),
                    name=text(item[1]),
                    tag=text(item[2]),
                    state=number(item[5]),
                )
        elif protocol == 5138:
            item = fields(payload)
            alliance_id = number(item[0])
            alliance(
                alliance_id,
                name=text(item[1]),
                tag=text(item[2]),
                state=number(request_fields[1]),
                member_count=number(item[8]),
                capacity=number(item[20]),
                leader_rid=number(item[13]),
                leader_name=text(item[15]),
                exact_power=number(item[16]),
            )
        elif protocol == 5123:
            alliance_id = number(request_fields[0])
            rosters[alliance_id] = [
                {"rid": number(item[0]), "rank": number(item[1])} for item in records(payload)
            ]
            alliance(alliance_id, state=number(request_fields[1]))
        elif protocol in (1023, 1029):
            for item in records(payload):
                decoded = profile(item)
                if not decoded:
                    continue
                profiles[decoded["rid"]] = decoded
                alliance(
                    decoded["alliance_id"],
                    name=decoded["alliance_name"],
                    tag=decoded["alliance_tag"],
                    state=decoded["state"],
                )

    own_roster = None
    for session, request in sorted(requests.items(), key=lambda item: item[1]["order"]):
        if request["type"] == 5404 and session in responses:
            payload = fields(responses[session]).get(1)
            if isinstance(payload, bytes):
                own_roster = [
                    {
                        "rid": number(item[0]),
                        "power": number(item[1]),
                        "rank": number(item[2]),
                    }
                    for item in records(payload)
                ]

    if own_roster:
        candidates = Counter(
            profiles[row["rid"]]["alliance_id"]
            for row in own_roster
            if row["rid"] in profiles
        )
        own_alliance_id = candidates.most_common(1)[0][0]
        rosters[own_alliance_id] = own_roster

    for alliance_id, roster in rosters.items():
        rank_by_rid = {row["rid"]: row["rank"] for row in roster}
        for rid, rank in rank_by_rid.items():
            if rid in profiles:
                profiles[rid]["rank"] = rank
        item = alliance(alliance_id)
        item["roster_count"] = len(roster)
        item["rank_counts"] = {
            f"R{rank}": count
            for rank, count in sorted(Counter(rank_by_rid.values()).items())
        }
        unresolved = [row for row in roster if row["rid"] not in profiles]
        if unresolved:
            item["unresolved_roster_members"] = unresolved
        power_rows = [row["power"] for row in roster if "power" in row]
        if len(power_rows) == len(roster):
            item["roster_power_sum"] = sum(power_rows)
            item.setdefault("exact_power", sum(power_rows))

    for alliance_id, item in alliances.items():
        observed = [player for player in profiles.values() if player["alliance_id"] == alliance_id]
        item["observed_profile_count"] = len(observed)
        item["observed_profile_power_sum"] = sum(player["power"] for player in observed)
        if alliance_id in rosters:
            roster_ids = {row["rid"] for row in rosters[alliance_id]}
            complete = [player for player in observed if player["rid"] in roster_ids]
            item["roster_profiles_decoded"] = len(complete)
            if len(complete) == len(roster_ids):
                item["decoded_roster_power_sum"] = sum(player["power"] for player in complete)

    result = {
        "source": Path(source).name,
        "capture_only": True,
        "alliances": sorted(alliances.values(), key=lambda item: (item.get("state", 0), item.get("tag", ""), item["id"])),
        "profiles": sorted(profiles.values(), key=lambda item: (item["alliance_id"], -item["power"], item["rid"])),
    }

    by_tag = {item.get("tag"): item for item in result["alliances"]}
    assert by_tag["WTH"]["roster_count"] == 96
    assert by_tag["BDL"]["roster_count"] == 43
    assert by_tag["BDL"]["exact_power"] == by_tag["BDL"]["decoded_roster_power_sum"]
    assert by_tag["TGR"]["name"] == "Grimmreapers"
    assert by_tag["RWR"]["name"] == "RoyalWarriors"

    Path(target).write_text(json.dumps(result, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(
        json.dumps(
            {
                "alliances": len(result["alliances"]),
                "profiles": len(result["profiles"]),
                "output": str(target),
                "WTH": {key: by_tag["WTH"].get(key) for key in ("roster_count", "exact_power", "decoded_roster_power_sum")},
                "BDL": {key: by_tag["BDL"].get(key) for key in ("roster_count", "exact_power", "decoded_roster_power_sum")},
                "TGR": {key: by_tag["TGR"].get(key) for key in ("roster_count", "exact_power", "decoded_roster_power_sum")},
                "RWR": {key: by_tag["RWR"].get(key) for key in ("roster_count", "exact_power", "decoded_roster_power_sum")},
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} CAPTURE.pcap OUTPUT.json")
    main(sys.argv[1], sys.argv[2])
