#!/usr/bin/env python3
"""Persistent automatic gather loop for authenticated bot sessions."""

import threading
import time


COOLDOWN_SECONDS = 5 * 60
RETRY_SECONDS = 60
ACTIVE_STATUSES = {"occupied", "marching", "gathering", "returning"}


def next_event_at(items, now, fallback=RETRY_SECONDS):
    future = []
    for item in items:
        if item.get("status") == "marching" and item.get("arrives_at", 0) > now + 5:
            future.append(item["arrives_at"] - 5)
        for value in (item.get("finish_at"), item.get("return_at")):
            if isinstance(value, (int, float)) and value > now:
                future.append(value + 5)
    return int(min(future)) if future else now + fallback


class GatherScheduler:
    def __init__(self, store, bots, fetch_gathers, start_gather, disconnect_gather, log_returned=None):
        self.store = store
        self.bots = bots
        self.fetch_gathers = fetch_gathers
        self.start_gather = start_gather
        self.disconnect_gather = disconnect_gather
        self.log_returned = log_returned or (lambda item: None)
        self.stop_event = threading.Event()
        self.running = set()
        self.running_lock = threading.Lock()

    def tick(self, now=None):
        now = int(now or time.time())
        for schedule in self.store.active_gather_schedules():
            if schedule["next_run_at"] and schedule["next_run_at"] > now:
                continue
            with self.running_lock:
                if schedule["id"] in self.running:
                    continue
                self.running.add(schedule["id"])
            try:
                self.run_schedule(schedule, now)
            finally:
                with self.running_lock:
                    self.running.discard(schedule["id"])

    def run_schedule(self, schedule, now):
        bot_id = schedule["bot_id"]
        bot = self.bots.get(bot_id)
        if not bot or bot.get("owner_id") != schedule["user_id"] or not bot.get("gather_ready"):
            self.store.update_gather_schedule(schedule["id"], next_run_at=now + RETRY_SECONDS, last_error="Bot session is not loaded; add a fresh game PCAP.")
            return
        try:
            items = self.fetch_gathers(bot_id, True)
            for item in items:
                if item.get("status") == "returned":
                    self.log_returned(item)
            runs = self.store.gather_runs(schedule["id"], 500)
            known_ids = {run["march_id"] for run in runs}
            for item in items:
                if item.get("march_id") in known_ids:
                    self.store.log_gather_run(schedule["id"], next(run["cycle_no"] for run in runs if run["march_id"] == item["march_id"]), item)
            runs = self.store.gather_runs(schedule["id"], 500)
            active = [item for item in items if item.get("status") in ACTIVE_STATUSES]
            cycle_runs = [run for run in runs if run["cycle_no"] == schedule["cycles_started"]]
            cycle_ids = {run["march_id"] for run in cycle_runs}
            cycle_active = any(item.get("march_id") in cycle_ids and item.get("status") in ACTIVE_STATUSES for item in items)
            latest_cycle = max((run["cycle_no"] for run in runs), default=0)
            if schedule["phase"] != "waiting" and latest_cycle > schedule["cycles_started"]:
                latest_ids = {run["march_id"] for run in runs if run["cycle_no"] == latest_cycle}
                latest_items = [item for item in items if item.get("march_id") in latest_ids and item.get("status") in ACTIVE_STATUSES]
                if latest_items:
                    self.store.update_gather_schedule(
                        schedule["id"], cycles_started=latest_cycle, phase="waiting",
                        next_run_at=next_event_at(latest_items, now), last_error=None,
                    )
                    return
            if schedule["phase"] == "waiting":
                if cycle_active or any(item.get("status") == "occupied" for item in active):
                    cycle_items = [item for item in items if item.get("march_id") in cycle_ids]
                    self.store.update_gather_schedule(schedule["id"], next_run_at=next_event_at(cycle_items, now), last_error=None)
                    return
                if not schedule["infinite"] and schedule["cycles_started"] >= schedule["total_cycles"]:
                    self.store.update_gather_schedule(schedule["id"], status="completed", phase="ready", next_run_at=0, last_error=None)
                else:
                    self.store.update_gather_schedule(schedule["id"], phase="cooldown", next_run_at=now + COOLDOWN_SECONDS, last_error=None)
                return
            effective_limit = min(schedule["march_limit"], schedule["detected_limit"] or schedule["march_limit"])
            available = effective_limit - len(active)
            if available <= 0:
                self.store.update_gather_schedule(schedule["id"], next_run_at=now + RETRY_SECONDS, last_error="Waiting for a free march slot.")
                return
            sent = 0
            error_text = None
            cycle_no = schedule["cycles_started"] + 1
            for slot in range(available):
                resource = schedule["resources"][(schedule["cycles_started"] * effective_limit + slot) % len(schedule["resources"])]
                try:
                    item = self.start_gather(bot_id, resource)
                except (ConnectionError, OSError, RuntimeError, ValueError) as error:
                    error_text = str(error)
                    if "2878" in error_text or "no march slot" in error_text.casefold():
                        detected = len(active) + sent
                        if detected:
                            self.store.update_gather_schedule(schedule["id"], detected_limit=detected)
                    break
                self.store.log_gather_run(schedule["id"], cycle_no, item)
                sent += 1
            if sent:
                cycle_items = [run for run in self.store.gather_runs(schedule["id"], 500) if run["cycle_no"] == cycle_no]
                self.store.update_gather_schedule(
                    schedule["id"], cycles_started=cycle_no, phase="waiting", next_run_at=next_event_at(cycle_items, now),
                    last_run_at=now, last_error=error_text,
                )
            else:
                self.store.update_gather_schedule(schedule["id"], next_run_at=now + RETRY_SECONDS, last_error=error_text or "No gather march was sent.")
        except (ConnectionError, OSError, RuntimeError, ValueError) as error:
            self.store.update_gather_schedule(schedule["id"], next_run_at=now + RETRY_SECONDS, last_error=str(error))
        finally:
            if schedule["connection_mode"] == "disconnect":
                self.disconnect_gather(bot_id)

    def run_forever(self):
        while not self.stop_event.wait(2):
            self.tick()

    def start(self):
        threading.Thread(target=self.run_forever, name="gather-scheduler", daemon=True).start()


def self_test():
    import tempfile
    from pathlib import Path
    from wos_saas import SaaSStore

    with tempfile.TemporaryDirectory() as directory:
        store = SaaSStore(Path(directory) / "test.db")
        store.initialize()
        user = store.register("loop@example.test", "correct horse battery", "Loop Test")
        schedule = store.save_gather_schedule(user["id"], "bot", ["meat", "wood"], 2, 2, "disconnect")
        store.update_gather_schedule(schedule["id"], next_run_at=100)
        active, disconnected = [], []

        def fetch(_bot, _refresh):
            return [dict(item) for item in active]

        def send(_bot, resource):
            item = {"resource": resource, "march_id": len(active) + 1, "started_at": 100, "arrives_at": 150, "status": "marching"}
            active.append(item)
            return dict(item)

        scheduler = GatherScheduler(store, {"bot": {"owner_id": user["id"], "gather_ready": True}}, fetch, send, lambda bot: disconnected.append(bot))
        scheduler.tick(100)
        assert len(active) == 2 and store.gather_schedule(user["id"], "bot")["cycles_started"] == 1
        assert store.gather_schedule(user["id"], "bot")["next_run_at"] == 145
        for item in active:
            item["status"] = "returned"
        scheduler.tick(200)
        assert store.gather_schedule(user["id"], "bot")["next_run_at"] == 200 + COOLDOWN_SECONDS
        active.clear()
        scheduler.tick(499)
        assert not active
        scheduler.tick(500)
        assert len(active) == 2 and store.gather_schedule(user["id"], "bot")["cycles_started"] == 2
        for item in active:
            item["status"] = "returned"
        scheduler.tick(600)
        assert store.gather_schedule(user["id"], "bot")["status"] == "completed"
        active.clear()
        schedule = store.save_gather_schedule(user["id"], "bot", ["coal"], 1, 1, "disconnect", True)
        store.update_gather_schedule(schedule["id"], next_run_at=700)
        scheduler.tick(700)
        active[0]["status"] = "returned"
        scheduler.tick(800)
        assert store.gather_schedule(user["id"], "bot")["status"] == "active"
        assert disconnected
    print("gather scheduler self-test passed")


if __name__ == "__main__":
    self_test()
