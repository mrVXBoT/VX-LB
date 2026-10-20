import datetime
import time
from typing import Dict, List, Optional, Tuple

from core.dns_routing import effective_config, route_key, routing_lock, snapshot_matches
from core.storage import atomic_update, load_data, rotated_log, LOG_FILE
from core.transport_change import mutation_lock, busy as transport_busy

DEFAULT_SCHEDULE = {
    "enabled": False,
    "mode": "interval",
    "interval_minutes": 60,
    "daily_time": "03:00",
}
_HISTORY_LIMIT = 20


def normalize_schedule(value: dict) -> dict:
    schedule = {**DEFAULT_SCHEDULE, **(value or {})}
    schedule["enabled"] = bool(schedule.get("enabled"))
    if schedule.get("mode") not in ("interval", "daily"):
        raise ValueError("حالت زمان‌بندی نامعتبر است")
    try:
        interval = int(schedule.get("interval_minutes", 60))
    except (TypeError, ValueError):
        raise ValueError("بازه باید عددی بین 5 تا 10080 دقیقه باشد")
    if not 5 <= interval <= 10080:
        raise ValueError("بازه باید بین 5 تا 10080 دقیقه باشد")
    schedule["interval_minutes"] = interval
    daily_time = str(schedule.get("daily_time", "03:00"))
    try:
        datetime.datetime.strptime(daily_time, "%H:%M")
    except ValueError:
        raise ValueError("ساعت روزانه باید با قالب HH:MM وارد شود")
    if len(daily_time) != 5:
        raise ValueError("ساعت روزانه باید با قالب HH:MM وارد شود")
    schedule["daily_time"] = daily_time
    return {key: schedule[key] for key in DEFAULT_SCHEDULE}


def next_run_epoch(schedule: dict, now: Optional[float] = None) -> float:
    now = time.time() if now is None else now
    schedule = normalize_schedule(schedule)
    if schedule["mode"] == "interval":
        return now + schedule["interval_minutes"] * 60
    hour, minute = map(int, schedule["daily_time"].split(":"))
    current = datetime.datetime.fromtimestamp(now)
    target = current.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target.timestamp() <= now:
        target += datetime.timedelta(days=1)
    return target.timestamp()


def effective_schedule(data: dict, pool_name: str) -> dict:
    global_schedule = normalize_schedule(data.get("dns_scheduler", {}))
    pool_rotation = data.get("pools", {}).get(pool_name, {}).get("rotation", {})
    if pool_rotation.get("inherit_global", True):
        return global_schedule
    return normalize_schedule(pool_rotation)


def pool_rotation_status(data: dict, pool_name: str) -> dict:
    pool = data.get("pools", {}).get(pool_name, {})
    stored = pool.get("rotation", {})
    schedule = effective_schedule(data, pool_name)
    return {
        **schedule,
        "inherit_global": stored.get("inherit_global", True),
        "active_ip": stored.get("active_ip", ""),
        "last_rotation_at": stored.get("last_rotation_at", ""),
        "next_rotation_at": stored.get("next_rotation_at", ""),
        "next_run_epoch": stored.get("next_run_epoch"),
        "last_result": stored.get("last_result", ""),
        "last_error": stored.get("last_error", ""),
        "history": stored.get("history", [])[-_HISTORY_LIMIT:],
    }


def save_global_schedule(settings: dict) -> dict:
    schedule = normalize_schedule(settings)
    now = time.time()
    next_epoch = next_run_epoch(schedule, now) if schedule["enabled"] else None

    def update(data: dict):
        data["dns_scheduler"] = {**schedule, "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "next_run_epoch": next_epoch}

    atomic_update(update)
    return schedule


def save_pool_schedule(pool_name: str, settings: dict) -> dict:
    inherit_global = bool(settings.get("inherit_global", False))
    schedule = None if inherit_global else normalize_schedule(settings)
    now = time.time()

    def update(data: dict):
        pool = data.get("pools", {}).get(pool_name)
        if pool is None:
            raise KeyError("استخر یافت نشد")
        rotation = pool.setdefault("rotation", {})
        rotation["inherit_global"] = inherit_global
        if inherit_global:
            for key in DEFAULT_SCHEDULE:
                rotation.pop(key, None)
            effective = normalize_schedule(data.get("dns_scheduler", {}))
        else:
            rotation.update(schedule)
            effective = schedule
        rotation["next_run_epoch"] = next_run_epoch(effective, now) if effective["enabled"] else None
        rotation["next_rotation_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(rotation["next_run_epoch"])) if rotation["next_run_epoch"] else ""
        rotation["last_result"] = ""
        rotation["last_error"] = ""

    atomic_update(update)
    data = load_data()
    return pool_rotation_status(data, pool_name)


def scheduled_dns_ips(data: dict, pool_name: str, candidates: List[str]) -> Tuple[List[str], bool]:
    """Keep a scheduled pool pinned to its current healthy DNS target."""
    schedule = effective_schedule(data, pool_name)
    if not schedule["enabled"] or not candidates:
        return candidates, False
    active_ip = data.get("pools", {}).get(pool_name, {}).get("rotation", {}).get("active_ip")
    if active_ip in candidates:
        return [active_ip], False
    return [sorted(set(candidates))[0]], True


def _rotation_candidates(data: dict, pool_name: str) -> List[str]:
    pool = data.get("pools", {}).get(pool_name, {})
    report = data.get("watchdog_status", {}).get("pool_reports", {}).get(pool_name, {})
    node_states = report.get("nodes", {})
    allowed = {"HEALTHY"} if pool.get("dns_policy", "strict") == "strict" else {"HEALTHY", "CANARY"}
    return sorted({ip for ip, result in node_states.items() if result.get("status") in allowed and ip in {n.get("ip") for n in pool.get("nodes", [])}})


def _write_rotation_result(pool_name: str, event: dict, *, active_ip: Optional[str] = None,
                           last_rotation_at: Optional[str] = None, next_epoch: Optional[float] = None) -> None:
    def update(data: dict):
        pool = data.get("pools", {}).get(pool_name)
        if pool is None:
            return
        rotation = pool.setdefault("rotation", {"inherit_global": True})
        rotation["last_attempt_at"] = event["at"]
        rotation["last_result"] = event["result"]
        rotation["last_error"] = event.get("error", "")
        if active_ip is not None:
            rotation["active_ip"] = active_ip
        if last_rotation_at:
            rotation["last_rotation_at"] = last_rotation_at
        if next_epoch is not None:
            rotation["next_run_epoch"] = next_epoch
            rotation["next_rotation_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_epoch))
        history = rotation.setdefault("history", [])
        history.append(event)
        del history[:-_HISTORY_LIMIT]

    atomic_update(update)


def rotate_pool(pool_name: str, trigger: str = "scheduled", now: Optional[float] = None) -> dict:
    now = time.time() if now is None else now
    now_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    event = {"at": now_text, "trigger": trigger, "result": "failed", "from_ip": "", "to_ip": ""}
    next_epoch = None
    try:
        with mutation_lock():
            data = load_data()
            pool = data.get("pools", {}).get(pool_name)
            if pool is None:
                return {"success": False, "error": "استخر یافت نشد"}
            schedule = effective_schedule(data, pool_name)
            if trigger == "scheduled" and not schedule["enabled"]:
                return {"success": False, "skipped": True, "error": "زمان‌بندی غیرفعال است"}
            next_epoch = next_run_epoch(schedule, now) if schedule["enabled"] else None
            if len(pool.get("nodes", [])) < 2:
                raise ValueError("برای چرخش حداقل دو نود لازم است")
            if transport_busy(data):
                raise RuntimeError("عملیات تغییر یا نگهداری استخر در جریان است")
            config = effective_config(data, pool_name)
            if not config.get("enabled") or not all(config.get(key) for key in ("api_token", "zone_id", "subdomain")):
                raise ValueError("Cloudflare برای این استخر فعال و کامل نیست")
            key = route_key(config)
            if data.get("dns_overrides", {}).get(key):
                raise RuntimeError("مسیر DNS دستی فعال است؛ ابتدا حالت DNS خودکار را انتخاب کنید")
            owners = [name for name in data.get("pools", {}) if name != pool_name and route_key(effective_config(data, name)) == key]
            if owners:
                raise RuntimeError("این رکورد DNS بین چند استخر مشترک است؛ چرخش مستقل ممکن نیست")
            candidates = _rotation_candidates(data, pool_name)
            if len(candidates) < 2:
                raise RuntimeError("کمتر از دو نود سالم برای چرخش وجود دارد")
            with routing_lock():
                latest = load_data()
                if transport_busy(latest):
                    raise RuntimeError("عملیات تغییر یا نگهداری استخر در جریان است")
                latest_config = effective_config(latest, pool_name)
                if latest.get("dns_overrides", {}).get(route_key(latest_config)):
                    raise RuntimeError("مسیر DNS دستی فعال است؛ ابتدا حالت DNS خودکار را انتخاب کنید")
                pool_latest = latest.get("pools", {}).get(pool_name, {})
                candidates = _rotation_candidates(latest, pool_name)
                if len(candidates) < 2:
                    raise RuntimeError("کمتر از دو نود سالم برای چرخش وجود دارد")
                manager = CloudflareManager = None
                from core.cloudflare import CloudflareManager as _CloudflareManager
                manager = _CloudflareManager(latest_config["api_token"], latest_config["zone_id"])
                manager.scope = latest_config.get("scope", "single")
                before = manager.record_snapshot(latest_config["subdomain"])
                if not before.get("success"):
                    raise RuntimeError("خواندن رکورد DNS ناموفق بود؛ تغییری اعمال نشد")
                current = pool_latest.get("rotation", {}).get("active_ip")
                if current not in candidates:
                    current = next((record.get("content") for record in before.get("records", []) if record.get("content") in candidates), "")
                current_index = candidates.index(current) if current in candidates else -1
                target = candidates[(current_index + 1) % len(candidates)]
                event["from_ip"] = current
                event["to_ip"] = target
                sync = manager.sync_subdomain(latest_config["subdomain"], [target], proxied=False, ttl=60)
                after = manager.record_snapshot(latest_config["subdomain"])
                if sync.get("status") != "SYNCED" or not snapshot_matches(after, [target]):
                    raise RuntimeError(sync.get("warning") or "تغییر DNS تأیید نشد")
                event["result"] = "success"
                event["error"] = ""
                _write_rotation_result(pool_name, event, active_ip=target, last_rotation_at=now_text, next_epoch=next_epoch)
                report = {
                    "source": "rotation", "checked_at": now_text,
                    "subdomain": latest_config["subdomain"], "scope": manager.scope,
                    "dns_snapshot": after, "healthy_ips": [target], "cloudflare_sync": sync,
                    "rotation": {"trigger": trigger, "from_ip": current, "to_ip": target, "result": "success"}
                }
                def update_report(inventory: dict):
                    inventory.setdefault("watchdog_status", {}).setdefault("pool_reports", {})[pool_name] = report
                atomic_update(update_report)
                result = {"success": True, "from_ip": current, "to_ip": target, "next_rotation_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_epoch)) if next_epoch else ""}
                rotated_log(LOG_FILE, f"[dns-rotation] pool={pool_name} trigger={trigger} from={current or '-'} to={target} result=success")
                return result
    except Exception as exc:
        event["result"] = "skipped" if isinstance(exc, (ValueError,)) or "در جریان است" in str(exc) or "دستی فعال" in str(exc) or "سالم" in str(exc) else "failed"
        event["error"] = str(exc)
        if trigger == "scheduled":
            _write_rotation_result(pool_name, event, next_epoch=next_epoch)
        rotated_log(LOG_FILE, f"[dns-rotation] pool={pool_name} trigger={trigger} result={event['result']} error={event['error']}")
        return {"success": False, "skipped": event["result"] == "skipped", "error": str(exc)}


def run_due_rotations(now: Optional[float] = None, callback=None) -> List[dict]:
    now = time.time() if now is None else now
    data = load_data()
    results = []
    for pool_name, pool in data.get("pools", {}).items():
        schedule = effective_schedule(data, pool_name)
        if not schedule["enabled"]:
            continue
        rotation = pool.get("rotation", {})
        due = rotation.get("next_run_epoch")
        if due is None:
            due = data.get("dns_scheduler", {}).get("next_run_epoch") if rotation.get("inherit_global", True) else None
        if due is None:
            due = next_run_epoch(schedule, now)
            _write_rotation_result(pool_name, {"at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)), "trigger": "scheduled", "result": "scheduled", "from_ip": "", "to_ip": ""}, next_epoch=due)
            continue
        if now < float(due):
            continue
        result = rotate_pool(pool_name, "scheduled", now)
        results.append({"pool": pool_name, **result})
        if callback:
            callback(f"DNS rotation for {pool_name}: {result.get('error') or result.get('to_ip')}")
    return results


def record_watchdog_target(pool_name: str, ip: str, at: Optional[str] = None) -> None:
    at = at or time.strftime("%Y-%m-%d %H:%M:%S")
    def update(data: dict):
        pool = data.get("pools", {}).get(pool_name)
        if pool is not None:
            rotation = pool.setdefault("rotation", {"inherit_global": True})
            previous = rotation.get("active_ip", "")
            rotation["active_ip"] = ip
            if previous and previous != ip:
                history = rotation.setdefault("history", [])
                history.append({"at": at, "trigger": "health_failover", "result": "success", "from_ip": previous, "to_ip": ip})
                del history[:-_HISTORY_LIMIT]
    atomic_update(update)


def sync_target_for_watchdog(data: dict, pool_name: str, candidates: List[str]) -> Tuple[List[str], bool]:
    return scheduled_dns_ips(data, pool_name, candidates)


def due_pool_settings(data: dict, pool_name: str) -> dict:
    return pool_rotation_status(data, pool_name)
