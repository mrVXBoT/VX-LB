import json
import os
import fcntl
import tempfile
import threading
from typing import Dict, List, Optional, Callable, Tuple
from core.validation import validate_server_type

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
INVENTORY_FILE = os.path.join(DATA_DIR, "inventory.json")
LOCK_FILE = os.path.join(DATA_DIR, "inventory.lock")
LOG_FILE = os.path.join(DATA_DIR, "watchdog.log")

_in_process_lock = threading.RLock()
_lock_depth = 0
_lock_fd = None
_lock_shared = False


class InventoryCorrupted(RuntimeError):
    """Raised when inventory.json AND all backups are unreadable.

    Deliberately loud: silently returning an empty inventory lets the next
    write persist the amnesia and orphan the entire fleet. The operator must
    restore from a backup instead.
    """

def _ensure_dir():
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    # Repair permissions of files made by earlier releases as well.
    paths = [INVENTORY_FILE, INVENTORY_FILE + ".bak", LOCK_FILE, LOG_FILE]
    paths += [f"{INVENTORY_FILE}.bak{g}" for g in range(1, _BACKUP_GENERATIONS + 1)]
    for path in paths:
        try:
            os.chmod(path, 0o600)
        except FileNotFoundError:
            pass

class _FileLock:
    """Inter-process and inter-thread re-entrant file lock using fcntl and RLock.

    shared=True takes LOCK_SH (concurrent readers); the default LOCK_EX is for
    writers. Nested acquisition keeps the outermost mode (an update that reads
    stays exclusive).
    """
    def __init__(self, lock_path: str, shared: bool = False):
        self.lock_path = lock_path
        self.shared = shared

    def __enter__(self):
        global _lock_depth, _lock_fd, _lock_shared
        _in_process_lock.acquire()
        try:
            _ensure_dir()
            if _lock_depth == 0:
                fd = os.open(self.lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
                _lock_fd = os.fdopen(fd, "w")
                _lock_shared = self.shared
                fcntl.flock(_lock_fd, fcntl.LOCK_SH if self.shared else fcntl.LOCK_EX)
            _lock_depth += 1
            return self
        except BaseException:
            if _lock_depth == 0 and _lock_fd is not None:
                _lock_fd.close()
                _lock_fd = None
            _in_process_lock.release()
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        global _lock_depth, _lock_fd, _lock_shared
        try:
            _lock_depth -= 1
            if _lock_depth == 0:
                if _lock_fd:
                    try:
                        fcntl.flock(_lock_fd, fcntl.LOCK_UN)
                        _lock_fd.close()
                    except Exception:
                        pass
                    _lock_fd = None
        finally:
            _in_process_lock.release()

def _read_inventory_if_valid(path: str) -> Optional[dict]:
    """Read an inventory object, rejecting invalid JSON and scalar/array roots."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return None
            data = json.loads(content)
            return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


_BACKUP_GENERATIONS = 3  # inventory.json.bak1 .. .bak3


def _rotate_backups(target_path: str):
    """Shift .bak1->.bak2->.bak3, then copy the current (validated) file to .bak1.

    The current file is only archived if it is an inventory object -- a corrupt file
    must never clobber the last good backup.
    """
    import shutil
    dir_name = os.path.dirname(target_path)
    if _read_inventory_if_valid(target_path) is None:
        return
    for gen in range(_BACKUP_GENERATIONS, 1, -1):
        older = f"{target_path}.bak{gen - 1}"
        newer = f"{target_path}.bak{gen}"
        if os.path.exists(older):
            os.replace(older, newer)
    backup_tmp_fd, backup_tmp = tempfile.mkstemp(dir=dir_name, prefix=".tmp_backup_", suffix=".json")
    try:
        with os.fdopen(backup_tmp_fd, "wb") as backup, open(target_path, "rb") as original:
            shutil.copyfileobj(original, backup)
            backup.flush()
            os.fsync(backup.fileno())
        os.replace(backup_tmp, f"{target_path}.bak1")
    finally:
        if os.path.exists(backup_tmp):
            os.remove(backup_tmp)


# --- Rotating log helper (prevents unbounded disk growth) ---
_LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB per file
_LOG_BACKUPS = 3


def rotated_log(path: str, line: str):
    """Append a line to a log file with size-based rotation.

    Keeps path, path.1 .. path.N. Thread/process-safe enough for append-only
    logging: rotation is best-effort under concurrency (a partial duplicate
    line is the worst case, never data loss of the new line).
    """
    _ensure_dir()
    line = line if line.endswith("\n") else line + "\n"
    try:
        if os.path.exists(path) and os.path.getsize(path) >= _LOG_MAX_BYTES:
            for gen in range(_LOG_BACKUPS, 0, -1):
                older = f"{path}.{gen - 1}" if gen > 1 else path
                newer = f"{path}.{gen}"
                if os.path.exists(older):
                    try:
                        os.replace(older, newer)
                    except OSError:
                        pass
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def _fsync_dir(dir_name: str):
    try:
        fd = os.open(dir_name, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        pass


def _atomic_write_json(target_path: str, data: dict):
    _ensure_dir()
    dir_name = os.path.dirname(target_path)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".tmp_inv_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())

        # Keep rotating backups of the last-known-good state before replacing.
        if os.path.exists(target_path):
            _rotate_backups(target_path)

        os.replace(tmp_path, target_path)
        _fsync_dir(dir_name)  # durability: persist the rename itself
    except Exception:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        raise

def _default_inventory() -> dict:
    from core.schema_migration import CURRENT_SCHEMA_VERSION
    return {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "iran_servers": [],
        "kharej_servers": [],
        "pools": {},
        "custom_links": {},
        "resource_reservations": {},
        "persistent_jobs": {},
        "node_telemetry": {},
        "watchdog_status": {}
    }


def load_data(migrate: bool = False) -> dict:
    _ensure_dir()
    # Migrations can write, so they need an exclusive lock from the start.
    # Ordinary reads retain the outer exclusive lock inside atomic_update.
    with _FileLock(LOCK_FILE, shared=not migrate):
        if os.path.exists(INVENTORY_FILE):
            return _load_existing_inventory(migrate)

    # Another process may create the inventory before this exclusive lock.
    # Recheck here so initialization never overwrites its changes.
    with _FileLock(LOCK_FILE):
        if not os.path.exists(INVENTORY_FILE):
            backup_paths = [f"{INVENTORY_FILE}.bak{gen}" for gen in range(1, _BACKUP_GENERATIONS + 1)]
            backup_paths.append(INVENTORY_FILE + ".bak")
            if any(os.path.exists(path) for path in backup_paths):
                return _load_existing_inventory(migrate)
            default_data = _default_inventory()
            _atomic_write_json(INVENTORY_FILE, default_data)
            return default_data
        return _load_existing_inventory(migrate)


def _load_existing_inventory(migrate: bool) -> dict:
    """Read/recover inventory while the caller holds the appropriate file lock."""
    data = _read_inventory_if_valid(INVENTORY_FILE)
    if data is None:
        # Main file unreadable: walk the backup generations, newest first.
        for gen in range(1, _BACKUP_GENERATIONS + 1):
            data = _read_inventory_if_valid(f"{INVENTORY_FILE}.bak{gen}")
            if data is not None:
                break
        if data is None:
            # Legacy single .bak from older releases.
            data = _read_inventory_if_valid(INVENTORY_FILE + ".bak")
        if data is None:
            raise InventoryCorrupted(
                f"inventory.json and all backups under {DATA_DIR} are unreadable. "
                "Refusing to continue with an empty inventory; restore from backup."
            )

    if migrate:
        from core.schema_migration import apply_migrations
        data, was_modified = apply_migrations(data)
        if was_modified:
            _atomic_write_json(INVENTORY_FILE, data)
    return data


def atomic_update(updater_fn: Callable[[dict], None]) -> dict:
    """
    Safely executes a read-modify-write cycle under an exclusive inter-process file lock.
    updater_fn receives the current data dict, modifies it in place.
    The updated dict is then atomically written to disk.
    """
    _ensure_dir()
    with _FileLock(LOCK_FILE):
        data = load_data()
        updater_fn(data)
        _atomic_write_json(INVENTORY_FILE, data)
        return data

def save_data(data: dict):
    _ensure_dir()
    with _FileLock(LOCK_FILE):
        _atomic_write_json(INVENTORY_FILE, data)

def _server_collection_key(server_type: str) -> str:
    """Resolve an explicit server role; typos must never select another fleet."""
    return f"{validate_server_type(server_type)}_servers"

def add_server(server_type: str, server_info: dict) -> bool:
    """
    server_type: 'iran' or 'kharej'
    server_info: {name, ip, port, username, password}
    """
    key = _server_collection_key(server_type)
    def upsert_server(d: dict):
        if key not in d:
            d[key] = []
        for s in d[key]:
            if s["ip"] == server_info["ip"]:
                s.update(server_info)
                return
        d[key].append(server_info)

    atomic_update(upsert_server)
    return True

def delete_server(server_type: str, ip: str) -> bool:
    key = _server_collection_key(server_type)
    deleted = [False]
    def remove_server(d: dict):
        if key in d:
            before = len(d[key])
            d[key] = [s for s in d[key] if s["ip"] != ip]
            if len(d[key]) < before:
                deleted[0] = True

    atomic_update(remove_server)
    return deleted[0]

def get_servers(server_type: str) -> List[dict]:
    key = _server_collection_key(server_type)
    data = load_data()
    return data.get(key, [])


def update_server_telemetry(server_type: str, ip: str, fields: dict) -> bool:
    """Merge health/telemetry fields into a saved server record. Returns True if found."""
    key = _server_collection_key(server_type)
    done = [False]
    def merge_server_telemetry(d: dict):
        for s in d.get(key, []):
            if s.get("ip") == ip:
                s.update(fields)
                done[0] = True
                break
    atomic_update(merge_server_telemetry)
    return done[0]

def get_pools() -> Dict[str, dict]:
    data = load_data()
    return data.get("pools", {})

def save_pool(pool_name: str, pool_data: dict):
    def store_pool(d: dict):
        if "pools" not in d:
            d["pools"] = {}
        d["pools"][pool_name] = pool_data

    atomic_update(store_pool)

def delete_pool(pool_name: str) -> bool:
    deleted = [False]
    def remove_pool(d: dict):
        if pool_name in d.get("pools", {}):
            del d["pools"][pool_name]
            d.get("pool_creations", {}).pop(pool_name, None)
            deleted[0] = True

    atomic_update(remove_pool)
    return deleted[0]


# ============================================================================
# Cloudflare token profiles — multi-credential management
# ============================================================================

def _cf_profiles(d: dict) -> dict:
    return d.setdefault("cloudflare_profiles", {})


def get_cf_profiles() -> dict:
    """Return all Cloudflare token profiles (raw, includes tokens — server-side only)."""
    return load_data().get("cloudflare_profiles", {})


def get_cf_profile(profile_id: str) -> dict:
    return load_data().get("cloudflare_profiles", {}).get(profile_id, {})


def cf_profile_public(profile_id: str, profile: dict) -> dict:
    """Metadata-only view of a profile — safe to send to the frontend."""
    token = profile.get("token", "")
    return {
        "id": profile_id,
        "label": profile.get("label", ""),
        "token_hint": ("••••••••" + token[-4:]) if len(token) >= 4 else "••••",
        "enabled": profile.get("enabled", True),
        "zone_count": len(profile.get("zone_cache", [])),
        "last_validated_at": profile.get("last_validated_at", ""),
        "zone_cache_fetched_at": profile.get("zone_cache_fetched_at", ""),
        "created_at": profile.get("created_at", ""),
        "updated_at": profile.get("updated_at", ""),
    }


def save_cf_profile(profile_id: str, profile: dict):
    def store_profile(d: dict):
        _cf_profiles(d)[profile_id] = profile
    atomic_update(store_profile)


def update_cf_profile(profile_id: str, fields: dict) -> bool:
    done = [False]
    def merge_profile_fields(d: dict):
        p = _cf_profiles(d).get(profile_id)
        if p is not None:
            p.update(fields)
            done[0] = True
    atomic_update(merge_profile_fields)
    return done[0]


def delete_cf_profile(profile_id: str) -> Tuple[bool, List[str]]:
    """Delete a profile. Returns (deleted, pool_names_using_it)."""
    using = []
    deleted = [False]
    def remove_unreferenced_profile(d: dict):
        using.extend(name for name, pool in d.get("pools", {}).items()
                     if (pool.get("cloudflare") or {}).get("profile_id") == profile_id)
        if using:
            return
        if _cf_profiles(d).pop(profile_id, None) is not None:
            deleted[0] = True
    atomic_update(remove_unreferenced_profile)
    return deleted[0], using


def set_cf_profile_zones(profile_id: str, zones: list):
    def cache_profile_zones(d: dict):
        p = _cf_profiles(d).get(profile_id)
        if p is not None:
            import datetime
            p["zone_cache"] = zones
            p["zone_cache_fetched_at"] = datetime.datetime.utcnow().isoformat() + "Z"
    atomic_update(cache_profile_zones)


def cf_profile_pools(profile_id: str) -> List[str]:
    """Pool names whose cloudflare config references this profile."""
    return [name for name, p in load_data().get("pools", {}).items()
            if (p.get("cloudflare") or {}).get("profile_id") == profile_id]


def cf_audit(action: str, profile_id: str = "", zone_id: str = "",
             detail: str = "", ok: bool = True):
    """Append a bounded, sanitized audit entry — never log tokens or record content."""
    import datetime
    def append_audit_entry(d: dict):
        log = d.setdefault("cloudflare_audit", [])
        log.append({
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "action": action,
            "profile_id": profile_id,
            "zone_id": zone_id,
            "detail": str(detail)[:300],
            "ok": bool(ok),
        })
        del log[:-200]  # keep last 200 entries
    atomic_update(append_audit_entry)


def migrate_legacy_cf_profiles() -> int:
    """Convert legacy global cloudflare + pool cloudflare configs into token profiles.

    Returns number of profiles created. Idempotent — safe to call on every load.
    """
    import datetime
    created = [0]
    def migrate_profiles(d: dict):
        profiles = _cf_profiles(d)
        now = datetime.datetime.utcnow().isoformat() + "Z"

        def ensure_profile(token: str, zone_id: str, label: str) -> str:
            for pid, p in profiles.items():
                if p.get("token") == token:
                    return pid
            pid = "cf-legacy-" + __import__("hashlib").sha256(token.encode()).hexdigest()[:12]
            profiles[pid] = {
                "label": label, "token": token, "enabled": True,
                "created_at": now, "updated_at": now,
                "last_validated_at": "", "zone_cache": [], "zone_cache_fetched_at": "",
            }
            created[0] += 1
            return pid

        # Global legacy cloudflare config
        g = d.get("cloudflare") or {}
        if g.get("api_token") and g.get("zone_id"):
            pid = ensure_profile(g["api_token"], g["zone_id"], "Legacy Cloudflare (global)")
            g.setdefault("profile_id", pid)

        # Per-pool legacy cloudflare configs
        for pool in d.get("pools", {}).values():
            cf = pool.get("cloudflare") or {}
            if cf.get("api_token") and cf.get("zone_id") and not cf.get("profile_id"):
                pid = ensure_profile(cf["api_token"], cf["zone_id"], "Legacy Cloudflare (pool)")
                cf["profile_id"] = pid
    atomic_update(migrate_profiles)
    return created[0]
