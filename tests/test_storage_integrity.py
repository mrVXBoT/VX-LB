"""Storage must preserve inventory and references across invalid input and writes."""
import json

import pytest

from core import storage


@pytest.fixture
def inventory_path(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DATA_DIR", str(tmp_path))
    for name, filename in [("INVENTORY_FILE", "inventory.json"),
                           ("LOCK_FILE", "inventory.lock"),
                           ("LOG_FILE", "watchdog.log")]:
        monkeypatch.setattr(storage, name, str(tmp_path / filename))
    return tmp_path / "inventory.json"


@pytest.mark.parametrize("migrate", [False, True])
def test_initialization_and_migration_write_under_exclusive_lock(inventory_path, monkeypatch, migrate):
    if migrate:
        inventory_path.write_text('{"pools": {}}')
    write_json = storage._atomic_write_json
    writes = []

    def checked_write(path, data):
        writes.append(path)
        assert storage._lock_depth > 0
        assert not storage._lock_shared, "Inventory writes need an exclusive process lock"
        write_json(path, data)

    monkeypatch.setattr(storage, "_atomic_write_json", checked_write)
    result = storage.load_data(migrate=migrate)
    assert writes
    assert json.loads(inventory_path.read_text()) == result


@pytest.mark.parametrize("invalid", [[], "text", 1, True, None])
def test_non_object_inventory_recovers_from_backup(inventory_path, invalid):
    inventory_path.write_text(json.dumps(invalid))
    backup = inventory_path.with_suffix(".json.bak1")
    backup.write_text('{"pools": {"production": {}}}')
    assert "production" in storage.load_data()["pools"]
    storage.atomic_update(lambda data: data.update(marker="updated"))
    assert "production" in json.loads(backup.read_text())["pools"]


def test_invalid_inventory_and_backups_fail_without_overwriting(inventory_path):
    inventory_path.write_text("[]")
    with pytest.raises(storage.InventoryCorrupted):
        storage.atomic_update(lambda data: data.clear())
    assert inventory_path.read_text() == "[]"


@pytest.mark.parametrize("suffix", [".bak1", ".bak2", ".bak3", ".bak"])
def test_missing_main_inventory_recovers_existing_backup(inventory_path, suffix):
    backup = inventory_path.with_name(inventory_path.name + suffix)
    backup.write_text('{"pools": {"production": {}}}')
    assert "production" in storage.load_data()["pools"]
    storage.atomic_update(lambda data: data.update(recovered=True))
    assert "production" in json.loads(inventory_path.read_text())["pools"]


def test_missing_inventory_with_only_invalid_backup_does_not_initialize(inventory_path):
    inventory_path.with_suffix(".json.bak1").write_text("[]")
    with pytest.raises(storage.InventoryCorrupted):
        storage.load_data()
    assert not inventory_path.exists()


def test_migration_write_failure_is_reported(inventory_path, monkeypatch):
    original = '{"pools": {}}'
    inventory_path.write_text(original)

    def failed_write(*args):
        raise OSError("disk full")

    monkeypatch.setattr(storage, "_atomic_write_json", failed_write)
    with pytest.raises(OSError, match="disk full"):
        storage.load_data(migrate=True)
    assert inventory_path.read_text() == original


def test_successful_server_role_normalization_and_profile_deletion(inventory_path):
    storage.add_server(" IRAN ", {"ip": "192.0.2.1"})
    assert storage.get_servers("iran") == [{"ip": "192.0.2.1"}]
    storage.save_cf_profile("unused", {"token": "fixture-only"})
    assert storage.delete_cf_profile("unused") == (True, [])
    assert storage.delete_cf_profile("unused") == (False, [])


@pytest.mark.parametrize("operation", [
    lambda: storage.add_server("typo", {"ip": "192.0.2.1"}),
    lambda: storage.delete_server("typo", "192.0.2.1"),
    lambda: storage.get_servers("typo"),
    lambda: storage.update_server_telemetry("typo", "192.0.2.1", {"status": "DOWN"}),
])
def test_unknown_server_type_never_selects_foreign_servers(inventory_path, operation):
    original = {"kharej_servers": [{"ip": "192.0.2.1", "name": "production"}]}
    inventory_path.write_text(json.dumps(original))
    with pytest.raises(ValueError, match="server type"):
        operation()
    assert json.loads(inventory_path.read_text()) == original


def test_profile_reference_is_checked_inside_atomic_update(inventory_path, monkeypatch):
    storage.save_cf_profile("dns", {"token": "fixture-only"})
    atomic_update = storage.atomic_update

    def concurrent_assignment(update):
        # A pool starts using the profile after the caller's initial snapshot.
        atomic_update(lambda data: data.setdefault("pools", {}).update(
            production={"cloudflare": {"profile_id": "dns"}}))
        return atomic_update(update)

    monkeypatch.setattr(storage, "atomic_update", concurrent_assignment)
    assert storage.delete_cf_profile("dns") == (False, ["production"])
    assert storage.get_cf_profile("dns")["token"] == "fixture-only"
