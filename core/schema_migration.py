"""Schema versioning and migrations for VX-LB persistent storage.

Schema versioning, persistent migrations, stable engine attribution
for legacy records, and rollback protection.
"""
import copy
import logging
from typing import Dict, Tuple, Callable

logger = logging.getLogger("vxlb.schema_migration")

CURRENT_SCHEMA_VERSION = 3

def migrate_v0_to_v1(data: dict) -> dict:
    """Migrate legacy unversioned schema (v0) to v1:
    - Attribute default 'engine': 'backpack' to pools lacking engine.
    - Attribute default 'dns_policy': 'strict'.
    - Set 'schema_version': 1.
    """
    migrated = copy.deepcopy(data)
    migrated["schema_version"] = 1
    pools = migrated.get("pools", {})
    for pool_name, pool in pools.items():
        if not isinstance(pool, dict):
            continue
        if "engine" not in pool:
            transport = pool.get("transport", "")
            if transport in ("gre",):
                pool["engine"] = "gre_ipv4"
            elif transport in ("xhttp",):
                pool["engine"] = "xhttp"
            elif transport in ("gre_xhttp",):
                pool["engine"] = "gre_xhttp"
            elif transport in ("waterwall",):
                pool["engine"] = "waterwall"
            elif transport in ("paqet",):
                pool["engine"] = "paqet"
            else:
                pool["engine"] = "backpack"
        if "dns_policy" not in pool:
            pool["dns_policy"] = "strict"
    return migrated

def migrate_v1_to_v2(data: dict) -> dict:
    """Migrate v1 schema to v2:
    - Add top-level 'custom_links' for independent multi-server links.
    - Add top-level 'resource_reservations' for atomic port/IP/VNI locking.
    - Ensure persistent job tracking dictionary exists.
    - Set 'schema_version': 2.
    """
    migrated = copy.deepcopy(data)
    migrated["schema_version"] = 2
    if "custom_links" not in migrated:
        migrated["custom_links"] = {}
    if "resource_reservations" not in migrated:
        migrated["resource_reservations"] = {}
    if "persistent_jobs" not in migrated:
        migrated["persistent_jobs"] = {}
    return migrated

def migrate_v2_to_v3(data: dict) -> dict:
    """Migrate v2 schema to v3:
    - Augment each pool with structured 'composition' metadata
      (transport, encryption, camouflage layers) via infer_composition_from_pool.
    - Initialize 'matrix_links' dictionary for multi-server matrix routing.
    - Preserves 100% of existing legacy fields (engine, transport, camouflage, etc.).
    - Set 'schema_version': 3.
    """
    if not isinstance(data, dict):
        return data

    migrated = copy.deepcopy(data)
    migrated["schema_version"] = 3

    if "matrix_links" not in migrated or not isinstance(migrated["matrix_links"], dict):
        migrated["matrix_links"] = {}

    pools = migrated.get("pools", {})
    if isinstance(pools, dict):
        from core.composition_schema import deconstruct_legacy_pool
        for pool_name, pool in pools.items():
            if isinstance(pool, dict) and "composition" not in pool:
                pool["composition"] = deconstruct_legacy_pool(pool).to_dict()

    return migrated

MIGRATION_PIPELINE: Dict[int, Callable[[dict], dict]] = {
    0: migrate_v0_to_v1,
    1: migrate_v1_to_v2,
    2: migrate_v2_to_v3,
}

def apply_migrations(data: dict) -> Tuple[dict, bool]:
    """Applies sequential schema migrations if stored data is behind CURRENT_SCHEMA_VERSION.
    
    Returns:
        (migrated_data: dict, was_modified: bool)
    """
    if not isinstance(data, dict):
        return data, False

    initial_version = data.get("schema_version", 0)
    current_version = initial_version
    current_data = data

    while current_version < CURRENT_SCHEMA_VERSION:
        migration_fn = MIGRATION_PIPELINE.get(current_version)
        if not migration_fn:
            logger.warning(f"No migration function registered for schema version {current_version}")
            break
        logger.info(f"Applying schema migration from version {current_version} to {current_version + 1}")
        current_data = migration_fn(current_data)
        current_version = current_data.get("schema_version", current_version + 1)

    was_modified = (current_version != initial_version)
    return current_data, was_modified
