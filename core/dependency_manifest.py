"""Dependency and binary authenticity manifests for LD-BP tunnel platform.

Machine-readable dependency manifest specifying pinned versions,
architectures (x86_64, aarch64), cryptographic SHA-256 checksums, licenses,
and pre-installation verification checks.

Audited to ensure ONLY verified checksums are marked valid; placeholder and
dummy hashes (such as empty-file SHA-256) have been removed.
"""
import hashlib
import os
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Tuple, List, Any

@dataclass
class BinaryManifest:
    name: str
    engine_id: str
    pinned_version: str
    license_spdx: str
    architectures: Dict[str, Dict[str, Any]]  # arch -> {"sha256": Optional[str], "source_url": Optional[str], "is_verified": bool}
    executable_name: str
    required_capabilities: List[str]

    def to_dict(self) -> dict:
        return asdict(self)

PLATFORM_DEPENDENCIES: Dict[str, BinaryManifest] = {
    "backpack": BinaryManifest(
        name="BackPack",
        engine_id="backpack",
        pinned_version="v0.4.2",
        license_spdx="MIT",
        executable_name="backpack",
        required_capabilities=[],
        architectures={
            # BackPack binaries are installed on production servers via install.sh or host packages.
            # No release binary hash was officially verified; empty file hash was removed.
            "x86_64": {
                "sha256": None,
                "source_url": None,
                "is_verified": False
            },
            "aarch64": {
                "sha256": None,
                "source_url": None,
                "is_verified": False
            }
        }
    ),
    "xray": BinaryManifest(
        name="Xray-core",
        engine_id="xhttp",
        pinned_version="v26.3.27",
        license_spdx="MPL-2.0",
        executable_name="xray",
        required_capabilities=[],
        architectures={
            "x86_64": {
                "sha256": "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed",
                "source_url": "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip",
                "is_verified": True
            },
            "aarch64": {
                "sha256": None,
                "source_url": "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip",
                "is_verified": False
            }
        }
    ),
    "waterwall": BinaryManifest(
        name="WaterWall",
        engine_id="waterwall",
        pinned_version="v1.46.96",
        license_spdx="GPL-3.0",
        executable_name="Waterwall",
        required_capabilities=[],
        architectures={
            "x86_64": {
                "sha256": "4847a625cf9e176788d38d06511d9fc820940eb0f440460ec3ec32e1a000b7ce",
                "source_url": "https://github.com/radkesvat/WaterWall/releases/download/v1.46.96/Waterwall-linux-gcc-x64.zip",
                "archive_type": "zip", "archive_member": "Waterwall",
                "archive_sha256": "81311d5abc48f6ec4d417b16de1ad478d18d5ed19fc7ef64749b47e0a8099337",
                "is_verified": True
            },
            "aarch64": {
                "sha256": None,
                "source_url": None,
                "is_verified": False
            }
        }
    ),
    "paqet": BinaryManifest(
        name="Paqet",
        engine_id="paqet",
        pinned_version="v1.0.0-alpha.21",
        license_spdx="Apache-2.0",
        executable_name="paqet",
        required_capabilities=["cap_net_raw", "cap_net_admin"],
        architectures={
            "x86_64": {
                "sha256": "edb5d928443b3d47e5c7c86ae394dbac117826e7ddb7c27355fbd2cdd9ee1791",
                "source_url": "https://github.com/hanselime/paqet/releases/download/v1.0.0-alpha.21/paqet-linux-amd64-v1.0.0-alpha.21.tar.gz",
                "archive_type": "tar.gz", "archive_member": "paqet_linux_amd64",
                "archive_sha256": "4f2f69e0493746726598485ef18df43372470a1514f8021594137e522f0f4fc7",
                "is_verified": True
            },
            "aarch64": {
                "sha256": None,
                "source_url": None,
                "is_verified": False
            }
        }
    ),
    "trusttunnel": BinaryManifest(
        name="TrustTunnel",
        engine_id="trusttunnel",
        pinned_version="v1.1.0",
        license_spdx="Apache-2.0",
        executable_name="trusttunnel",
        required_capabilities=["cap_net_admin"],
        architectures={
            "x86_64": {
                "sha256": None,
                "source_url": "https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/trusttunnel-amd64",
                "is_verified": False
            }
        }
    ),
    'slipstream': BinaryManifest(
        name="Slipstream client", engine_id="slipstream",
        pinned_version="v0.1.1", license_spdx="Apache-2.0",
        executable_name="slipstream-client",
        required_capabilities=[],
        architectures={'x86_64': {'sha256': '77e8b639e2429cf5f84e35898eb6f06bd43a81e0637eccdfbb28307b60cbcaa3', 'source_url': 'https://github.com/EndPositive/slipstream/releases/download/v0.1.1/slipstream-client-v0.1.1-linux-x86_64', 'is_verified': True}, 'aarch64': {'sha256': 'bdd74b6d619b82c5da56143b4708ab9aaf9769b8cbd435ec3eaf20c3efd197f5', 'source_url': 'https://github.com/EndPositive/slipstream/releases/download/v0.1.1/slipstream-client-v0.1.1-linux-arm64', 'is_verified': True}},
    ),
    'slipstream-server': BinaryManifest(
        name="Slipstream server", engine_id="slipstream",
        pinned_version="v0.1.1", license_spdx="Apache-2.0",
        executable_name="slipstream-server",
        required_capabilities=["cap_net_bind_service"],
        architectures={'x86_64': {'sha256': '505f1809bc9feb682d2eb5716232c5aed0fcd34344ea1194b684629f1b7cbab8', 'source_url': 'https://github.com/EndPositive/slipstream/releases/download/v0.1.1/slipstream-server-v0.1.1-linux-x86_64', 'is_verified': True}, 'aarch64': {'sha256': '03a7e2b1fba5428f3bfee4b7a0c6ef58b044ea89b221cc8d13d72482a2bb586e', 'source_url': 'https://github.com/EndPositive/slipstream/releases/download/v0.1.1/slipstream-server-v0.1.1-linux-arm64', 'is_verified': True}},
    ),
    "backhaul": BinaryManifest(
        name="Backhaul",
        engine_id="backhaul",
        pinned_version="v0.6.4",
        license_spdx="MIT",
        executable_name="backhaul",
        required_capabilities=[],
        architectures={
            "x86_64": {
                "sha256": None,
                "source_url": "https://github.com/Musix/backhaul/releases/download/v0.6.4/backhaul_linux_amd64.tar.gz",
                "is_verified": False
            }
        }
    ),
    "frp": BinaryManifest(
        name="FRP",
        engine_id="frp",
        pinned_version="v0.61.0",
        license_spdx="Apache-2.0",
        executable_name="frps",
        required_capabilities=[],
        architectures={
            "x86_64": {
                "sha256": None,
                "source_url": "https://github.com/fatedier/frp/releases/download/v0.61.0/frp_0.61.0_linux_amd64.tar.gz",
                "is_verified": False
            }
        }
    ),
    "rathole": BinaryManifest(
        name="Rathole",
        engine_id="rathole",
        pinned_version="v0.5.0",
        license_spdx="Apache-2.0",
        executable_name="rathole",
        required_capabilities=[],
        architectures={
            "x86_64": {
                "sha256": None,
                "source_url": "https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-musl.zip",
                "is_verified": False
            }
        }
    ),
    "gost": BinaryManifest(
        name="GOST",
        engine_id="gost",
        pinned_version="v3.0.0-rc10",
        license_spdx="MIT",
        executable_name="gost",
        required_capabilities=[],
        architectures={
            "x86_64": {
                "sha256": None,
                "source_url": "https://github.com/go-gost/gost/releases/download/v3.0.0-rc10/gost_3.0.0-rc10_linux_amd64.tar.gz",
                "is_verified": False
            }
        }
    ),
    "hysteria2": BinaryManifest(
        name="Hysteria 2",
        engine_id="hysteria2",
        pinned_version="v2.6.0",
        license_spdx="MIT",
        executable_name="hysteria",
        required_capabilities=[],
        architectures={
            "x86_64": {
                "sha256": None,
                "source_url": "https://github.com/apernet/hysteria/releases/download/app%2Fv2.6.0/hysteria-linux-amd64",
                "is_verified": False
            }
        }
    ),
    "spoof": BinaryManifest(
        name="Spoof Suite (nfqws / ciadpi)",
        engine_id="spoof",
        pinned_version="v1.2.0",
        license_spdx="MIT",
        executable_name="nfqws",
        required_capabilities=[],
        architectures={
            "x86_64": {
                "sha256": None,
                "source_url": None,
                "is_verified": False
            },
            "aarch64": {
                "sha256": None,
                "source_url": None,
                "is_verified": False
            }
        }
    ),
}

def get_dependency_manifest(name: str) -> Optional[BinaryManifest]:
    """Retrieve manifest entry by binary or engine name."""
    clean = name.lower().strip()
    if clean in PLATFORM_DEPENDENCIES:
        return PLATFORM_DEPENDENCIES[clean]
    for manifest in PLATFORM_DEPENDENCIES.values():
        if manifest.engine_id.lower() == clean or manifest.executable_name.lower() == clean:
            return manifest
    return None

def verify_file_sha256(file_path: str, expected_sha256: str) -> bool:
    """Verifies that the file at file_path matches the expected SHA-256 hash."""
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return False
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower() == expected_sha256.lower().strip()

def validate_binary_prerequisites(name: str, host_arch: str, local_path: Optional[str] = None) -> Tuple[bool, str]:
    """Validates architecture support, license compliance, and binary checksum if present."""
    manifest = get_dependency_manifest(name)
    if not manifest:
        return False, f"Unknown binary or engine: '{name}'"

    arch = host_arch.lower().strip()
    if arch not in manifest.architectures:
        supported = ", ".join(manifest.architectures.keys())
        return False, f"Architecture '{host_arch}' not supported for {manifest.name} (supports: {supported})"

    arch_info = manifest.architectures[arch]

    if local_path and os.path.exists(local_path):
        expected_hash = arch_info.get("sha256")
        if not arch_info.get("is_verified") or not expected_hash:
            return False, f"Binary '{local_path}' cannot be verified: manifest has no verified SHA-256 for {manifest.name} ({arch})"
        if not verify_file_sha256(local_path, expected_hash):
            return False, f"Binary '{local_path}' SHA-256 does not match pinned manifest for {manifest.name}"

    return True, f"Binary {manifest.name} {manifest.pinned_version} ({manifest.license_spdx}) is compliant"
