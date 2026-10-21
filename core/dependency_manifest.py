"""Dependency and binary authenticity manifests for VX-LB tunnel platform.

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
            # Bundled binary checksums are measured at bundle time and stay
            # pinned in the depot for offline installs.
            "x86_64": {
                "sha256": "ed03357f23b4ab63fb54f5e06f69778793c323ac099a4410660ad53f80e98107",
                "source_url": None,
                "is_verified": True
            },
            "aarch64": {
                "sha256": "62f2ad8b2c60feb573334ff64022cbda2e79792e1c735a3a59317230d0a29e1f",
                "source_url": None,
                "is_verified": True
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
                "sha256": "c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04",
                "source_url": "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip",
                "archive_type": "zip", "archive_member": "xray",
                "is_verified": True
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
                "sha256": "aa3bb31f4feb19253b3e0f4091b7bf5d09b2975a0b2efc109f184abe5154fb05",
                "source_url": "https://github.com/radkesvat/WaterWall/releases/download/v1.46.96/Waterwall-linux-gcc-arm64.zip",
                "archive_type": "zip", "archive_member": "Waterwall",
                "is_verified": True
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
                "sha256": "f6db279a57a772a250efffe4bb0a79b112495331568ccc0f6e5f4398bbe962e3",
                "source_url": "https://github.com/hanselime/paqet/releases/download/v1.0.0-alpha.21/paqet-linux-arm64-v1.0.0-alpha.21.tar.gz",
                "archive_type": "tar.gz", "archive_member": "paqet_linux_arm64",
                "is_verified": True
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
                "sha256": "9bb15f4e30e2ff196cf0aa387462c42387d9405ddfeb5caad133838560fa33cd",
                "source_url": "https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/trusttunnel-v1.1.0-linux-x86_64.tar.gz",
                "archive_type": "tar.gz", "archive_member": "trusttunnel_endpoint",
                "is_verified": True
            },
            "aarch64": {
                "sha256": "0aa249672b1aa3a6fa7eadfb72159b7d965f6f006681f97a2528eed9161541c3",
                "source_url": "https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/trusttunnel-v1.1.0-linux-aarch64.tar.gz",
                "archive_type": "tar.gz", "archive_member": "trusttunnel_endpoint",
                "is_verified": True
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
        pinned_version="v0.7.2",
        license_spdx="MIT",
        executable_name="backhaul",
        required_capabilities=[],
        architectures={
            "x86_64": {
                "sha256": "7f1b1439d7fe1d15ae0b376e15614fe13d8a12f6e07a90263e310ea2a9d601fb",
                "source_url": "https://github.com/Musixal/Backhaul/releases/download/v0.7.2/backhaul_linux_amd64.tar.gz",
                "archive_type": "tar.gz", "archive_member": "backhaul",
                "is_verified": True
            },
            "aarch64": {
                "sha256": "f8533e29fac489b179e191c81f6bdcb0247302dc01ad1c06a8f5664f32f5ba6b",
                "source_url": "https://github.com/Musixal/Backhaul/releases/download/v0.7.2/backhaul_linux_arm64.tar.gz",
                "archive_type": "tar.gz", "archive_member": "backhaul",
                "is_verified": True
            }
        }
    ),
    "frpc": BinaryManifest(
        name="FRP client",
        engine_id="frp",
        pinned_version="v0.61.0",
        license_spdx="Apache-2.0",
        executable_name="frpc",
        required_capabilities=[],
        architectures={
            "x86_64": {
                "sha256": "0007a720afc328a15e5b30c093c81cc63d6b6a4aa418f57d3677855393c30103",
                "source_url": "https://github.com/fatedier/frp/releases/download/v0.61.0/frp_0.61.0_linux_amd64.tar.gz",
                "archive_type": "tar.gz", "archive_member": "frpc",
                "is_verified": True
            },
            "aarch64": {
                "sha256": "5a8b0d748263d9879439b5c8c8010095572cfb9a280300edbf130280a32415a4",
                "source_url": "https://github.com/fatedier/frp/releases/download/v0.61.0/frp_0.61.0_linux_arm64.tar.gz",
                "archive_type": "tar.gz", "archive_member": "frpc",
                "is_verified": True
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
                "sha256": "3231238ffc16588e8bbb035336885f5e88b2fa5972202d1f29af74bdd3cbba5f",
                "source_url": "https://github.com/fatedier/frp/releases/download/v0.61.0/frp_0.61.0_linux_amd64.tar.gz",
                "archive_type": "tar.gz", "archive_member": "frps",
                "is_verified": True
            },
            "aarch64": {
                "sha256": "f8419e5460762de873301aa9fbe15f90364bb0ca89e841ad4ff291dc371b53d1",
                "source_url": "https://github.com/fatedier/frp/releases/download/v0.61.0/frp_0.61.0_linux_arm64.tar.gz",
                "archive_type": "tar.gz", "archive_member": "frps",
                "is_verified": True
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
                "sha256": "d2202f2aa3a432135bddbe1c6104600c6577cd4507a70e77c08741c7ad879926",
                "source_url": "https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.zip",
                "archive_type": "zip", "archive_member": "rathole",
                "is_verified": True
            },
            "aarch64": {
                "sha256": "c95474d2ecdc031b3bb20c495595a0d6c6440c1ff7748f594d7ecd5315d36e8f",
                "source_url": "https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-aarch64-unknown-linux-musl.zip",
                "archive_type": "zip", "archive_member": "rathole",
                "is_verified": True
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
                "sha256": "a5201a49dcee2331795c41a0458b55f91393883eb9529661a65c3264e8a28237",
                "source_url": "https://github.com/go-gost/gost/releases/download/v3.0.0-rc10/gost_3.0.0-rc10_linux_amd64.tar.gz",
                "archive_type": "tar.gz", "archive_member": "gost",
                "is_verified": True
            },
            "aarch64": {
                "sha256": "7570796ee7d3233eb425d2fe642b6894d6e795d7a8cf1de4522ddd8107f2dd7b",
                "source_url": "https://github.com/go-gost/gost/releases/download/v3.0.0-rc10/gost_3.0.0-rc10_linux_arm64.tar.gz",
                "archive_type": "tar.gz", "archive_member": "gost",
                "is_verified": True
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
                "sha256": "6dc6cb49fcaeeeaf8127aa1fe0124f9f65e20fac2ae4e8227b086d2be30c6944",
                "source_url": "https://github.com/apernet/hysteria/releases/download/app%2Fv2.6.0/hysteria-linux-amd64",
                "is_verified": True
            },
            "aarch64": {
                "sha256": "4eaa4a290b0a04f831c8df5e4a571b9a5b779a83265f748a452f2ff90288d218",
                "source_url": "https://github.com/HyNetworks/hysteria/releases/download/app/v2.6.0/hysteria-linux-arm64",
                "is_verified": True
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
