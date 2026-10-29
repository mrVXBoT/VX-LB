#!/usr/bin/env python3
"""
VX LB — Offline Binary Bundler for Air-Gapped / Wartime Deployment.
Downloads verified tunnel binaries and caches them in bin/{arch}/
so nodes in restricted environments (intranet / no GitHub) can be
provisioned directly over SSH without external internet access.
"""
import hashlib
import os
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(BASE_DIR, "bin")

TARGETS = [
    {
        "name": "backpack",
        "arch": "x86_64",
        "url": "https://github.com/AminMGMT/BackPack/releases/download/v1.8.5/backpack_linux_amd64.tar.gz",
        "is_tar": True,
        "tar_member": "backpack",
        "dest": "backpack",
    },
    {
        "name": "backpack",
        "arch": "aarch64",
        "url": "https://github.com/AminMGMT/BackPack/releases/download/v1.8.5/backpack_linux_arm64.tar.gz",
        "is_tar": True,
        "tar_member": "backpack",
        "dest": "backpack",
    },
    {
        "name": "waterwall",
        "arch": "x86_64",
        "url": "https://github.com/radkesvat/WaterWall/releases/download/v1.46.96/Waterwall-linux-gcc-x64.zip",
        "is_zip": True,
        "zip_member": "Waterwall",
        "archive_sha256": "81311d5abc48f6ec4d417b16de1ad478d18d5ed19fc7ef64749b47e0a8099337",
        "sha256": "4847a625cf9e176788d38d06511d9fc820940eb0f440460ec3ec32e1a000b7ce",
        "dest": "Waterwall",
    },
    {
        "name": "slipstream-client",
        "arch": "x86_64",
        "url": "https://github.com/EndPositive/slipstream/releases/download/v0.1.1/slipstream-client-v0.1.1-linux-x86_64",
        "sha256": "77e8b639e2429cf5f84e35898eb6f06bd43a81e0637eccdfbb28307b60cbcaa3",
        "dest": "slipstream-client",
    },
    {
        "name": "slipstream-server",
        "arch": "x86_64",
        "url": "https://github.com/EndPositive/slipstream/releases/download/v0.1.1/slipstream-server-v0.1.1-linux-x86_64",
        "sha256": "505f1809bc9feb682d2eb5716232c5aed0fcd34344ea1194b684629f1b7cbab8",
        "dest": "slipstream-server",
    },
    {
        "name": "rathole",
        "arch": "x86_64",
        "url": "https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.zip",
        "is_zip": True,
        "zip_member": "rathole",
        "sha256": "d2202f2aa3a432135bddbe1c6104600c6577cd4507a70e77c08741c7ad879926",
        "dest": "rathole",
    },
    {
        "name": "rathole",
        "arch": "aarch64",
        "url": "https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-aarch64-unknown-linux-musl.zip",
        "is_zip": True,
        "zip_member": "rathole",
        "sha256": "c95474d2ecdc031b3bb20c495595a0d6c6440c1ff7748f594d7ecd5315d36e8f",
        "dest": "rathole",
    },
    {
        "name": "paqet",
        "arch": "x86_64",
        "url": "https://github.com/hanselime/paqet/releases/download/v1.0.0-alpha.21/paqet-linux-amd64-v1.0.0-alpha.21.tar.gz",
        "is_tar": True,
        "tar_member": "paqet_linux_amd64",
        "archive_sha256": "4f2f69e0493746726598485ef18df43372470a1514f8021594137e522f0f4fc7",
        "sha256": "edb5d928443b3d47e5c7c86ae394dbac117826e7ddb7c27355fbd2cdd9ee1791",
        "dest": "paqet",
    },
    {
        "name": "paqet",
        "arch": "aarch64",
        "url": "https://github.com/hanselime/paqet/releases/download/v1.0.0-alpha.21/paqet-linux-arm64-v1.0.0-alpha.21.tar.gz",
        "is_tar": True,
        "tar_member": "paqet_linux_arm64",
        "sha256": "f6db279a57a772a250efffe4bb0a79b112495331568ccc0f6e5f4398bbe962e3",
        "dest": "paqet",
    },
    {
        "name": "candy-spoof-client",
        "arch": "x86_64",
        "url": "https://github.com/AmiRCandy/Candy-Spoof/releases/download/nightly-20260402-143253/candy-spoof-client-linux-x86_64",
        "sha256": "2aff9805f3825cdeb0e6d6860640256229a179c461d0b49b45edc38a11c1cbaf",
        "dest": "candy-spoof-client",
    },
    {
        "name": "candy-spoof-server",
        "arch": "x86_64",
        "url": "https://github.com/AmiRCandy/Candy-Spoof/releases/download/nightly-20260402-143253/candy-spoof-server-linux-x86_64",
        "sha256": "269a04b768905491c9bae0b8f20ff5412fa99a0897bafe1a874d312448a996ef",
        "dest": "candy-spoof-server",
    },
    {
        "name": "parsaksh-spoof",
        "arch": "x86_64",
        "url": "https://github.com/ParsaKSH/spoof-tunnel/releases/download/v3.0.2/spoof-linux-amd64",
        "sha256": "a8dfe9e838ad5655b467765eae6f374e5f63af31bf2dded9aab295815fbcabf8",
        "dest": "spoof",
    },
    {
        "name": "parsaksh-spoof",
        "arch": "aarch64",
        "url": "https://github.com/ParsaKSH/spoof-tunnel/releases/download/v3.0.2/spoof-linux-arm64",
        "sha256": "caf08b3960d4eea72910fb0613a8893560a41f5b2f2e18f9a6c595c9ad7ea16c",
        "dest": "spoof",
    },
]

def sha256_file(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(65536), b""):
        digest.update(chunk)
    return digest.hexdigest()


def fetch_and_bundle():
    print("=" * 60)
    print("  VX LB — Offline Binary Depot Bundler")
    print("=" * 60)
    
    os.makedirs(os.path.join(BIN_DIR, "x86_64"), exist_ok=True)
    os.makedirs(os.path.join(BIN_DIR, "aarch64"), exist_ok=True)

    for item in TARGETS:
        arch = item["arch"]
        dest_path = os.path.join(BIN_DIR, arch, item["dest"])
        if os.path.exists(dest_path) and os.path.getsize(dest_path) > 1000:
            expected = item.get("sha256")
            with open(dest_path, "rb") as cached:
                valid = not expected or sha256_file(cached) == expected
            if valid:
                print(f"[*] {item['name']} ({arch}) already cached at {dest_path}")
                continue

        url = item["url"]
        print(f"[+] Downloading {item['name']} ({arch}) from {url} ...")
        tmp_download = dest_path + ".tmp"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VX-LB-Bundler/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp, open(tmp_download, "wb") as out:
                shutil.copyfileobj(resp, out)

            archive_digest = item.get("archive_sha256")
            if archive_digest:
                with open(tmp_download, "rb") as archive:
                    actual = sha256_file(archive)
                if actual != archive_digest:
                    raise ValueError(f"Archive checksum mismatch for {item['name']}")

            if item.get("is_tar"):
                with tarfile.open(tmp_download, "r:*") as tar:
                    member = tar.getmember(item["tar_member"])
                    f = tar.extractfile(member)
                    with open(dest_path, "wb") as out:
                        shutil.copyfileobj(f, out)
                os.remove(tmp_download)
            elif item.get("is_zip"):
                with zipfile.ZipFile(tmp_download) as archive:
                    member = next(name for name in archive.namelist()
                                  if os.path.basename(name) == item["zip_member"])
                    with archive.open(member) as source, open(dest_path, "wb") as out:
                        shutil.copyfileobj(source, out)
                os.remove(tmp_download)
            else:
                expected_sha = item.get("sha256")
                if expected_sha:
                    h = hashlib.sha256()
                    with open(tmp_download, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            h.update(chunk)
                    actual_sha = h.hexdigest()
                    if actual_sha != expected_sha:
                        print(f"[-] Checksum mismatch for {item['name']}! Expected {expected_sha}, got {actual_sha}")
                        os.remove(tmp_download)
                        continue
                os.rename(tmp_download, dest_path)

            expected = item.get("sha256")
            if expected:
                with open(dest_path, "rb") as binary:
                    actual = sha256_file(binary)
                if actual != expected:
                    os.remove(dest_path)
                    raise ValueError(f"Binary checksum mismatch for {item['name']}")

            # Make executable
            st = os.stat(dest_path)
            os.chmod(dest_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            print(f"[✓] Successfully bundled {item['dest']} -> {dest_path}")
        except Exception as e:
            print(f"[!] Failed to bundle {item['name']} ({arch}): {e}")
            if os.path.exists(tmp_download):
                os.remove(tmp_download)

    print("\n[✓] Binary bundling complete. All assets stored in bin/")

if __name__ == "__main__":
    fetch_and_bundle()
