import urllib.request
import urllib.error
import urllib.parse
import json
import re
from typing import List, Dict, Tuple, Optional

CF_API = "https://api.cloudflare.com/client/v4"

_DNS_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(\*|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.?$"
)


def _error_message(result: dict, fallback: str = "خطای Cloudflare") -> str:
    for e in (result or {}).get("errors", []):
        if isinstance(e, dict) and e.get("message"):
            return e["message"]
    for m in (result or {}).get("messages", []):
        if isinstance(m, dict) and m.get("message"):
            return m["message"]
    return fallback


def validate_record_payload(record: dict) -> Tuple[bool, str]:
    """Server-side validation of a Cloudflare DNS record payload."""
    if not isinstance(record, dict):
        return False, "رکورد باید یک شیء باشد"
    rtype = str(record.get("type", "")).upper().strip()
    allowed = {"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS", "PTR"}
    if rtype not in allowed:
        return False, f"نوع رکورد پشتیبانی نمی‌شود: {rtype or '—'}"
    name = str(record.get("name", "")).lower().strip().rstrip(".")
    if not name or len(name) > 255:
        return False, "نام رکورد معتبر نیست"
    if not _HOSTNAME_RE.match(name):
        return False, "نام رکورد باید hostname معتبر باشد"
    ttl = record.get("ttl", 1)
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        return False, "TTL باید عدد باشد"
    if not (ttl == 1 or 60 <= ttl <= 86400):
        return False, "TTL باید 1 (Auto) یا بین 60 تا 86400 باشد"
    record["ttl"] = ttl
    record["name"] = name
    record["type"] = rtype

    content = str(record.get("content", "")).strip()
    if rtype == "A":
        import ipaddress
        try:
            ipaddress.IPv4Address(content)
        except ValueError:
            return False, "محتوای رکورد A باید IPv4 معتبر باشد"
        record["content"] = content
    elif rtype == "AAAA":
        import ipaddress
        try:
            ipaddress.IPv6Address(content)
        except ValueError:
            return False, "محتوای رکورد AAAA باید IPv6 معتبر باشد"
        record["content"] = content
    elif rtype in ("CNAME", "PTR", "NS", "MX"):
        if not _HOSTNAME_RE.match(content.lower().rstrip(".")):
            return False, f"محتوای رکورد {rtype} باید hostname معتبر باشد"
        record["content"] = content.rstrip(".")
    elif rtype == "TXT":
        if not content:
            return False, "محتوای رکورد TXT نمی‌تواند خالی باشد"
        record["content"] = content
    if rtype == "MX":
        try:
            record["priority"] = int(record.get("priority", 10))
        except (TypeError, ValueError):
            return False, "اولویت MX باید عدد باشد"
        if not (0 <= record["priority"] <= 65535):
            return False, "اولویت MX باید بین 0 تا 65535 باشد"
    if rtype == "SRV":
        data = record.get("data")
        if not isinstance(data, dict):
            return False, "رکورد SRV به data شامل service/proto/priority/weight/port/target نیاز دارد"
        try:
            data["priority"] = int(data.get("priority", 0))
            data["weight"] = int(data.get("weight", 0))
            data["port"] = int(data.get("port", 0))
        except (TypeError, ValueError):
            return False, "فیلدهای عددی SRV باید عدد باشند"
        for f in ("priority", "weight", "port"):
            if not (0 <= data[f] <= 65535):
                return False, f"SRV {f} باید بین 0 تا 65535 باشد"
        if not _HOSTNAME_RE.match(str(data.get("target", "")).lower().rstrip(".")):
            return False, "target رکورد SRV باید hostname معتبر باشد"
        record["data"] = data
    if rtype == "CAA":
        data = record.get("data")
        if not isinstance(data, dict):
            return False, "رکورد CAA به data شامل flags/tag/value نیاز دارد"
        try:
            data["flags"] = int(data.get("flags", 0))
        except (TypeError, ValueError):
            return False, "flags رکورد CAA باید عدد باشد"
        if not (0 <= data["flags"] <= 255):
            return False, "flags رکورد CAA باید بین 0 تا 255 باشد"
        if not data.get("tag") or not data.get("value"):
            return False, "tag و value رکورد CAA الزامی است"
        record["data"] = data
    return True, ""


class CloudflareManager:
    def __init__(self, api_token: str, zone_id: Optional[str] = None):
        self.scope = "single"
        self.api_token = api_token.strip()
        self.zone_id = (zone_id or "").strip()
        self.base_url = (
            f"{CF_API}/zones/{self.zone_id}/dns_records" if self.zone_id else f"{CF_API}/zones"
        )

    # ------------------------------------------------------------------ http
    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

    def _request(self, method: str, endpoint: str, data: Optional[dict] = None,
                 base: Optional[str] = None) -> dict:
        url = endpoint if endpoint.startswith("http") else f"{base or self.base_url}{endpoint}"
        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            try:
                return json.loads(err_body)
            except Exception:
                return {"success": False, "errors": [{"message": str(e)}]}
        except Exception as e:
            return {"success": False, "errors": [{"message": str(e)}]}

    # --------------------------------------------------------------- account
    def verify_token(self) -> Tuple[bool, str]:
        res = self._request("GET", "/user/tokens/verify", base=CF_API)
        if res.get("success"):
            return True, ""
        return False, _error_message(res, "توکن نامعتبر است")

    # ---------------------------------------------------------------- zones
    def _zone_url(self, zone_id: str) -> str:
        return f"{CF_API}/zones/{zone_id.strip()}/dns_records"

    def list_zones(self, name: str = "", status: str = "", per_page: int = 50) -> Dict:
        """Fetch ALL zones accessible to this token (paginated)."""
        params: Dict[str, str] = {"per_page": str(min(per_page, 50)), "page": "1"}
        if name:
            params["name"] = name.lower().strip()
        if status:
            params["status"] = status
        zones: List[Dict] = []
        page = 1
        while True:
            params["page"] = str(page)
            res = self._request("GET", "/zones?" + urllib.parse.urlencode(params), base=CF_API)
            if not res.get("success"):
                return {"success": False, "zones": [], "error": _error_message(res, "خواندن Zoneها ناموفق بود")}
            zones.extend(res.get("result", []))
            info = res.get("result_info", {})
            if page >= info.get("total_pages", 1):
                return {"success": True, "zones": zones, "count": info.get("total_count", len(zones))}
            page += 1

    def get_zone(self, zone_id: str) -> Dict:
        res = self._request("GET", f"/{zone_id.strip()}", base=f"{CF_API}/zones")
        if res.get("success") and res.get("result"):
            return {"success": True, "zone": res["result"]}
        return {"success": False, "error": _error_message(res, "Zone یافت نشد")}

    # --------------------------------------------------------------- records
    def list_records_typed(self, zone_id: str, rtype: str = "", name: str = "",
                           per_page: int = 100) -> Dict:
        """List DNS records for a zone — all types, paginated."""
        params: Dict[str, str] = {"per_page": str(min(per_page, 100)), "page": "1"}
        if rtype:
            params["type"] = rtype.upper().strip()
        if name:
            params["name"] = name.lower().strip()
        records: List[Dict] = []
        page = 1
        while True:
            params["page"] = str(page)
            res = self._request("GET", "?" + urllib.parse.urlencode(params),
                                base=self._zone_url(zone_id))
            if not res.get("success"):
                return {"success": False, "records": [],
                        "error": _error_message(res, "خواندن رکوردها ناموفق بود")}
            records.extend(res.get("result", []))
            info = res.get("result_info", {})
            if page >= info.get("total_pages", 1):
                return {"success": True, "records": records,
                        "count": info.get("total_count", len(records))}
            page += 1

    def create_record(self, zone_id: str, record: dict) -> Tuple[bool, str]:
        ok, err = validate_record_payload(record)
        if not ok:
            return False, err
        res = self._request("POST", "", record, base=self._zone_url(zone_id))
        if res.get("success"):
            return True, res["result"]["id"]
        return False, _error_message(res, "ساخت رکورد ناموفق بود")

    def update_record(self, zone_id: str, record_id: str, record: dict) -> Tuple[bool, str]:
        ok, err = validate_record_payload(record)
        if not ok:
            return False, err
        res = self._request("PUT", f"/{record_id}", record, base=self._zone_url(zone_id))
        if res.get("success"):
            return True, record_id
        return False, _error_message(res, "ویرایش رکورد ناموفق بود")

    def patch_record(self, zone_id: str, record_id: str, fields: dict) -> Tuple[bool, str]:
        allowed = {"ttl", "proxied", "comment", "tags"}
        fields = {k: v for k, v in (fields or {}).items() if k in allowed}
        if not fields:
            return False, "فیلد قابل ویرایشی یافت نشد"
        res = self._request("PATCH", f"/{record_id}", fields, base=self._zone_url(zone_id))
        if res.get("success"):
            return True, record_id
        return False, _error_message(res, "ویرایش رکورد ناموفق بود")

    def delete_record_zoned(self, zone_id: str, record_id: str) -> Tuple[bool, str]:
        res = self._request("DELETE", f"/{record_id}", base=self._zone_url(zone_id))
        if res.get("success"):
            return True, "حذف شد"
        return False, _error_message(res, "حذف رکورد ناموفق بود")

    # ============================================================ legacy API
    def subdomain_records(self, domain: str) -> Dict:
        """Read all existing IPv4 subdomain records; never include the apex."""
        domain = domain.lower().strip().removeprefix('*.').rstrip('.')
        if not domain or '.' not in domain or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-.' for c in domain):
            return {'success': False, 'records': [], 'error': 'دامنه معتبر وارد کنید'}
        records = []
        page = 1
        while True:
            response = self._request('GET', '?' + urllib.parse.urlencode({'type': 'A', 'per_page': 100, 'page': page}))
            if not response.get('success'):
                return {'success': False, 'records': [], 'error': 'خواندن کامل رکوردهای Cloudflare ناموفق بود'}
            records.extend(r for r in response.get('result', []) if r.get('type', 'A') == 'A' and r.get('name', '').lower().endswith('.' + domain))
            if page >= response.get('result_info', {}).get('total_pages', 1):
                break
            page += 1
        return {'success': True, 'records': records, 'names': sorted({r['name'].lower() for r in records})}

    def record_snapshot(self, name: str) -> Dict:
        """Read provider records, preserving failure separately from an empty zone."""
        if self.scope == 'all_subdomains':
            result = self.subdomain_records(name)
            if not result.get('success'):
                return {'success': False, 'records': []}
            return {'success': True, 'names': result['names'], 'scope': 'all_subdomains',
                    'records': [{k: r.get(k) for k in ('name', 'content', 'proxied')} for r in result['records']]}
        records = []
        page = 1
        while True:
            response = self._request("GET", "?" + urllib.parse.urlencode(
                {"name": name.lower().strip(), "type": "A", "per_page": 100, "page": page}))
            if not response.get("success"):
                return {"success": False, "records": []}
            records.extend({"content": record.get("content", ""), "proxied": record.get("proxied", False)}
                           for record in response.get("result", []))
            if page >= response.get("result_info", {}).get("total_pages", 1):
                return {"success": True, "records": records}
            page += 1

    def list_records(self, name: str) -> List[Dict]:
        """Returns ALL A records for given subdomain (lowercased), paginated.

        Previously this fetched a single page (default 20), so sync_subdomain
        built its world-view from a truncated list -- creating duplicate A
        records and never deleting stale ones past page 1.
        """
        name = name.lower().strip()
        records: List[Dict] = []
        page = 1
        while True:
            res = self._request("GET", "?" + urllib.parse.urlencode(
                {"name": name, "type": "A", "per_page": 100, "page": page}))
            if not res.get("success"):
                raise RuntimeError("Cloudflare record read failed")
            records.extend(res.get("result", []))
            if page >= res.get("result_info", {}).get("total_pages", 1):
                break
            page += 1
        return records

    def add_a_record(self, name: str, ip: str, proxied: bool = False, ttl: int = 60) -> Tuple[bool, str]:
        """Creates an A record."""
        payload = {
            "type": "A",
            "name": name.lower().strip(),
            "content": ip.strip(),
            "ttl": ttl,
            "proxied": proxied
        }
        res = self._request("POST", "", payload)
        if res.get("success"):
            return True, res["result"]["id"]
        errors = ", ".join([e.get("message", "") for e in res.get("errors", [])])
        return False, errors

    def delete_record(self, record_id: str) -> Tuple[bool, str]:
        """Deletes a DNS record by ID."""
        res = self._request("DELETE", f"/{record_id}")
        if res.get("success"):
            return True, "Deleted"
        errors = ", ".join([e.get("message", "") for e in res.get("errors", [])])
        return False, errors

    def sync_subdomain(self, subdomain: str, healthy_ips: List[str], proxied: bool = False, ttl: int = 60) -> Dict:
        if self.scope != 'all_subdomains':
            return self._sync_single(subdomain, healthy_ips, proxied, ttl)
        discovery = self.subdomain_records(subdomain)
        if not discovery.get('success') or not discovery.get('names'):
            return {'status': 'ABORTED_DISCOVERY', 'warning': discovery.get('error', 'هیچ ساب‌دامینی با رکورد A یافت نشد'), 'added': [], 'deleted': [], 'kept': []}
        reports = {}
        for name in discovery['names']:
            reports[name] = self._sync_single(name, healthy_ips, proxied, ttl)
            # Forwarded client traffic requires DNS-only records, including
            # records already containing the selected address.
            try:
                current = self.list_records(name)
            except RuntimeError:
                reports[name]['status'] = 'PARTIAL'
                continue
            for record in current:
                if record['content'] in healthy_ips and record.get('proxied', False) != proxied:
                    result = self._request('PATCH', '/' + record['id'], {'proxied': proxied, 'ttl': ttl})
                    if not result.get('success'):
                        reports[name]['status'] = 'PARTIAL'
        snapshot = self.record_snapshot(subdomain)
        complete = snapshot.get('success') and all(
            {r['content'] for r in snapshot['records'] if r['name'].lower() == name} == set(healthy_ips)
            and all(r.get('proxied', False) == proxied for r in snapshot['records'] if r['name'].lower() == name)
            for name in set(discovery['names']) | set(snapshot.get('names', [])))
        return {'status': 'SYNCED' if complete else 'PARTIAL', 'scope': 'all_subdomains',
                'subdomain': subdomain, 'names': discovery['names'], 'domains': reports,
                'added': [ip for r in reports.values() for ip in r.get('added', [])],
                'deleted': [ip for r in reports.values() for ip in r.get('deleted', [])],
                'kept': [ip for r in reports.values() for ip in r.get('kept', [])],
                'warning': '' if complete else 'همگام‌سازی همهٔ ساب‌دامین‌ها تأیید نشد'}

    def _sync_single(self, subdomain: str, healthy_ips: List[str], proxied: bool = False, ttl: int = 60) -> Dict:
        """
        Synchronizes the subdomain A records with the healthy IPs list:
        - Ensures healthy IPs have A records.
        - Deletes A records for IPs that are not in healthy_ips, ONLY AFTER ensuring that
          at least one healthy record is confirmed active, and never deleting if it would
          leave the DNS zone empty.
        """
        subdomain = subdomain.lower().strip()
        try:
            existing = self.list_records(subdomain)
        except RuntimeError:
            return {'status': 'ABORTED_READ_FAILURE', 'added': [], 'deleted': [], 'kept': [], 'warning': 'خواندن کامل رکوردها ناموفق بود؛ تغییری اعمال نشد'}
        existing_records = [(rec["content"].strip(), rec["id"]) for rec in existing]
        existing_ips = {ip for ip, _ in existing_records}

        added = []
        deleted = []
        kept = []
        failed_adds = []

        # 1. Add missing healthy IPs
        for ip in healthy_ips:
            ip = ip.strip()
            if not ip:
                continue
            if ip in existing_ips:
                kept.append(ip)
            else:
                ok, rid = self.add_a_record(subdomain, ip, proxied=proxied, ttl=ttl)
                if ok:
                    added.append(ip)
                else:
                    failed_adds.append(ip)

        # Confirmed active healthy IPs in Cloudflare (either already existed or successfully added)
        confirmed_active = set(kept + added)

        # CRITICAL FAILOVER SAFETY RULE:
        # If adding new healthy IPs failed and none of the healthy IPs are already present,
        # WE MUST NOT DELETE ANY OLD RECORDS! Deleting them would result in zero A records!
        if not confirmed_active:
            # We have zero confirmed healthy records in Cloudflare.
            # ABORT deletion of existing records to avoid total DNS blackout!
            return {
                "subdomain": subdomain,
                "added": added,
                "deleted": [],
                "kept": list(existing_ips),
                "failed_adds": failed_adds,
                "current_healthy": healthy_ips,
                "status": "ABORTED_NO_CONFIRMED_HEALTHY_RECORDS",
                "warning": "Cloudflare addition failed or no healthy nodes confirmed; retained existing records to prevent empty DNS zone."
            }

        # 2. Delete unhealthy IPs from DNS ONLY if at least one confirmed record remains
        # Total records currently in DNS = len(existing_records) + len(added) - len(deleted)
        current_live_count = len(existing_records) + len(added)
        for ip, rec_id in existing_records:
            if ip not in healthy_ips:
                # Never delete if it leaves total records <= 1
                if (current_live_count - len(deleted)) <= 1:
                    continue
                ok, _ = self.delete_record(rec_id)
                if ok:
                    deleted.append(ip)

        return {
            "subdomain": subdomain,
            "added": added,
            "deleted": deleted,
            "kept": kept,
            "failed_adds": failed_adds,
            "current_healthy": healthy_ips,
            "status": "SYNCED"
        }
