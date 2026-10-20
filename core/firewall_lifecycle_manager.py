"""Firewall rule synthesis, resource lifecycle, and dependency safety manager.

Coverage:
- Precise scoped firewall rules per endpoint, protocol, and private IP
- UFW / iptables non-interference (never disable UFW; works alongside active UFW)
- Scoped rule creation and deletion by tag
- Persistent firewall & interface rules across reboots via scoped systemd services
- Secret masking and safe logging
- Safe resource teardown preventing deletion of base links with active dependencies,
             and providing dry-run dependency previews
"""
import ipaddress
import re
import shlex
from typing import Dict, List, Tuple, Optional, Any
from core.storage import load_data

SECRET_PATTERNS = [
    re.compile(r"(?i)(token\s*=\s*['\"])([^'\"]+)(['\"])"),
    re.compile(r"(?i)(password\s*=\s*['\"])([^'\"]+)(['\"])"),
    re.compile(r"(?i)(psk\s*=\s*['\"])([^'\"]+)(['\"])"),
    re.compile(r"(?i)(secret\s*=\s*['\"])([^'\"]+)(['\"])"),
    re.compile(r"(?i)(privatekey\s*=\s*['\"]?)([a-zA-Z0-9+/=]{40,})(['\"]?)"),
]

def mask_secrets(content: str) -> str:
    """Masks tokens, passwords, and private keys in logs and diagnostics."""
    masked = content
    for pat in SECRET_PATTERNS:
        masked = pat.sub(r"\1***REDACTED***\3", masked)
    return masked


class ScopedFirewallManager:
    """Generates and manages idempotent, tagged firewall rules that preserve external rules."""

    @staticmethod
    def generate_iptables_rules(tag: str, peer_ip: str, private_subnet: str, allowed_ports: List[int]) -> List[str]:
        """Generates precisely scoped iptables rules with custom comments."""
        rules = []
        comment = f"ldbp-{tag}"
        # Allow tunnel traffic from specific peer IP
        for p in allowed_ports:
            rules.append(f"iptables -A INPUT -p tcp -s {peer_ip} --dport {p} -m comment --comment '{comment}' -j ACCEPT")
            rules.append(f"iptables -A INPUT -p udp -s {peer_ip} --dport {p} -m comment --comment '{comment}' -j ACCEPT")
        # Allow internal traffic across private link
        rules.append(f"iptables -A INPUT -s {private_subnet} -m comment --comment '{comment}' -j ACCEPT")
        rules.append(f"iptables -A FORWARD -s {private_subnet} -m comment --comment '{comment}' -j ACCEPT")
        rules.append(f"iptables -A FORWARD -d {private_subnet} -m comment --comment '{comment}' -j ACCEPT")
        return rules

    @staticmethod
    def generate_ufw_rules(tag: str, peer_ip: str, private_subnet: str, allowed_ports: List[int]) -> List[str]:
        """Generates non-destructive UFW commands.

        Never disables UFW. Adds tagged allow rules for peer IP and private subnet.
        """
        comment = f"ldbp-{tag}"
        rules = []
        for p in allowed_ports:
            rules.append(f"ufw allow from {shlex.quote(peer_ip)} to any port {int(p)} proto tcp comment {shlex.quote(comment)}")
            rules.append(f"ufw allow from {shlex.quote(peer_ip)} to any port {int(p)} proto udp comment {shlex.quote(comment)}")
        rules.append(f"ufw allow from {shlex.quote(private_subnet)} comment {shlex.quote(comment)}")
        return rules

    @staticmethod
    def generate_cleanup_script(tag: str) -> str:
        """Generates teardown commands that remove ONLY rules matching the tag comment."""
        comment = f"ldbp-{tag}"
        script = f"""
# Clean scoped iptables rules matching comment {comment}
for table in filter nat; do
  iptables-save -t $table | grep -v '{comment}' | iptables-restore -T $table 2>/dev/null || true
done
# Clean UFW rules matching comment if UFW is active
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw status numbered | grep '{comment}' | awk -F"[][]" '{{print $2}}' | sort -rn | while read -r num; do
    echo "y" | ufw delete "$num" 2>/dev/null || true
  done
fi
"""
        return script.strip()

    @staticmethod
    def generate_persistence_unit(tag: str, rules: List[str]) -> Tuple[str, str]:
        """Generates a scoped systemd service to persist firewall rules across reboots.

        Returns (unit_name, unit_content).
        """
        service_name = f"ldbp-fw-{tag}.service"
        script_path = f"/etc/ldbp/fw-{tag}.sh"

        script_content = "#!/bin/bash\nset -e\n" + "\n".join(rules) + "\n"
        unit_content = f"""[Unit]
Description=LD-BP Scoped Firewall Rules ({tag})
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash {script_path}
ExecStop=/bin/bash -c "for table in filter nat; do iptables-save -t $table | grep -v 'ldbp-{tag}' | iptables-restore -T $table 2>/dev/null || true; done"

[Install]
WantedBy=multi-user.target
"""
        return service_name, unit_content


class DependencyLifecycleManager:
    """Enforces dependency tracking to prevent deleting underlying links."""

    @staticmethod
    def preview_dependent_resources(resource_id: str) -> Dict[str, Any]:
        """Inspects all pools, port forwards, and layered links dependent on this resource."""
        data = load_data()
        dependents = []
        affected_pools = []
        affected_forwards = []
        affected_layers = []

        # Check pools using this link
        for pool_name, pool in data.get("pools", {}).items():
            if pool.get("carrier_link") == resource_id:
                dependents.append(f"Pool '{pool_name}'")
                affected_pools.append(pool_name)

        # Check port forwards on this link
        custom_links = data.get("custom_links", {})
        link = custom_links.get(resource_id, {})
        for rule in link.get("port_forwarding_rules", []):
            affected_forwards.append(f"{rule.get('protocol', 'tcp').upper()}:{rule.get('listen_port')} -> {rule.get('backend_port')}")

        # Check stacked layered links
        for other_name, other_link in custom_links.items():
            if other_name == resource_id:
                continue
            if other_link.get("underlying_link") == resource_id:
                dependents.append(f"Stacked Overlay Link '{other_name}'")
                affected_layers.append(other_name)

        can_delete = len(dependents) == 0 and len(affected_forwards) == 0
        return {
            "resource_id": resource_id,
            "can_delete": can_delete,
            "blocking_dependents": dependents,
            "affected_pools": affected_pools,
            "affected_forwards": affected_forwards,
            "affected_layers": affected_layers,
            "warning": None if can_delete else f"Cannot delete '{resource_id}': has {len(dependents)} active dependent(s)."
        }

    @staticmethod
    def can_delete_link(link_name: str) -> Tuple[bool, List[str]]:
        """Checks if any pools, port forwards, or layered overlays depend on this link."""
        preview = DependencyLifecycleManager.preview_dependent_resources(link_name)
        return preview["can_delete"], preview["blocking_dependents"]
