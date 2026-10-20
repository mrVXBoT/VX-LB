import unittest
from unittest.mock import MagicMock, patch
from core.adapter_registry import get_adapter, list_registered_adapters
from core.private_link_manager import PrivateLinkManager
from core.firewall_lifecycle_manager import ScopedFirewallManager, DependencyLifecycleManager, mask_secrets
from core.telemetry_supervisor import TelemetrySupervisor
import core.kernel_tunnels_adapter
import core.overlay_tunnels_adapter
import core.wireguard_adapter
import core.software_engines_adapter

class AllTunnelsAndLifecycleTests(unittest.TestCase):
    def test_all_checklist_engine_adapters_are_registered(self):
        """Verify that every user-space and kernel tunnel engine is registered in the unified registry."""
        expected_engines = [
            "backpack", "waterwall", "paqet", "trusttunnel", "slipstream",
            "backhaul", "frp", "rathole", "gost", "hysteria2",
            "ip6ip6", "gre_ipv4", "gre_xhttp", "xhttp", "gre6", "gretap",
            "gre6tap", "gre6tap_ipsec", "sit", "6to4_unicast", "vxlan",
            "geneve", "geneve_ipsec", "geneve_gre6", "wireguard",
            "wireguard_hybrid", "erspan", "eoip", "l2tp", "isatap"
        ]
        registered = list_registered_adapters()
        for eng in expected_engines:
            self.assertIn(eng, registered, f"Engine {eng} missing from adapter registry")
            adapter = get_adapter(eng)
            self.assertIsNotNone(adapter)
            self.assertEqual(adapter.engine_id, eng)

    def test_kernel_tunnel_configuration_generation(self):
        """Verify configuration generation and systemd unit specs for kernel tunnels (IP6IP6, GRE6, SIT)."""
        gre6_adapter = get_adapter("gre6")
        ir_node = {"ip": "2001:db8::1", "node_name": "ir_gre6"}
        kh_serv = {"ip": "2001:db8::2"}
        cfg = gre6_adapter.configure(ir_node, kh_serv, {"mtu": 1400})
        self.assertEqual(cfg["engine"], "gre6")
        self.assertEqual(cfg["mode"], "ip6gre")
        self.assertEqual(cfg["mtu"], 1400)
        self.assertIn("ip link add", cfg["unit_script"])

    def test_overlay_tunnel_configuration_and_vni(self):
        """Verify VXLAN and Geneve configuration generation with VNI (3.13 - 3.15)."""
        vxlan_adapter = get_adapter("vxlan")
        ir_node = {"ip": "192.0.2.1", "node_name": "ir_vxlan"}
        kh_serv = {"ip": "198.51.100.1"}
        cfg = vxlan_adapter.configure(ir_node, kh_serv, {"vni": 2048, "dst_port": 4789})
        self.assertEqual(cfg["engine"], "vxlan")
        self.assertEqual(cfg["vni"], 2048)
        self.assertEqual(cfg["dst_port"], 4789)

    def test_wireguard_keypair_and_allowedips(self):
        """Verify WireGuard config generation with valid Curve25519-format keys and AllowedIPs."""
        wg_adapter = get_adapter("wireguard")
        ir_node = {"ip": "192.0.2.1", "node_name": "ir_wg"}
        kh_serv = {"ip": "198.51.100.1"}
        cfg = wg_adapter.configure(ir_node, kh_serv, {"tunnel_port": 51820})
        self.assertIn("PrivateKey =", cfg["iran_config"])
        self.assertIn("PublicKey =", cfg["iran_config"])
        self.assertIn("AllowedIPs = 10.100.2.2/32", cfg["iran_config"])
        self.assertIn("PersistentKeepalive = 25", cfg["iran_config"])

    def test_private_link_manager_standalone_link(self):
        """Create standalone private link without forced port forwarding."""
        fake_storage = {"custom_links": {}, "resource_reservations": {}}
        with patch("core.private_link_manager.load_data", return_value=fake_storage), \
             patch("core.private_link_manager.atomic_update", side_effect=lambda fn: fn(fake_storage)), \
             patch("core.resource_allocator.atomic_update", side_effect=lambda fn: fn(fake_storage)):

            link = PrivateLinkManager.create_private_link(
                link_name="standalone_link_1",
                engine_id="wireguard",
                iran_server={"ip": "192.0.2.10"},
                kharej_server={"ip": "198.51.100.20"},
                params={"tunnel_port": 51821}
            )
            self.assertEqual(link["link_name"], "standalone_link_1")
            self.assertEqual(link["engine_id"], "wireguard")
            self.assertEqual(link["iran_server"]["private_ip"], "10.100.0.1")
            self.assertEqual(link["kharej_server"]["private_ip"], "10.100.0.2")
            self.assertEqual(link["port_forwarding_rules"], [])

    def test_matrix_topology_and_mesh_explosion_safeguards(self):
        """Multi-destination matrix topology and explosion prevention."""
        fake_storage = {"custom_links": {}, "resource_reservations": {}}
        ir_list = [{"ip": f"192.0.2.{i}"} for i in range(1, 6)]  # 5 servers
        kh_list = [{"ip": f"198.51.100.{i}"} for i in range(1, 11)]  # 10 servers

        with patch("core.private_link_manager.load_data", return_value=fake_storage), \
             patch("core.private_link_manager.atomic_update", side_effect=lambda fn: fn(fake_storage)), \
             patch("core.resource_allocator.load_data", return_value=fake_storage), \
             patch("core.resource_allocator.atomic_update", side_effect=lambda fn: fn(fake_storage)):

            # 1. 5 x 10 = 50 links without allow_full_mesh raises ValueError
            with self.assertRaises(ValueError) as ctx:
                PrivateLinkManager.create_matrix_topology(ir_list, kh_list, "wireguard")
            self.assertIn("explosion", str(ctx.exception).lower())

            # 2. Explicit selected_pairs (e.g. 2 links) succeeds without collision
            selected = [("192.0.2.1", "198.51.100.1"), ("192.0.2.2", "198.51.100.2")]
            links = PrivateLinkManager.create_matrix_topology(ir_list, kh_list, "wireguard", selected_pairs=selected)
            self.assertEqual(len(links), 2)
            self.assertNotEqual(links[0]["private_subnet"], links[1]["private_subnet"])
            self.assertNotEqual(links[0]["interface"], links[1]["interface"])

    def test_path_overhead_and_mtu_discovery(self):
        """Path MTU calculation across layered hybrid encapsulations."""
        overhead_gre = PrivateLinkManager.calculate_path_overhead("gre_ipv4")
        self.assertEqual(overhead_gre, 100)

        # Layered: Geneve over GRE6
        overhead_hybrid = PrivateLinkManager.calculate_path_overhead("geneve", underlying_engine="gre6")
        self.assertEqual(overhead_hybrid, 50 + 64)

        rec_mtu = PrivateLinkManager.calculate_recommended_mtu("geneve", underlying_engine="gre6")
        self.assertEqual(rec_mtu, 1500 - 114)

    def test_link_mutation_diff_preview(self):
        """Preview link mutations with diff and potential downtime detection."""
        fake_storage = {
            "custom_links": {
                "link_alpha": {
                    "link_name": "link_alpha",
                    "mtu": 1400,
                    "engine_id": "wireguard",
                }
            }
        }
        with patch("core.private_link_manager.load_data", return_value=fake_storage):
            preview = PrivateLinkManager.preview_link_mutation("link_alpha", {"mtu": 1360})
            self.assertTrue(preview["has_changes"])
            self.assertTrue(preview["potential_downtime"])
            self.assertEqual(preview["diff"]["mtu"]["current"], 1400)
            self.assertEqual(preview["diff"]["mtu"]["proposed"], 1360)

    def test_firewall_scoped_rules_and_secret_masking(self):
        """Precise comment-tagged rules and secret masking."""
        rules = ScopedFirewallManager.generate_iptables_rules(
            tag="alpha",
            peer_ip="198.51.100.1",
            private_subnet="10.100.0.0/30",
            allowed_ports=[8443]
        )
        for r in rules:
            self.assertIn("ldbp-alpha", r)

        cleanup = ScopedFirewallManager.generate_cleanup_script("alpha")
        self.assertIn("grep -v 'ldbp-alpha'", cleanup)

        # Secret masking
        raw_log = 'Tunnel token="super_secret_token_12345" and password="my_password_xyz"'
        masked = mask_secrets(raw_log)
        self.assertNotIn("super_secret_token_12345", masked)
        self.assertNotIn("my_password_xyz", masked)
        self.assertIn("***REDACTED***", masked)

    def test_dependency_lifecycle_protection(self):
        """Prevent deleting underlying links when higher-level forwards depend on them."""
        fake_storage = {
            "pools": {
                "Pool1": {"carrier_link": "base_link"}
            },
            "custom_links": {
                "base_link": {"link_name": "base_link"},
                "overlay_link": {"underlying_link": "base_link"}
            }
        }
        with patch("core.firewall_lifecycle_manager.load_data", return_value=fake_storage):
            can_delete, reasons = DependencyLifecycleManager.can_delete_link("base_link")
            self.assertFalse(can_delete)
            self.assertEqual(len(reasons), 2)
            self.assertIn("Pool 'Pool1'", reasons[0])
            self.assertIn("overlay_link", reasons[1])

            can_delete_leaf, leaf_reasons = DependencyLifecycleManager.can_delete_link("overlay_link")
            self.assertTrue(can_delete_leaf)
            self.assertEqual(len(leaf_reasons), 0)

    def test_telemetry_supervisor_circuit_breaker(self):
        """Circuit breaker preventing restart loops with cooldowns."""
        sup = TelemetrySupervisor(max_consecutive_restarts=3, cooldown_seconds=60)
        target = "node-1"

        # 3 restarts allowed
        for _ in range(3):
            allowed, _ = sup.can_attempt_recovery(target)
            self.assertTrue(allowed)
            sup.mark_recovery_attempted(target)

        # 4th restart blocked by circuit breaker
        allowed_4th, reason = sup.can_attempt_recovery(target)
        self.assertFalse(allowed_4th)
        self.assertIn("Circuit breaker tripped", reason)

    def test_multi_layer_status_synthesis(self):
        """Multi-layer state separation (process, interface, handshake, data plane)."""
        # All UP -> HEALTHY
        healthy = TelemetrySupervisor.build_layered_status(True, True, True, True, True, True)
        self.assertEqual(healthy["overall_status"], "HEALTHY")

        # Handshake down -> DEGRADED
        degraded = TelemetrySupervisor.build_layered_status(True, True, False, True, True, False)
        self.assertEqual(degraded["overall_status"], "DEGRADED")

        # Process down -> DOWN
        down = TelemetrySupervisor.build_layered_status(False, False, False, False, False, False)
        self.assertEqual(down["overall_status"], "DOWN")

    def test_unimplemented_adapters_explicitly_fail_probe_modify_rollback(self):
        """Verify that adapters without real implementations return unsupported/False and no fake success."""
        for eng in ["trusttunnel", "backhaul", "rathole", "frp"]:
            adapter = get_adapter(eng)
            self.assertIsNotNone(adapter)

            # Probe must return passed=False
            res = adapter.probe({"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}, [443])
            self.assertFalse(res["passed"], f"Engine {eng} probe returned fake True")
            self.assertIn("unsupported", res["error"].lower())

            # Modify must return False
            ok_mod, msg_mod = adapter.modify("test_pool", {"mtu": 1300})
            self.assertFalse(ok_mod, f"Engine {eng} modify returned fake True")
            self.assertIn("unsupported", msg_mod.lower())

            # Rollback must return False
            ok_rb, msg_rb = adapter.rollback("test_pool", {})
            self.assertFalse(ok_rb, f"Engine {eng} rollback returned fake True")
            self.assertIn("unsupported", msg_rb.lower())

    def test_ufw_firewall_generation_and_persistence_unit(self):
        """Verify UFW rules generation without disabling UFW and persistence service."""
        rules = ScopedFirewallManager.generate_ufw_rules("pool1", "198.51.100.1", "10.100.0.0/30", [51820, 8080])
        self.assertEqual(len(rules), 5)  # 2 ports * 2 protos (tcp/udp) + 1 subnet rule
        self.assertTrue(all("ufw allow" in r for r in rules))
        self.assertTrue(all("ldbp-pool1" in r for r in rules))

        svc_name, unit = ScopedFirewallManager.generate_persistence_unit("pool1", rules)
        self.assertEqual(svc_name, "ldbp-fw-pool1.service")
        self.assertIn("Description=LD-BP Scoped Firewall Rules (pool1)", unit)
        self.assertIn("RemainAfterExit=yes", unit)

    def test_dependency_preview_and_blocked_deletion(self):
        """Verify preview_dependent_resources and blocked deletion of base links."""
        with patch("core.firewall_lifecycle_manager.load_data") as mock_load:
            mock_load.return_value = {
                "pools": {"pool_a": {"carrier_link": "link_base"}},
                "custom_links": {
                    "link_base": {"port_forwarding_rules": [{"protocol": "tcp", "listen_port": 80, "backend_port": 8080}]},
                    "link_overlay": {"underlying_link": "link_base"}
                }
            }
            preview = DependencyLifecycleManager.preview_dependent_resources("link_base")
            self.assertFalse(preview["can_delete"])
            self.assertIn("Pool 'pool_a'", preview["blocking_dependents"])
            self.assertIn("Stacked Overlay Link 'link_overlay'", preview["blocking_dependents"])
            self.assertEqual(len(preview["affected_forwards"]), 1)

    def test_link_telemetry_and_server_link_counting(self):
        """Verify comprehensive link telemetry summary and server link count."""
        link = {
            "name": "link1",
            "engine_id": "wireguard",
            "transport": "standard",
            "remote_ip": "198.51.100.1",
            "iran_ip": "192.0.2.1",
            "status": "online",
            "mtu": 1420
        }
        probe_data = {"overall_status": "HEALTHY", "latency_ms": 24.5, "loss_percent": 0.0}
        summary = TelemetrySupervisor.summarize_link_telemetry(link, probe_data)
        self.assertEqual(summary["link_name"], "link1")
        self.assertEqual(summary["status"], "HEALTHY")
        self.assertEqual(summary["latency_ms"], 24.5)
        self.assertEqual(summary["mtu"], 1420)

        data = {"custom_links": {"link1": link}}
        counts = TelemetrySupervisor.count_server_online_links(data)
        self.assertIn("198.51.100.1", counts)
        self.assertEqual(counts["198.51.100.1"]["online_links"], 1)

    def test_idle_node_classification(self):
        """Idle node with 0 bytes transferred is not falsely marked DOWN."""
        status_idle = TelemetrySupervisor.classify_node_activity(user_bytes_transferred=0, probe_passed=True)
        self.assertEqual(status_idle, "IDLE_HEALTHY")

        status_active = TelemetrySupervisor.classify_node_activity(user_bytes_transferred=1024, probe_passed=True)
        self.assertEqual(status_active, "ACTIVE_HEALTHY")

        status_down = TelemetrySupervisor.classify_node_activity(user_bytes_transferred=0, probe_passed=False)
        self.assertEqual(status_down, "DOWN")

    def test_scheduled_reset_timer(self):
        """Scheduled reset timer per link with session persistence."""
        sup = TelemetrySupervisor()
        due, _ = sup.check_link_reset_due("link1", interval_seconds=None)
        self.assertFalse(due)

        # Trigger reset due
        sup._restart_history["link1"] = {"last_reset": 0.0}
        due_now, reason = sup.check_link_reset_due("link1", interval_seconds=3600)
        self.assertTrue(due_now)
        self.assertIn("elapsed", reason)

    def test_phased_migration_dry_run_and_failure_report(self):
        """Phased migration dry run and partial failure reporting."""
        from core.telemetry_supervisor import PhasedMigrationManager
        preview = PhasedMigrationManager.execute_migration_dry_run(
            pool_name="pool1",
            current_transport="wireguard",
            target_transport="xhttp",
            ports=[443, 80],
        )
        self.assertEqual(preview["pool_name"], "pool1")
        self.assertEqual(preview["ports_preserved"], [443, 80])
        self.assertTrue(preview["dns_reconfiguration_required"])
        self.assertEqual(len(preview["phases"]), 4)

        report = PhasedMigrationManager.format_partial_failure_report(
            pool_name="pool1",
            attempted_transport="xhttp",
            failed_stage="bidirectional_probe",
            error_details="TLS handshake timeout",
            remaining_resources=["/etc/systemd/system/xhttp.service"],
        )
        self.assertEqual(report["status"], "PARTIAL_FAILURE_ROLLED_BACK")
        self.assertFalse(report["data_tested"])
        self.assertIn("TLS handshake timeout", report["error"])
        self.assertEqual(len(report["remediation_steps"]), 4)
