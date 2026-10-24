"""
Test WaterWall chain configs for syntax and structure correctness across all
supported modes (trojan, reality, reverse, halfduplex, bgp4).
Does NOT run the actual WaterWall binary.
"""
import json
import unittest
from core import waterwall
from core.waterwall_modes import MODES, default_settings


def make_node(mode):
    settings = default_settings(mode)
    if mode == "trojan":
        settings["password"] = "secret-pass-1234"
    if mode == "reality":
        settings["password"] = "secret"
        settings["server_name"] = "www.microsoft.com"
    if mode == "reverse":
        settings["secret"] = "vxlb-waterwall-reverse"
        settings["secret_length"] = 640
    if mode == "bgp4":
        settings["password"] = "x"
    prof = waterwall.profile(mode, settings)
    return {
        "node_name": "ldw" + "a" * 16,
        "waterwall": {
            "profile": prof,
            "outer_port": 8443,
            "backend_port": 9443,
        },
    }


class WaterWallConfigTests(unittest.TestCase):
    def test_chain_config_structure_per_mode(self):
        for mode in MODES:
            node = make_node(mode)
            iran_chain, kharej_chain = waterwall.chain_configs(node, "192.0.2.1", ["443", "2053"])
            self.assertIn(f"iran-{mode}-", iran_chain["name"], mode)
            self.assertIn(f"kharej-{mode}-", kharej_chain["name"], mode)
            self.assertIsInstance(iran_chain["nodes"], list)
            self.assertIsInstance(kharej_chain["nodes"], list)
            self.assertGreater(len(iran_chain["nodes"]), 0)
            self.assertGreater(len(kharej_chain["nodes"]), 0)

    def test_config_json_valid_per_mode(self):
        for mode in MODES:
            node = make_node(mode)
            iran_chain, kharej_chain = waterwall.chain_configs(node, "192.0.2.1", ["443", "2053"])
            iran_json = json.dumps(iran_chain)
            kharej_json = json.dumps(kharej_chain)
            self.assertEqual(json.loads(iran_json), iran_chain, mode)
            self.assertEqual(json.loads(kharej_json), kharej_chain, mode)

    def test_node_names_unique_within_chain(self):
        for mode in MODES:
            node = make_node(mode)
            iran_chain, kharej_chain = waterwall.chain_configs(node, "192.0.2.1", ["443"])
            iran_names = [n["name"] for n in iran_chain["nodes"]]
            kharej_names = [n["name"] for n in kharej_chain["nodes"]]
            self.assertEqual(len(iran_names), len(set(iran_names)), mode)
            self.assertEqual(len(kharej_names), len(set(kharej_names)), mode)

    def test_all_next_targets_exist(self):
        for mode in MODES:
            node = make_node(mode)
            iran_chain, kharej_chain = waterwall.chain_configs(node, "192.0.2.1", ["443"])
            for chain, side in [(iran_chain, "Iran"), (kharej_chain, "Kharej")]:
                node_names = {n["name"] for n in chain["nodes"]}
                for n in chain["nodes"]:
                    if "next" in n:
                        self.assertIn(n["next"], node_names, f"{mode}:{side} {n['name']} next {n['next']}")
                    if n["type"] == "Router":
                        for rule in n["settings"].get("rules", []):
                            if "target" in rule:
                                self.assertIn(rule["target"], node_names, f"{mode}:{side} {n['name']} target {rule['target']}")

    def test_backend_router_and_blackhole_present(self):
        for mode in MODES:
            node = make_node(mode)
            _, kharej_chain = waterwall.chain_configs(node, "192.0.2.1", ["443"])
            router = next((n for n in kharej_chain["nodes"] if n["name"] == "backend-router"), None)
            self.assertIsNotNone(router, mode)
            self.assertEqual(router["next"], "blackhole-reject", mode)
            blackhole = next((n for n in kharej_chain["nodes"] if n["name"] == "blackhole-reject"), None)
            self.assertIsNotNone(blackhole, mode)
            self.assertEqual(blackhole["type"], "BlackHole", mode)
            self.assertEqual(blackhole["settings"]["mode"], "active", mode)
            for rule in router["settings"]["rules"]:
                self.assertIn("destination-port", rule, mode)

    def test_mode_protocol_nodes_present(self):
        expectations = {
            "trojan": ("TrojanClient", "TrojanServer"),
            "reality": ("RealityClient", "RealityServer"),
            "reverse": ("ReverseClient", "ReverseServer"),
            "halfduplex": ("HalfDuplexClient", "HalfDuplexServer"),
            "bgp4": ("Bgp4Client", "Bgp4Server"),
        }
        for mode, (client_type, server_type) in expectations.items():
            node = make_node(mode)
            iran_chain, kharej_chain = waterwall.chain_configs(node, "192.0.2.1", ["443"])
            self.assertTrue(any(n["type"] == client_type for n in iran_chain["nodes"]), mode)
            self.assertTrue(any(n["type"] == server_type for n in kharej_chain["nodes"]), mode)

    def test_reverse_and_bridge_adjacency(self):
        node = make_node("reverse")
        iran_chain, kharej_chain = waterwall.chain_configs(node, "192.0.2.1", ["443"])
        iran_types = [n["type"] for n in iran_chain["nodes"]]
        kharej_types = [n["type"] for n in kharej_chain["nodes"]]
        self.assertIn("Bridge", iran_types)
        self.assertIn("ReverseClient", iran_types)
        self.assertIn("Bridge", kharej_types)
        self.assertIn("ReverseServer", kharej_types)
        # Bridge must be immediately before ReverseClient on the client side
        client_nodes = iran_chain["nodes"]
        for i, n in enumerate(client_nodes):
            if n["type"] == "ReverseClient":
                self.assertEqual(client_nodes[i - 1]["type"], "Bridge")
        server_nodes = kharej_chain["nodes"]
        for i, n in enumerate(server_nodes):
            if n["type"] == "ReverseServer":
                self.assertEqual(server_nodes[i + 1]["type"], "Bridge")

    def test_trojan_password_carried(self):
        node = make_node("trojan")
        iran_chain, kharej_chain = waterwall.chain_configs(node, "192.0.2.1", ["443"])
        client = next(n for n in iran_chain["nodes"] if n["type"] == "TrojanClient")
        server = next(n for n in kharej_chain["nodes"] if n["type"] == "TrojanServer")
        self.assertEqual(client["settings"]["password"], node["waterwall"]["profile"]["password"])
        self.assertEqual(server["settings"]["password"], node["waterwall"]["profile"]["password"])


if __name__ == "__main__":
    unittest.main()
