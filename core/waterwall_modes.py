"""Multi-mode WaterWall chain generation.

Rebuilds the WaterWall engine around the real WaterWall protocol nodes so each
mode matches the documented "client/server" chain instead of the old single
fixed VLESS+TLS+Mux+cert shape.

Modes:
  - trojan      : TrojanClient/TrojanServer (password-based; TLS optional)
  - reality     : RealityClient/RealityServer (fake-SNI camouflage, no cert)
  - reverse     : ReverseServer on Iran, ReverseClient on Kharej (Kharej dials Iran)
  - halfduplex  : HalfDuplexClient/HalfDuplexServer (separate up/down paths)
  - bgp4       : Bgp4Client/Bgp4Server (BGP-shaped framing, no real BGP)

All modes keep VX-LB's port-forwarding semantics: Iran listens on the client
ports and forwards to the same port on Kharej's loopback backend.
"""
import copy

MODES = ("trojan", "reality", "reverse", "halfduplex", "bgp4")

MODE_LABELS = {
    "halfduplex": "HalfDuplex",
    "reverse": "Reverse",
    "trojan": "Trojan",
    "bgp4": "Bgp4",
    "reality": "Reality",
}

MODE_HINTS = {
    "halfduplex": "Separate upload and download channels",
    "reverse": "Kharej dials Iran; users still enter on the Iran ports",
    "trojan": "Shared-password authentication; optional TLS requires certificates",
    "bgp4": "BGP-shaped framing; does not provide BGP routing",
    "reality": "Reality mode with configurable SNI; no public server certificate required",
}


def _listener(name, host, port, next_node):
    return {
        "name": name,
        "type": "TcpUdpListener",
        "settings": {
            "address": host,
            "port": port,
            "nodelay": True,
            "large-send-buffer": True,
            "large-recv-buffer": True,
        },
        "next": next_node,
    }


def _router(name, rules, next_node):
    return {"name": name, "type": "Router", "settings": {"rules": rules}, "next": next_node}


def _blackhole(name):
    return {"name": name, "type": "BlackHole", "settings": {"mode": "active"}}


def _connector(name, address, port, udp=False):
    settings = {
        "address": address,
        "port": port if isinstance(port, str) else int(port),
        "nodelay": True,
        "large-send-buffer": True,
        "large-recv-buffer": True,
    }
    return {"name": name, "type": "UdpConnector" if udp else "TcpConnector", "settings": settings}


def _backend_tail(allowed_ports, target_port, tcp_only=False, fixed_port=False):
    """Shared Kharej egress: Router -> BlackHole + per-destination connectors.

    Each allowed destination port is forwarded to the same port on loopback
    (dest_context->port), preserving the client/backend port mapping for every
    port in the chain (client ports + optional dedicated probe port).

    ``fixed_port`` routes every destination to the fixed ``target_port`` on
    loopback instead of the original destination port. Some node types (e.g.
    HalfDuplexServer/Bgp4Server) drop data when the backend connector uses the
    dynamic ``dest_context->port``, so those modes pass ``fixed_port=True``.
    """
    allowed = allowed_ports[0] if len(allowed_ports) == 1 else allowed_ports
    rules = [{"network": "tcp", "destination-port": allowed, "target": "tcp-connector-backend"}]
    if fixed_port:
        connector_cfg = {"address": "127.0.0.1", "port": int(target_port), "nodelay": True,
                         "large-send-buffer": True, "large-recv-buffer": True}
    else:
        connector_cfg = {"address": "127.0.0.1", "port": "dest_context->port", "nodelay": True,
                         "large-send-buffer": True, "large-recv-buffer": True}
    nodes = [
        _router("backend-router", rules, "blackhole-reject"),
        _blackhole("blackhole-reject"),
        {"name": "tcp-connector-backend", "type": "TcpConnector", "settings": connector_cfg},
    ]
    if not tcp_only:
        rules.insert(0, {"network": "udp", "destination-port": allowed, "target": "udp-connector-backend"})
        udp_cfg = dict(connector_cfg)
        nodes.append({"name": "udp-connector-backend", "type": "UdpConnector", "settings": udp_cfg})
    return nodes


def _kp_connector(kharej_ip, outer):
    return _connector("tcp-connector", kharej_ip, outer)


def iran_chain(mode, node, kharej_ip, ports):
    """Build the Iran (client) chain for a given mode."""
    ww = node["waterwall"]
    prof = ww["profile"]
    outer = int(ww["outer_port"])
    ports_list = [int(p) for p in ports]
    port_cfg = ports_list[0] if len(ports_list) == 1 else ports_list

    if mode == "trojan":
        return _iran_trojan(prof, ports_list, port_cfg, kharej_ip, outer, node)
    if mode == "reality":
        return _iran_reality(prof, ports_list, port_cfg, kharej_ip, outer, node)
    if mode == "reverse":
        return _iran_reverse(prof, ports_list, port_cfg, kharej_ip, outer, node)
    if mode == "halfduplex":
        return _iran_halfduplex(prof, ports_list, port_cfg, kharej_ip, outer, node)
    if mode == "bgp4":
        return _iran_bgp4(prof, ports_list, port_cfg, kharej_ip, outer, node)
    raise ValueError(f"WaterWall mode نامعتبر: {mode}")


def _iran_trojan(prof, ports_list, port_cfg, kharej_ip, outer, node):
    use_tls = bool(prof.get("certificate") and prof.get("key"))
    sni = prof.get("server_name") or kharej_ip
    iran_nodes = [
        _listener("tcp-udp-listener", "0.0.0.0", port_cfg, "protocol-router"),
    ]
    tcp_rules, udp_rules = [], []
    for p in ports_list:
        tcp_next = f"tcp-trojan-client-{p}"
        udp_next = f"udp-trojan-client-{p}"
        tcp_rules.append({"source-port": p, "target": tcp_next})
        udp_rules.append({"source-port": p, "target": udp_next})
        for proto, name in (("tcp", tcp_next), ("udp", udp_next)):
            connector = f"tcp-connector-{name}"
            branch_next = connector if not use_tls else f"tls-client-{name}"
            iran_nodes.append({
                "name": name,
                "type": "TrojanClient",
                "settings": {
                    "password": prof["password"],
                    "address": "127.0.0.1",
                    "port": p,
                    "protocol": proto,
                    "domain-strategy": "do-not-resolve-domains",
                },
                "next": branch_next,
            })
            if use_tls:
                iran_nodes.append({
                    "name": f"tls-client-{name}",
                    "type": "TlsClient",
                    "settings": {"sni": sni, "verify": False, "alpns": ["h2"], "x25519mlkem768": True},
                    "next": connector,
                })
            iran_nodes.append(_connector(connector, kharej_ip, outer))
    iran_nodes += [
        _router("protocol-router", [{"network": "udp", "target": "udp-port-router"}], "tcp-port-router"),
        _router("tcp-port-router", tcp_rules, "blackhole-iran-tcp"),
        _router("udp-port-router", udp_rules, "blackhole-iran-udp"),
        _blackhole("blackhole-iran-tcp"),
        _blackhole("blackhole-iran-udp"),
    ]
    return {"name": f"iran-trojan-{node['node_name']}", "nodes": iran_nodes}


def _iran_reality(prof, ports_list, port_cfg, kharej_ip, outer, node):
    ports_list = [ports_list[0]]  # Reality is TCP-only; single carrier port
    port_cfg = ports_list[0]
    iran_nodes = [
        {
            "name": "tcp-listener",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": port_cfg,
                "nodelay": True,
                "large-send-buffer": True,
                "large-recv-buffer": True,
            },
            "next": "protocol-router",
        },
        _router("protocol-router", [{"source-port": p, "target": "reality-client"} for p in ports_list], "blackhole-iran"),
        _blackhole("blackhole-iran"),
        {
            "name": "reality-client",
            "type": "RealityClient",
            "settings": {"sni": prof.get("server_name", kharej_ip), "verify": False, "password": prof["password"]},
            "next": "tcp-connector",
        },
        _kp_connector(kharej_ip, outer),
    ]
    return {"name": f"iran-reality-{node['node_name']}", "nodes": iran_nodes}


def _reverse_secret(prof):
    return {
        "reverse-secret-length": int(prof.get("secret_length", 640)),
        "reverse-secret": str(prof.get("secret") or "vxlb-waterwall-reverse"),
    }


def _iran_reverse(prof, ports_list, port_cfg, kharej_ip, outer, node):
    """Users enter on Iran. Kharej's ReverseClient dials the peer listener.

    ReverseServer is the side that can accept connections. Putting ReverseClient
    on Iran feeds a listener into a node that treats upstream Init as fatal, so
    the Iran process exits and systemd reports the service inactive.
    """
    iran_nodes = [
        {
            "name": "tcp-listener",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": port_cfg,
                "nodelay": True,
                "large-send-buffer": True,
                "large-recv-buffer": True,
            },
            "next": "port-header",
        },
        {
            "name": "port-header",
            "type": "HeaderClient",
            "settings": {"data": "src_context->port"},
            "next": "bridge-users",
        },
        {"name": "bridge-users", "type": "Bridge", "settings": {"pair": "bridge-reverse"}},
        {"name": "bridge-reverse", "type": "Bridge", "settings": {"pair": "bridge-users"}},
        {
            "name": "reverse-server",
            "type": "ReverseServer",
            "settings": _reverse_secret(prof),
            "next": "bridge-reverse",
        },
        {
            "name": "peer-listener",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": int(outer),
                "nodelay": True,
                "large-send-buffer": True,
                "large-recv-buffer": True,
                "whitelist": [f"{kharej_ip}/32"],
            },
            "next": "reverse-server",
        },
    ]
    return {"name": f"iran-reverse-{node['node_name']}", "nodes": iran_nodes}


def _iran_halfduplex(prof, ports_list, port_cfg, kharej_ip, outer, node):
    iran_nodes = [
        {
            "name": "tcp-listener",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": port_cfg,
                "nodelay": True,
                "large-send-buffer": True,
                "large-recv-buffer": True,
            },
            "next": "halfduplex-client",
        },
        {
            "name": "halfduplex-client",
            "type": "HalfDuplexClient",
            "settings": {},
            "next": "tcp-connector",
        },
        _kp_connector(kharej_ip, outer),
        _blackhole("blackhole-iran-halfduplex"),
    ]
    return {"name": f"iran-halfduplex-{node['node_name']}", "nodes": iran_nodes}


def _iran_bgp4(prof, ports_list, port_cfg, kharej_ip, outer, node):
    ports_list = [ports_list[0]]
    port_cfg = ports_list[0]
    iran_nodes = [
        {
            "name": "tcp-listener",
            "type": "TcpListener",
            "settings": {
                "address": "0.0.0.0",
                "port": port_cfg,
                "nodelay": True,
                "large-send-buffer": True,
                "large-recv-buffer": True,
            },
            "next": "bgp4-client",
        },
        {
            "name": "bgp4-client",
            "type": "Bgp4Client",
            "settings": {"password": prof.get("password", "")},
            "next": "tcp-connector",
        },
        _kp_connector(kharej_ip, outer),
        _blackhole("blackhole-iran-bgp4"),
    ]
    return {"name": f"iran-bgp4-{node['node_name']}", "nodes": iran_nodes}


def kharej_chain(mode, node, ports):
    """Build the Kharej (server) chain for a given mode."""
    ww = node["waterwall"]
    prof = ww["profile"]
    outer = int(ww["outer_port"])
    ports_list = [int(p) for p in ports]
    target_port = ww.get("backend_port") or ports_list[0]
    allowed = ports_list

    if mode == "trojan":
        return _kharej_trojan(prof, outer, allowed, target_port, node)
    if mode == "reality":
        return _kharej_reality(prof, outer, allowed, target_port, node)
    if mode == "reverse":
        return _kharej_reverse(prof, outer, allowed, target_port, node)
    if mode == "halfduplex":
        return _kharej_halfduplex(prof, outer, allowed, target_port, node)
    if mode == "bgp4":
        return _kharej_bgp4(prof, outer, allowed, target_port, node)
    raise ValueError(f"WaterWall mode نامعتبر: {mode}")


def _kharej_trojan(prof, outer, allowed, target_port, node):
    use_tls = bool(prof.get("certificate") and prof.get("key"))
    nodes = [_listener("tcp-udp-listener", "0.0.0.0", outer, "tls-server" if use_tls else "trojan-server")]
    if use_tls:
        nodes.append({
            "name": "tls-server",
            "type": "TlsServer",
            "settings": {
                "cert-file": prof["certificate"],
                "key-file": prof["key"],
                "select-alpns": ["h2"],
                "min-version": "TLSv1.3",
                "max-version": "TLSv1.3",
            },
            "next": "trojan-server",
        })
    nodes.append({
        "name": "trojan-server",
        "type": "TrojanServer",
        "settings": {"password": prof["password"], "connect": True, "udp": True},
        "next": "backend-router",
    })
    nodes += _backend_tail(allowed, target_port)
    return {"name": f"kharej-trojan-{node['node_name']}", "nodes": nodes}


def _kharej_reality(prof, outer, allowed, target_port, node):
    """Dial the backend port directly after RealityServer.

    A destination-port router never matches this connection: the accepted
    socket is the outer carrier, not the Iran client port. The blackhole then
    closes it and the probe reads zero bytes. Reality already has one backend
    port, so the server node connects there itself.
    """
    sni = prof.get("server_name") or "www.microsoft.com"
    nodes = [
        {
            "name": "tcp-listener",
            "type": "TcpListener",
            "settings": {"address": "0.0.0.0", "port": outer, "nodelay": True, "large-send-buffer": True, "large-recv-buffer": True},
            "next": "reality-server",
        },
        {
            "name": "reality-server",
            "type": "RealityServer",
            "settings": {"destination": "visitor-site", "password": prof["password"]},
            "next": "tcp-connector-backend",
        },
        _connector("visitor-site", sni, 443),
        _connector("tcp-connector-backend", "127.0.0.1", int(target_port)),
    ]
    return {"name": f"kharej-reality-{node['node_name']}", "nodes": nodes}


def _kharej_reverse(prof, outer, allowed, target_port, node):
    """Kharej dials Iran, then connects the recovered user port on loopback."""
    iran_ip = node.get("ip")
    if not iran_ip:
        raise ValueError("Reverse needs the Iran server address")
    nodes = [
        {
            "name": "tcp-connector-backend",
            "type": "TcpConnector",
            "settings": {
                "address": "127.0.0.1",
                "port": "dest_context->port",
                "nodelay": True,
                "large-send-buffer": True,
                "large-recv-buffer": True,
            },
        },
        {
            "name": "port-header",
            "type": "HeaderServer",
            "settings": {"override": "dest_context->port"},
            "next": "tcp-connector-backend",
        },
        {
            "name": "bridge-local",
            "type": "Bridge",
            "settings": {"pair": "bridge-reverse"},
            "next": "port-header",
        },
        {
            "name": "bridge-reverse",
            "type": "Bridge",
            "settings": {"pair": "bridge-local"},
            "next": "reverse-client",
        },
        {
            "name": "reverse-client",
            "type": "ReverseClient",
            "settings": dict(_reverse_secret(prof), **{"minimum-unused": 16}),
            "next": "tcp-connector",
        },
        _kp_connector(iran_ip, outer),
    ]
    return {"name": f"kharej-reverse-{node['node_name']}", "nodes": nodes}


def _kharej_halfduplex(prof, outer, allowed, target_port, node):
    nodes = [
        {
            "name": "tcp-listener",
            "type": "TcpListener",
            "settings": {"address": "0.0.0.0", "port": outer, "nodelay": True, "large-send-buffer": True, "large-recv-buffer": True},
            "next": "halfduplex-server",
        },
        {
            "name": "halfduplex-server",
            "type": "HalfDuplexServer",
            "settings": {},
            "next": "tcp-connector-backend",
        },
        _connector("tcp-connector-backend", "127.0.0.1", int(target_port)),
    ]
    return {"name": f"kharej-halfduplex-{node['node_name']}", "nodes": nodes}


def _kharej_bgp4(prof, outer, allowed, target_port, node):
    nodes = [
        {
            "name": "tcp-listener",
            "type": "TcpListener",
            "settings": {"address": "0.0.0.0", "port": outer, "nodelay": True, "large-send-buffer": True, "large-recv-buffer": True},
            "next": "bgp4-server",
        },
        {
            "name": "bgp4-server",
            "type": "Bgp4Server",
            "settings": {"password": prof.get("password", "")},
            "next": "tcp-connector-backend",
        },
        _connector("tcp-connector-backend", "127.0.0.1", int(target_port)),
    ]
    return {"name": f"kharej-bgp4-{node['node_name']}", "nodes": nodes}


def default_settings(mode):
    """Return a default settings template for the given mode."""
    base = {"binary": "/usr/local/bin/waterwall", "port": 443}
    if mode == "trojan":
        base.update({"password": "", "tls": False})
    elif mode == "reality":
        base.update({"password": "", "server_name": "www.microsoft.com"})
    elif mode == "reverse":
        base.update({"secret": "vxlb-waterwall-reverse", "secret_length": 640})
    elif mode in ("halfduplex", "bgp4"):
        base.update({"password": ""})
    return base
