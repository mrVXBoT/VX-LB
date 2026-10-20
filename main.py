#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socket
from functools import wraps
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

# Add root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.storage import (
    add_server,
    get_servers,
    delete_server,
    get_pools,
    load_data,
    LOG_FILE
)
from core.ssh_client import SSHManager
from core.tunnel import SUPPORTED_TRANSPORTS
from core.load_balancer import LoadBalancerManager
from core.transport_change import mutation_lock, busy as transport_busy, start_change, run_change, update_job
from core.cloudflare import CloudflareManager
from core.watchdog import TelemetryWatchdog
from core.web_server import (
    is_web_running,
    get_web_pid,
    get_web_port,
    start_background_web,
    stop_background_web
)

console = Console()
watchdog = TelemetryWatchdog(check_interval=30)

def pool_mutation_flow(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        with mutation_lock():
            if transport_busy():
                console.print("Tunnel change or rollback is in progress; pool operations are locked.")
                return
            return function(*args, **kwargs)
    return guarded

def clear_screen():
    os.system("clear" if os.name == "posix" else "cls")

def show_banner():
    clear_screen()
    banner_text = """[bold cyan]
██╗   ██╗██╗  ██╗   ██╗     ██████╗
╚██╗ ██╔╝╚██╗██╔╝   ██║     ██╔══██╗
 ╚████╔╝  ╚███╔╝    ██║     ██████╔╝
  ╚██╔╝   ██╔██╗    ██║     ██╔══██╗
   ██║   ██╔╝ ██╗   ███████╗██████╔╝
   ╚═╝   ╚═╝  ╚═╝   ╚══════╝╚═════╝
[/bold cyan]
[bold yellow]VX LB — Multi-Iran Load Balancer & Tunnel Orchestrator[/bold yellow]
"""
    console.print(banner_text)
    
    # Quick statistics
    ir_count = len(get_servers("iran"))
    kh_count = len(get_servers("kharej"))
    pools = get_pools()
    pool_count = len(pools)
    cf_pools = [p for p in pools.values() if (p.get("cloudflare") or {}).get("enabled")]
    if cf_pools:
        cf_subs = [p["cloudflare"]["subdomain"] for p in cf_pools if p.get("cloudflare", {}).get("subdomain")]
        if len(cf_subs) == 1:
            dns_display = cf_subs[0]
        else:
            dns_display = f"{len(cf_subs)} Pools Active"
    else:
        cf_cfg = load_data().get("cloudflare")
        dns_display = cf_cfg.get("subdomain", "None") if (cf_cfg and cf_cfg.get("enabled")) else "None"

    is_running = watchdog.is_daemon_running() or watchdog._running
    daemon_status = "[bold green]ON[/bold green]" if is_running else "[dim]OFF[/dim]"
    web_on = is_web_running()
    web_status = f"[bold green]:{get_web_port()}[/bold green]" if web_on else "[dim]OFF[/dim]"
    status_bar = f"[white]Iran:[/white] [green]{ir_count}[/green] | [white]Kharej:[/white] [blue]{kh_count}[/blue] | [white]Pools:[/white] [yellow]{pool_count}[/yellow] | [white]Failover:[/white] [cyan]{dns_display}[/cyan] ({daemon_status}) | [white]Web UI:[/white] {web_status}"
    console.print(Panel(status_bar, border_style="dim"))

def manage_servers_menu():
    while True:
        show_banner()
        console.print("[bold green]=== Server Management ===[/bold green]\n")
        console.print("  [1] ➕ Add & Test New Server")
        console.print("  [2] 📋 View Registered Servers")
        console.print("  [3] 🗑️  Delete a Server")
        console.print("  [0] 🔙 Back to Main Menu\n")

        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "0"], default="1")

        if choice == "1":
            add_new_server_flow()
        elif choice == "2":
            list_servers_flow()
            Prompt.ask("\nPress Enter to return")
        elif choice == "3":
            delete_server_flow()
        elif choice == "0":
            break

def add_new_server_flow():
    console.print("\n[bold cyan]--- Add New Server ---[/bold cyan]")
    stype = Prompt.ask("Server location / role", choices=["iran", "kharej"], default="iran")
    name = Prompt.ask("Friendly name (e.g. ir-mci or kh-frankfurt)")
    ip = Prompt.ask("Server IP address")
    port = Prompt.ask("SSH port", default="22")
    from core.validation import validate_port
    try:
        port = int(validate_port(port))
    except ValueError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        time.sleep(1)
        return
    username = Prompt.ask("SSH username", default="root")
    console.print("[dim]Select SSH authentication method:[/dim]")
    console.print("  [1] Password")
    console.print("  [2] SSH Private Key file")
    auth_choice = Prompt.ask("Authentication", choices=["1", "2"], default="1")
    password = None
    key_path = None
    if auth_choice == "1":
        password = Prompt.ask("SSH password", password=True)
    else:
        default_key = os.path.expanduser("~/.ssh/id_rsa")
        if not os.path.exists(default_key):
            ed_key = os.path.expanduser("~/.ssh/id_ed25519")
            if os.path.exists(ed_key):
                default_key = ed_key
        key_path = Prompt.ask("Private key path", default=default_key)
        if not os.path.isfile(os.path.expanduser(key_path)):
            console.print(f"[bold yellow]Warning: Key file '{key_path}' does not exist locally.[/bold yellow]")

    console.print(f"\n[cyan]🔄 Testing SSH connectivity to {ip}:{port}...[/cyan]")
    ssh = SSHManager(ip=ip, port=port, username=username, password=password, key_path=key_path, timeout=10)
    ok, msg = ssh.connect()

    if ok:
        console.print(f"[bold green]Success: Connection successful: {msg}[/bold green]")
        _, out, _ = ssh.execute("uname -m")
        arch = out.strip()
        console.print(f"[dim]Architecture detected: {arch}[/dim]")
        ssh.close()

        server_info = {
            "name": name,
            "ip": ip,
            "port": port,
            "username": username,
            "password": password,
            "key_path": key_path,
            "arch": arch
        }
        add_server(stype, server_info)
        console.print(f"[bold green]✔️ Server saved successfully in {stype} inventory.[/bold green]")
    else:
        console.print(f"[bold red]Error: Connection failed: {msg}[/bold red]")
        if "Authentication failed" in msg:
            console.print("[yellow]💡 Hint: invalid username or SSH password/key.[/yellow]")
        elif "Server connection error" in msg:
            console.print("[yellow]💡 Hint: network connection failed (check the server's SSH port and firewall).[/yellow]")
        if Confirm.ask("Do you want to save this server anyway?", default=False):
            server_info = {
                "name": name,
                "ip": ip,
                "port": port,
                "username": username,
                "password": password,
                "key_path": key_path,
                "arch": "unknown"
            }
            add_server(stype, server_info)
            console.print("[yellow]Server saved.[/yellow]")

    time.sleep(1.5)

def list_servers_flow():
    iran_srvs = get_servers("iran")
    kharej_srvs = get_servers("kharej")

    table = Table(title="Registered Servers Inventory", show_lines=True)
    table.add_column("#", style="dim", width=5)
    table.add_column("Location", style="cyan")
    table.add_column("Name", style="bold white")
    table.add_column("IP Address", style="yellow")
    table.add_column("SSH Port", style="dim")
    table.add_column("Username", style="dim")

    row_idx = 1
    for s in iran_srvs:
        table.add_row(str(row_idx), "🇮🇷 Iran", s["name"], s["ip"], str(s.get("port", 22)), s.get("username", "root"))
        row_idx += 1

    for s in kharej_srvs:
        table.add_row(str(row_idx), "🌍 Kharej", s["name"], s["ip"], str(s.get("port", 22)), s.get("username", "root"))
        row_idx += 1

    console.print(table)

def delete_server_flow():
    list_servers_flow()
    stype = Prompt.ask("Location of the server to delete", choices=["iran", "kharej"])
    ip = Prompt.ask("Enter IP address of the server to delete")

    # Safety guard: Check if server is currently in an active load balancer pool
    pools = get_pools()
    for p_name, p_data in pools.items():
        if stype == "kharej" and p_data.get("kharej_server", {}).get("ip") == ip:
            console.print(f"[bold red]Error: Cannot delete {ip}: This server is the destination Kharej server for active pool '{p_name}'![/bold red]")
            console.print("[yellow]Please delete the pool first via Manage Load Balancers.[/yellow]")
            Prompt.ask("\nPress Enter to return")
            return
        if stype == "iran":
            for n in p_data.get("nodes", []):
                if n.get("ip") == ip:
                    console.print(f"[bold red]Error: Cannot delete {ip}: This server is currently an active node in pool '{p_name}'![/bold red]")
                    console.print(f"[yellow]Please remove node {ip} from pool '{p_name}' first (Manage Load Balancers -> [R]).[/yellow]")
                    Prompt.ask("\nPress Enter to return")
                    return

    if delete_server(stype, ip):
        console.print(f"[bold green]✔️ Server {ip} successfully deleted.[/bold green]")
    else:
        console.print("[bold red]Error: Server not found with this IP address.[/bold red]")
    time.sleep(1.5)

@pool_mutation_flow
def create_load_balancer_flow():
    show_banner()
    console.print("[bold green]=== Create Load Balancer (Multi-Iran ⇄ 1-Kharej) ===[/bold green]\n")

    kharej_srvs = get_servers("kharej")
    iran_srvs = get_servers("iran")

    if not kharej_srvs:
        console.print("[bold red]Error: No Kharej servers registered! Please add a Kharej server first via Server Management.[/bold red]")
        Prompt.ask("\nPress Enter to return")
        return

    if not iran_srvs:
        console.print("[bold red]Error: No Iran servers registered! Please add Iran servers first via Server Management.[/bold red]")
        Prompt.ask("\nPress Enter to return")
        return

    pool_name = Prompt.ask("Enter a name for this load balancer (e.g. VIP-LB or Web-Tunnel)", default="Main-LB")

    # 1. Select Kharej Server
    console.print("\n[bold cyan]1. Select Destination Kharej Server:[/bold cyan]")
    for idx, s in enumerate(kharej_srvs, 1):
        console.print(f"  [{idx}] {s['name']} ({s['ip']})")
    
    kh_choice = Prompt.ask("Choose Kharej server index", choices=[str(i) for i in range(1, len(kharej_srvs)+1)], default="1")
    selected_kharej = kharej_srvs[int(kh_choice) - 1]

    # 2. Select Iran Servers
    console.print("\n[bold cyan]2. Select Iran Edge Servers for Load Balancing:[/bold cyan]")
    for idx, s in enumerate(iran_srvs, 1):
        console.print(f"  [{idx}] {s['name']} ({s['ip']})")
    console.print("  [A] All Iran Servers")

    ir_input = Prompt.ask("Enter comma-separated numbers (e.g. 1,2) or 'A' for all", default="A")
    if ir_input.strip().upper() == "A":
        selected_irans = iran_srvs
    else:
        indices = [int(x.strip()) for x in ir_input.split(",") if x.strip().isdigit()]
        selected_irans = [iran_srvs[i - 1] for i in indices if 1 <= i <= len(iran_srvs)]

    if not selected_irans:
        console.print("[bold red]Error: No Iran servers selected![/bold red]")
        time.sleep(2)
        return

    # 3. Select Transport (Smart Selector & Wizard)
    console.print("\n[bold cyan]3. Select Tunnel Protocol & Engine:[/bold cyan]")
    console.print("  [bold green][1] 🛡️  Most stable & anti-filter (default recommendation):[/bold green] [bold]PCK[/bold] [dim](resilient to network disruption, anti-RST, no drops)[/dim]")
    console.print("  [bold cyan][2] 🎮  Gaming & lowest ping (high packet loss):[/bold cyan] [bold]Quantum KCP[/bold] [dim](smart Fast-ARQ delivery for minimal ping and jitter)[/dim]")
    console.print("  [bold magenta][3] ☁️  Traverse Cloudflare CDN (web camouflage):[/bold magenta] [bold]WSS TLS 1.3[/bold] [dim](standard WebSocket traffic over a domain)[/dim]")
    console.print("  [bold blue][4] ⚡  Direct kernel layer-3 network:[/bold blue] [bold]WireGuard[/bold] [dim](max speed and efficiency via Linux kernel driver)[/dim]")
    console.print("  [bold red][5] 🚨  Emergency & national intranet:[/bold red] [bold]Slipstream DNS[/bold] [dim](tunnels over DNS port 53 during full international outages)[/dim]")
    console.print("  [bold yellow][0] 📋  Full expert menu (view and pick from all 40 protocols)[/bold yellow]")
    
    wizard_choice = Prompt.ask("Select profile or enter '0' for full list", choices=["1", "2", "3", "4", "5", "0"], default="1")
    
    if wizard_choice == "1":
        selected_transport = "pck"
    elif wizard_choice == "2":
        selected_transport = "quantum"
    elif wizard_choice == "3":
        selected_transport = "wss"
    elif wizard_choice == "4":
        selected_transport = "wireguard"
    elif wizard_choice == "5":
        selected_transport = "slipstream"
    else:
        console.print("\n[bold cyan]--- All Supported Transports (40 Engines) ---[/bold cyan]")
        for k, v in SUPPORTED_TRANSPORTS.items():
            console.print(f"  [{k}] {v[1]}")
        tr_choice = Prompt.ask("Select protocol number", choices=list(SUPPORTED_TRANSPORTS.keys()), default="3")
        selected_transport = SUPPORTED_TRANSPORTS[tr_choice][0]
    
    console.print(f"[bold green]Selected Transport: {selected_transport}[/bold green]\n")
    gre_options = {"gre_mtu": Prompt.ask("GRE MTU (576-1400)", default="1400")} if selected_transport == "gre" else {}

    if selected_transport in {'xhttp','gre_xhttp'}:
        tls_name=Prompt.ask("TLS server name on Kharej")
        settings={'server_name':tls_name,'binary':Prompt.ask("Xray binary path on both servers",default='/usr/local/bin/xray'),
                  'port':Prompt.ask("Preferred outer port on Kharej",default='443')}
        if selected_transport in {'xhttp','gre_xhttp'}:
            settings['certificate']=Prompt.ask("Certificate chain on Kharej",default='/etc/letsencrypt/live/'+tls_name+'/fullchain.pem')
            settings['key']=Prompt.ask("Private key file on Kharej",default='/etc/letsencrypt/live/'+tls_name+'/privkey.pem')
        gre_options={'camouflage':settings}
    elif selected_transport == 'waterwall':
        tls_name = Prompt.ask("TLS server name on Kharej (SNI / domain)")
        settings = {
            'server_name': tls_name,
            'binary': Prompt.ask("WaterWall binary path on both servers", default='/usr/local/bin/waterwall'),
            'port': Prompt.ask("Preferred outer port on Kharej", default='443'),
            'certificate': Prompt.ask("Certificate chain on Kharej", default='/etc/letsencrypt/live/' + tls_name + '/fullchain.pem'),
            'key': Prompt.ask("Private key file on Kharej", default='/etc/letsencrypt/live/' + tls_name + '/privkey.pem')
        }
        gre_options = {'camouflage': settings}
    elif selected_transport == 'paqet':
        settings = {
            'tunnel_port': Prompt.ask("Preferred Paqet raw KCP port on Kharej", default='9999'),
            'binary': Prompt.ask("Paqet binary path on both servers", default='/usr/local/bin/paqet'),
            'cipher': Prompt.ask("Cipher (aes-128-gcm / chacha20-poly1305 / none)", default='aes-128-gcm'),
            'kcp_mode': Prompt.ask("KCP mode (fast / normal / manual)", default='fast')
        }
        gre_options = {'camouflage': settings}
    elif selected_transport == 'geneve_ipsec':
        vni_in = Prompt.ask("VNI (1-16777215, default auto)", default="")
        mtu_in = Prompt.ask("Geneve MTU (576-1420)", default="1400")
        try:
            mtu_val = int(mtu_in) if mtu_in else 1400
        except ValueError:
            mtu_val = 1400
        vni_val = int(vni_in) if vni_in.isdigit() else None
        gre_options = {"geneve_mtu": mtu_val, "vni": vni_val}
    elif selected_transport == 'vxlan':
        console.print("\n[bold yellow]Security warning: VXLAN is completely raw with no encryption or obfuscation (RFC 7348).[/bold yellow]")
        console.print("[dim]Status: experimental; no encryption/obfuscation — kernel link test verified.[/dim]")
        console.print("\n[bold cyan]VXLAN reference profiles:[/bold cyan]")
        console.print("  [1] P2P: direct point-to-point (Point-to-Point Unicast - no bridge)")
        console.print("  [2] Bridge + IP Pointing: dedicated bridge pointing at remote IP")
        console.print("  [3] Bridge + FDB: dedicated bridge with forwarding table (FDB Unicast)")
        method_choice = Prompt.ask("Select method", choices=["1", "2", "3"], default="1")
        method_map = {"1": "p2p", "2": "bridge_pointip", "3": "fdb_bridge"}
        vx_method = method_map[method_choice]
        vni_in = Prompt.ask("VNI (1-16777215)", default="1000")
        vni_val = int(vni_in) if vni_in.isdigit() else 1000
        port_in = Prompt.ask("Destination UDP port (RFC 7348)", default="4789")
        port_val = int(port_in) if port_in.isdigit() else 4789
        mtu_in = Prompt.ask("Interface MTU (576-1450)", default="1400")
        mtu_val = int(mtu_in) if mtu_in.isdigit() else 1400
        br_name = None
        if vx_method in {"bridge_pointip", "fdb_bridge"}:
            br_name = Prompt.ask("Dedicated bridge name (optional; leave empty for auto)", default="")
            br_name = br_name.strip() or None
        gre_options = {
            "vxlan_method": vx_method,
            "vni": vni_val,
            "dst_port": port_val,
            "vxlan_mtu": mtu_val,
            "bridge_name": br_name
        }
    elif selected_transport == 'gre6':
        console.print("\n[bold yellow]Security warning: GRE6 is completely raw with no encryption or obfuscation (RFC 7676).[/bold yellow]")
        console.print("[dim]Status: experimental — no encryption or obfuscation.[/dim]")
        from core.ipv6_tunnel_tools import validate_ipv6_address
        try:
            validate_ipv6_address(selected_kharej.get("ip"))
            for s in selected_irans:
                validate_ipv6_address(s.get("ip"))
        except ValueError as e:
            console.print(f"[bold red]Error: Invalid IPv6 address: {e}[/bold red]")
            time.sleep(2)
            return
        mtu_in = Prompt.ask("GRE6 MTU (1200-1440)", default="1400")
        try:
            mtu_val = int(mtu_in) if mtu_in else 1400
        except ValueError:
            mtu_val = 1400
        gre_options = {"gre6_mtu": mtu_val}
    elif selected_transport == 'ip6ip6':
        console.print("\n[bold yellow]Security warning: IP6IP6 is completely raw with no encryption or obfuscation (RFC 2473).[/bold yellow]")
        console.print("[dim]Status: experimental — no encryption or obfuscation. Internal addressing is IPv6-only.[/dim]")
        from core.ipv6_tunnel_tools import validate_ipv6_address
        try:
            validate_ipv6_address(selected_kharej.get("ip"))
            for s in selected_irans:
                validate_ipv6_address(s.get("ip"))
        except ValueError as e:
            console.print(f"[bold red]Error: Invalid IPv6 address: {e}[/bold red]")
            time.sleep(2)
            return
        mtu_in = Prompt.ask("IP6IP6 MTU (1280-1460)", default="1420")
        try:
            mtu_val = int(mtu_in) if mtu_in else 1420
        except ValueError:
            mtu_val = 1420
        gre_options = {"ip6ip6_mtu": mtu_val}
    elif selected_transport == 'wireguard':
        console.print("\n[bold yellow]Warning: WireGuard status: experimental — live probe not run[/bold yellow]")
        console.print("[dim]Layer-3 link based on Curve25519/ChaCha20-Poly1305. Official kernel WireGuard driver test not run yet.[/dim]")
        port_in = Prompt.ask("WireGuard listen port (UDP)", default="51820")
        port_val = int(port_in) if port_in.isdigit() else 51820
        mtu_in = Prompt.ask("WireGuard MTU (576-1420)", default="1420")
        mtu_val = int(mtu_in) if mtu_in.isdigit() else 1420
        psk_in = Prompt.ask("Enable PresharedKey (y/n)", choices=["y", "n"], default="n")
        gre_options = {
            "tunnel_port": port_val,
            "wireguard_port": port_val,
            "mtu": mtu_val,
            "wireguard_mtu": mtu_val,
            "enable_psk": (psk_in.lower() == "y"),
        }

    elif selected_transport == 'slipstream':
        console.print("[yellow]Slipstream experimental: DNS path with mutually-TLS relay; delegation must be configured beforehand.[/yellow]")
        gre_options = {
            "domain": Prompt.ask("Delegated DNS domain"),
            "resolvers": [value.strip() for value in Prompt.ask("DNS resolvers (comma separated)", default="1.1.1.1:53,8.8.8.8:53").split(",") if value.strip()],
            "dns_port": Prompt.ask("Kharej server DNS port", default="53"),
            "rate_limit": Prompt.ask("Max QPS per source IP (10-2000)", default="1000"),
        }

    # 4. Forwarded Client/Config Ports
    console.print("\n[bold cyan]4. Forwarded Client Service Ports:[/bold cyan]")
    console.print("[dim]Note: These are the ports your users/configs connect to (e.g. 2222 or 443, 2053, 2083).[/dim]")
    console.print("[dim]BackPack ports or GRE private addresses will be assigned automatically.[/dim]")
    ports_input = Prompt.ask("Enter client ports (comma-separated)", default="2222")
    client_ports = [p.strip() for p in ports_input.split(",") if p.strip()]

    # Summary Confirmation
    console.print("\n" + "="*50)
    console.print(f"[bold yellow]Deployment Summary:[/bold yellow]")
    console.print(f"• Pool Name: [bold]{pool_name}[/bold]")
    console.print(f"• Destination Kharej: [bold]{selected_kharej['name']} ({selected_kharej['ip']})[/bold]")
    console.print(f"• Iran Nodes Count: [bold]{len(selected_irans)}[/bold]")
    console.print(f"• Protocol: [bold]{selected_transport}[/bold]")
    console.print(f"• Client Ports: [bold]{', '.join(client_ports)}[/bold]")
    console.print("="*50 + "\n")

    if not Confirm.ask("Start load balancer deployment?", default=True):
        return

    def log_callback(msg: str):
        console.print(f"  [cyan]•[/cyan] {msg}")

    with console.status("[bold green]Deploying tunnels and configuring load balancer...[/bold green]"):
        ok, msg, pool_data = LoadBalancerManager.create_pool(
            pool_name=pool_name,
            kharej_server=selected_kharej,
            iran_servers=selected_irans,
            transport=selected_transport,
            client_ports=client_ports,
            callback=log_callback,
            **gre_options
        )

    if ok:
        show_pool_success_summary(pool_data)
    else:
        console.print(f"\n[bold red]Error: Deployment failed: {msg}[/bold red]")

    Prompt.ask("\nPress Enter to continue")

def show_pool_success_summary(pool_data: dict):
    console.print("\n" + "🎉"*25)
    console.print(Panel("[bold green]Load Balancer deployed and tunnels are active![/bold green]", border_style="green"))

    # Active Iran IPs Table
    table = Table(title="Active Iran Nodes in Load Balancer Pool", show_lines=True)
    table.add_column("Node Name", style="white")
    table.add_column("Iran Server IP", style="bold yellow")
    table.add_column("Auto Tunnel Port", style="cyan")
    table.add_column("Tunnel Status", style="bold green")

    active_ips = []
    for node in pool_data["nodes"]:
        active_ips.append(node["ip"])
        # show the real per-node status instead of hardcoding green.
        status = node.get("status", "active")
        status_txt = "🟢 Active" if status == "active" else f"🟡 {status}"
        t_port = str(node.get("tunnel_port") or (node.get("waterwall",{}).get("outer_port") if node.get("waterwall") else None) or (node.get("paqet",{}).get("tunnel_port") if node.get("paqet") else None) or (node.get("vxlan",{}).get("local_private") if node.get("vxlan") else None) or (node.get("wireguard",{}).get("local_private") if node.get("wireguard") else None) or (node.get("geneve",{}).get("local_private") if node.get("geneve") else None) or (node.get("gre6",{}).get("local_private") if node.get("gre6") else None) or (node.get("ip6ip6",{}).get("local_private") if node.get("ip6ip6") else None) or node.get("gre",{}).get("local_private", "-"))
        table.add_row(node["server_name"], node["ip"], t_port, status_txt)

    console.print(table)

    # Load Balancing Instructions
    ports_str = ", ".join(pool_data["client_ports"])
    # Prefer the pool's own Cloudflare config; fall back to the global one.
    pool_cf = pool_data.get("cloudflare") or {}
    cf_cfg = pool_cf if pool_cf.get("subdomain") else (load_data().get("cloudflare") or {})
    subdomain = cf_cfg.get("subdomain", "lb.example.com")

    guide_text = f"""[bold yellow]📌 Connection Endpoints & DNS Auto-Failover:[/bold yellow]

[bold white]1. Subdomain with Auto-Failover (Cloudflare):[/bold white]
Connect users to: [bold green]{subdomain}:{ports_str}[/bold green]
The Watchdog automatically points this subdomain only to the verified, unblocked IP(s)!

[bold white]2. Direct IP Setup:[/bold white]
[bold yellow]{', '.join(active_ips)}[/bold yellow]
"""
    console.print(Panel(guide_text, title="Configuration Endpoints", border_style="cyan"))

def diagnose_pool_flow(pool_name: str):
    pools = get_pools()
    pool = pools.get(pool_name)
    if not pool:
        console.print("[red]Pool not found.[/red]")
        return

    console.print(f"\n[bold cyan]🩺 Live End-to-End Diagnostic for Pool: [white]{pool_name}[/white][/bold cyan]")
    console.print("[dim]Multi-stage check: 1) SSH connectivity  2) tunnel interface/service  3) outbound port reachability  4) latency and data transfer[/dim]\n")

    kh_srv = pool.get("kharej_server", {})
    client_ports = pool.get("client_ports", ["2222"])
    nodes = pool.get("nodes", [])

    # Step 1: Probe Kharej
    console.print(f"[bold yellow]1. Checking Kharej destination server ({kh_srv.get('ip')})...[/bold yellow]")
    kh_ssh = SSHManager.from_server(kh_srv, timeout=8)
    ok_kh, msg_kh = kh_ssh.connect()
    if not ok_kh:
        console.print(f"  [bold red]❌ SSH access to Kharej server failed:[/bold red] {msg_kh}")
        console.print("  [dim]💡 Please verify the Kharej server is up and SSH port/firewall allow access.[/dim]\n")
        Prompt.ask("Press Enter to return")
        return
    else:
        console.print(f"  [bold green]✅ SSH connection to Kharej server established.[/bold green]")

    # Check listening backend ports on Kharej
    port_status_kh = {}
    from core.validation import shquote
    for p in client_ports:
        code, out, _ = kh_ssh.execute(f"ss -tulpn 2>/dev/null | grep ':{shquote(p)} ' || netstat -tulpn 2>/dev/null | grep ':{shquote(p)} ' || true")
        is_listening = bool(out.strip())
        port_status_kh[p] = is_listening
        if is_listening:
            console.print(f"  [green]  • Port {p} is active on the Kharej server and a program is listening (LISTEN).[/green]")
        else:
            console.print(f"  [yellow]  • ⚠️ Port {p} is DOWN on the Kharej server! No program (e.g. Xray/V2Ray) is listening on it.[/yellow]")
            console.print(f"    [dim]💡 Note: the tunnel will connect, but clients won't work until you start the destination service.[/dim]")

    kh_ssh.close()

    # Step 2: Probe each Iran node
    console.print(f"\n[bold yellow]2. Checking Iran server nodes ({len(nodes)} nodes)...[/bold yellow]")
    diag_table = Table(title=f"Comprehensive pool diagnostics report: {pool_name}", show_lines=True)
    diag_table.add_column("Node IP", style="cyan")
    diag_table.add_column("SSH conn", style="white")
    diag_table.add_column("Tunnel svc", style="white")
    diag_table.add_column("Client ports", style="white")
    diag_table.add_column("Ping latency", style="white")
    diag_table.add_column("Final verdict", style="bold")

    for node in nodes:
        node_ip = node.get("ip")
        node_name = node.get("node_name", "")
        ir_ssh = SSHManager.from_server(node, timeout=8)
        ok_ir, msg_ir = ir_ssh.connect()
        if not ok_ir:
            diag_table.add_row(
                node_ip,
                "[red]❌ DOWN[/red]",
                "[dim]-[/dim]",
                "[dim]-[/dim]",
                "[dim]-[/dim]",
                "[bold red]❌ Iran server unreachable[/bold red]"
            )
            continue

        transport = pool.get("transport", "pck")
        engine = pool.get("engine", transport)
        service_name = f"backpack-{node_name}.service"
        if engine in ("paqet", "waterwall", "slipstream", "wireguard", "vxlan", "gre", "geneve_ipsec"):
            service_name = f"vxlb-{engine}-{node_name}.service"

        code_svc, out_svc, _ = ir_ssh.execute(f"systemctl is-active {shquote(service_name)} 2>/dev/null || systemctl is-active {shquote(f'backpack-{node_name}.service')} 2>/dev/null || echo 'inactive'")
        svc_active = (out_svc.strip() == "active")
        svc_str = "[green]🟢 active[/green]" if svc_active else f"[red]🔴 {out_svc.strip()}[/red]"

        ports_open = []
        for p in client_ports:
            c_p, out_p, _ = ir_ssh.execute(f"ss -tulpn 2>/dev/null | grep ':{shquote(p)} ' || netstat -tulpn 2>/dev/null | grep ':{shquote(p)} ' || true")
            if out_p.strip():
                ports_open.append(p)
        ports_str = f"[green]🟢 open ({', '.join(ports_open)})[/green]" if ports_open else "[yellow]🟡 pending[/yellow]"

        code_ping, out_ping, _ = ir_ssh.execute(f"ping -c 2 -W 2 {kh_srv.get('ip')} 2>/dev/null | grep 'rtt' || true")
        latency_str = "[dim]N/A[/dim]"
        if out_ping.strip():
            try:
                avg_lat = out_ping.strip().split("/")[4]
                latency_str = f"[cyan]{float(avg_lat):.1f} ms[/cyan]"
            except Exception:
                latency_str = "[green]✓ connected[/green]"

        ir_ssh.close()

        all_backend_listening = all(port_status_kh.values()) if port_status_kh else False
        if svc_active and ports_open and all_backend_listening:
            verdict = "[bold green]🟢 fully healthy, ready for traffic[/bold green]"
        elif svc_active and ports_open and not all_backend_listening:
            verdict = "[bold yellow]🟡 tunnel OK / Kharej service down[/bold yellow]"
        elif svc_active and not ports_open:
            verdict = "[bold yellow]🟡 Service up / port unreachable[/bold yellow]"
        else:
            verdict = "[bold red]🔴 Tunnel inactive[/bold red]"

        diag_table.add_row(
            node_ip,
            "[green]✅ connected[/green]",
            svc_str,
            ports_str,
            latency_str,
            verdict
        )

    console.print(diag_table)
    console.print("\n[dim]Status legend:[/dim]")
    console.print("  [bold green]🟢 Fully healthy:[/bold green] the tunnel link and the Kharej server software are both active and working.")
    console.print("  [bold yellow]🟡 Tunnel OK / Kharej service down:[/bold yellow] the tunnel itself is fine; just start your proxy or target service on the Kharej server.")
    console.print("  [bold red]🔴 Error:[/bold red] the tunnel service is not running (review system logs in the load balancer manager).")
    Prompt.ask("\nPress Enter to return")

def manage_pools_menu():
    while True:
        show_banner()
        pools = get_pools()
        console.print("[bold green]=== Load Balancer Pools Management ===[/bold green]\n")

        if not pools:
            console.print("[yellow]No load balancers currently configured.[/yellow]\n")
            console.print("  [0] 🔙 Back to Main Menu")
            Prompt.ask("\nPress Enter to return")
            break

        table = Table(title="Active Load Balancers", show_lines=True)
        table.add_column("#", style="dim", width=5)
        table.add_column("Pool Name", style="bold cyan")
        table.add_column("Kharej Server", style="blue")
        table.add_column("Iran Nodes", style="yellow")
        table.add_column("Protocol", style="white")
        table.add_column("Client Ports", style="green")

        pool_list = list(pools.values())
        for idx, p in enumerate(pool_list, 1):
            table.add_row(
                str(idx),
                p["name"],
                p["kharej_server"]["ip"],
                str(len(p.get("nodes", []))),
                p["transport"],
                ", ".join(p.get("client_ports", []))
            )
        console.print(table)

        console.print("\n[bold]Operations:[/bold]")
        console.print("  [V] 🔍 View Details & IP Endpoints")
        console.print("  [E] 🩺 Live Health Check & Diagnostics (live troubleshooting and fault isolation)")
        console.print("  [A] ➕ Add New Iran Server to Pool")
        console.print("  [R] ➖ Remove an Iran Server from Pool")
        console.print("  [P] 🔌 Manage Client Ports (Add / Remove Forwarded Ports)")
        console.print("  [T] Change Tunnel Transport (Rolling Change / Rollback)")
        console.print("  [C] Configure Cloudflare DNS for this Pool (Subdomain & Token)")
        console.print("  [D] 🗑️  Delete Entire Load Balancer Pool")
        console.print("  [0] 🔙 Back to Main Menu\n")

        action = Prompt.ask("Select an operation", choices=["V", "E", "A", "R", "P", "C", "D", "T", "0", "v", "e", "a", "r", "p", "c", "d", "t"], default="V").upper()

        if action == "0":
            break
        elif action == "V":
            sel = Prompt.ask("Choose load balancer index", choices=[str(i) for i in range(1, len(pool_list)+1)])
            show_pool_success_summary(pool_list[int(sel)-1])
            Prompt.ask("\nPress Enter to return")
        elif action == "E":
            sel = Prompt.ask("Choose load balancer index", choices=[str(i) for i in range(1, len(pool_list)+1)])
            diagnose_pool_flow(pool_list[int(sel)-1]["name"])
        elif action == "T":
            sel = Prompt.ask("Choose load balancer index", choices=[str(i) for i in range(1, len(pool_list)+1)])
            change_pool_transport_flow(pool_list[int(sel)-1]["name"])
        elif action == "A":
            sel = Prompt.ask("Choose load balancer index", choices=[str(i) for i in range(1, len(pool_list)+1)])
            add_node_to_pool_flow(pool_list[int(sel)-1]["name"])
        elif action == "R":
            sel = Prompt.ask("Choose load balancer index", choices=[str(i) for i in range(1, len(pool_list)+1)])
            remove_node_from_pool_flow(pool_list[int(sel)-1]["name"])
        elif action == "P":
            sel = Prompt.ask("Choose load balancer index", choices=[str(i) for i in range(1, len(pool_list)+1)])
            manage_pool_ports_flow(pool_list[int(sel)-1]["name"])
        elif action == "C":
            with mutation_lock():
                if transport_busy():
                    console.print("Tunnel change or rollback is in progress; pool operations are locked.")
                    continue
                sel = Prompt.ask("Choose load balancer index", choices=[str(i) for i in range(1, len(pool_list)+1)])
                target_pool = pool_list[int(sel)-1]
                p_name = target_pool["name"]
                existing_cf = target_pool.get("cloudflare") or load_data().get("cloudflare") or {}
                console.print(f"\n[bold cyan]Configure Independent Cloudflare DNS for Pool '{p_name}':[/bold cyan]")
                tok = Prompt.ask("Cloudflare API Token", password=True, default=existing_cf.get("api_token", ""))
                zid = Prompt.ask("Zone ID", default=existing_cf.get("zone_id", ""))
                scope = Prompt.ask("DNS scope: single record or all existing A subdomains", choices=['single','all_subdomains'], default=existing_cf.get('scope','single'))
                sub = Prompt.ask("Root domain" if scope == 'all_subdomains' else "Subdomain for this pool (e.g. pool-a.example.com)", default=existing_cf.get("subdomain", f"{p_name.lower()}.example.com"))
                if scope == 'all_subdomains':
                    sub = sub.lower().strip().removeprefix('*.').rstrip('.')
                    preview = CloudflareManager(tok,zid).subdomain_records(sub)
                    if not preview.get('success') or not preview.get('names'):
                        console.print('[red]No A subdomain records found or provider read failed; nothing saved.[/red]')
                        Prompt.ask("Press Enter to continue")
                        continue
                    console.print('All existing and future A subdomains will use this pool with DNS-only records. Apex, CNAME and AAAA are excluded.')
                    for r in preview['records']: console.print(f"{r['name']} -> {r['content']}", markup=False)
                    if not Confirm.ask('Activate management of all these A subdomains?', default=False): continue
                ok, msg = LoadBalancerManager.set_pool_cloudflare(p_name, tok, zid, sub, enabled=True, scope=scope)
                if ok:
                    console.print(f"[bold green]Success: {msg}[/bold green]")
                else:
                    console.print(f"[bold red]Error: {msg}[/bold red]")
                Prompt.ask("\nPress Enter to continue")
        elif action == "D":
            with mutation_lock():
                if transport_busy():
                    console.print("Tunnel change or rollback is in progress; pool operations are locked.")
                    continue
                sel = Prompt.ask("Choose load balancer index to delete", choices=[str(i) for i in range(1, len(pool_list)+1)])
                target_name = pool_list[int(sel)-1]["name"]
                if Confirm.ask(f"Are you sure you want to delete load balancer '{target_name}'?", default=False):
                    with console.status("Tearing down tunnels and services..."):
                        _, msg = LoadBalancerManager.delete_entire_pool(target_name)
                    console.print(f"[bold green]{msg}[/bold green]")
                    time.sleep(1.5)

def change_pool_transport_flow(pool_name: str):
    pool = get_pools().get(pool_name)
    if not pool:
        console.print("Pool no longer exists.")
        return
    if pool.get("transport") == "gre":
        from core.gre import change_mtu, recover_update
        if pool.get('gre_update',{}).get('status') == 'rollback_failed':
            with mutation_lock():ok,message=recover_update(pool_name)
        else:
            mtu=Prompt.ask("GRE MTU (576-1400)",default=str(pool.get('gre_mtu',1400)))
            with mutation_lock():ok,message=change_mtu(pool_name,mtu)
        console.print(message,markup=False)
        return
    if pool.get("transport") in ("geneve", "geneve_ipsec") or pool.get("engine") in ("geneve", "geneve_ipsec"):
        from core.geneve import change_mtu
        mtu = Prompt.ask("Geneve MTU (576-1420)", default=str(pool.get('geneve_mtu', 1400)))
        with mutation_lock():
            ok, message = change_mtu(pool_name, mtu)
        console.print(message, markup=False)
        return
    if pool.get("transport") == "vxlan" or pool.get("engine") == "vxlan":
        import json as _json
        from core.vxlan_adapter import change_mtu, pool_status
        console.print(f"[bold cyan]VXLAN pool management ({pool_name}):[/bold cyan]")
        console.print("  [1] View live interface status and FDB")
        console.print("  [2] Change VXLAN interfaces MTU")
        vx_action = Prompt.ask("Select operation", choices=["1", "2"], default="1")
        if vx_action == "1":
            ok, msg, st = pool_status(pool_name)
            console.print(f"Result: {msg}")
            for ip, data in st.items():
                console.print(f"Node {ip}: {_json.dumps(data, indent=2, ensure_ascii=False)}")
        else:
            mtu = Prompt.ask("VXLAN MTU (576-1450)", default=str(pool.get('vxlan_mtu', 1400)))
            with mutation_lock():
                ok, message = change_mtu(pool_name, int(mtu))
            console.print(message, markup=False)
        return
    if pool.get("transport") == "gre6" or pool.get("engine") == "gre6":
        import json as _json
        from core.gre6 import change_mtu, pool_status
        console.print(f"[bold cyan]GRE6 pool management ({pool_name}):[/bold cyan]")
        console.print("[dim]Status: experimental — no encryption or obfuscation (Cleartext over IPv6)[/dim]")
        console.print("  [1] View live interface status")
        console.print("  [2] Change GRE6 interfaces MTU")
        action = Prompt.ask("Select operation", choices=["1", "2"], default="1")
        if action == "1":
            ok, msg, st = pool_status(pool_name)
            console.print(f"Result: {msg}")
            for ip, data in st.items():
                console.print(f"Node {ip}: {_json.dumps(data, indent=2, ensure_ascii=False)}")
        else:
            mtu = Prompt.ask("GRE6 MTU (1200-1440)", default=str(pool.get('gre6_mtu', 1400)))
            with mutation_lock():
                ok, message = change_mtu(pool_name, int(mtu))
            console.print(message, markup=False)
        return
    if pool.get("transport") == "ip6ip6" or pool.get("engine") == "ip6ip6":
        import json as _json
        from core.ip6ip6 import change_mtu, pool_status
        console.print(f"[bold cyan]IP6IP6 pool management ({pool_name}):[/bold cyan]")
        console.print("[dim]Status: experimental — no encryption or obfuscation (Cleartext over IPv6)[/dim]")
        console.print("  [1] View live interface status")
        console.print("  [2] Change IP6IP6 interfaces MTU")
        action = Prompt.ask("Select operation", choices=["1", "2"], default="1")
        if action == "1":
            ok, msg, st = pool_status(pool_name)
            console.print(f"Result: {msg}")
            for ip, data in st.items():
                console.print(f"Node {ip}: {_json.dumps(data, indent=2, ensure_ascii=False)}")
        else:
            mtu = Prompt.ask("IP6IP6 MTU (1280-1460)", default=str(pool.get('ip6ip6_mtu', 1420)))
            with mutation_lock():
                ok, message = change_mtu(pool_name, int(mtu))
            console.print(message, markup=False)
        return
    if pool.get("transport") == "wireguard" or pool.get("engine") == "wireguard":
        import json as _json
        from core.wireguard_adapter import change_mtu, pool_status, probe_pool
        console.print(f"[bold cyan]WireGuard pool management ({pool_name}):[/bold cyan]")
        console.print("[dim]Status: experimental — live probe not run[/dim]")
        console.print("  [1] View live interface status and dump")
        console.print("  [2] Run active nonce round-trip challenge probe")
        console.print("  [3] Change WireGuard interfaces MTU")
        wg_action = Prompt.ask("Select operation", choices=["1", "2", "3"], default="1")
        if wg_action == "1":
            ok, msg, st = pool_status(pool_name)
            console.print(f"Result: {msg}")
            for ip, data in st.items():
                console.print(f"Node {ip}: {_json.dumps(data, indent=2, ensure_ascii=False)}")
        elif wg_action == "2":
            with console.status("Sending nonce and verifying response..."):
                res = probe_pool(pool_name)
            if res.get("passed"):
                console.print(f"[bold green]Success: probe passed: latency {res.get('latency_ms', 1.0)}ms[/bold green]")
            else:
                console.print(f"[bold red]Error: probe failed: {res.get('error')}[/bold red]")
        else:
            mtu = Prompt.ask("WireGuard MTU (576-1420)", default=str(pool.get('wireguard_mtu', 1420)))
            with mutation_lock():
                ok, message = change_mtu(pool_name, int(mtu))
            console.print(message, markup=False)
        return
    if pool.get('engine') == 'xray':
        if pool.get('transport_change',{}).get('status')=='rollback_failed':
            from core.https_tunnel import change_ports
            with mutation_lock():ok,message=change_ports(pool_name,pool['client_ports'],recovery=True)
            console.print(message,markup=False)
        else:console.print('HTTPS is an independent engine; create a new pool to change its security mode.')
        return
    job = pool.get("transport_change") or {}
    if job.get("status") == "rollback_failed":
        console.print("Previous rollback is incomplete; new changes remain locked.")
        if Confirm.ask("Retry restoring the original configurations on both sides?", default=False):
            with mutation_lock():
                current = (get_pools().get(pool_name) or {}).get("transport_change") or {}
                if current.get("status") != "rollback_failed":
                    console.print("Rollback is already running or no longer needed.")
                    return
                update_job(pool_name, status="rolling_back", message="Retrying restoration from terminal")
            with console.status("Restoring original tunnel configurations..."):
                run_change(pool_name, recovering=True)
        else:
            return
    else:
        console.print(f"Current transport: {pool.get('transport')} | Nodes: {len(pool.get('nodes', []))}", markup=False)
        choices = {key: value for key, value in SUPPORTED_TRANSPORTS.items() if value[0] != pool.get('transport') and value[0] not in {"gre","xhttp","gre_xhttp","reality","waterwall","paqet","geneve_ipsec","vxlan","gre6","ip6ip6","wireguard"}}
        for key, (_, label) in choices.items():
            console.print(f"  [{key}] {label}", markup=False)
        console.print("  [0] Return", markup=False)
        selected = Prompt.ask("New tunnel transport", choices=[*choices, "0"])
        if selected == "0":
            return
        console.print("Nodes change one at a time. Existing connections may disconnect during restart.\n"
                      "A private round-trip probe verifies forwarding; no active user is required.\n"
                      "On failure, all changed nodes revert. Members, tokens, ports and DNS settings are preserved.\n"
                      "Pool operations are locked and DNS synchronization for this domain pauses during the change.")
        if not Confirm.ask("Start the rolling transport change?", default=False):
            return
        with mutation_lock():
            ok, message = start_change(pool_name, choices[selected][0], background=False)
        if not ok:
            console.print(message, markup=False)
            return
        with console.status("Changing tunnel transport and verifying fresh traffic..."):
            run_change(pool_name)
    result = (get_pools().get(pool_name) or {}).get("transport_change") or {}
    console.print(f"Status: {result.get('status')} — {result.get('message', '')}", markup=False)
    if result.get("error"):
        console.print(result["error"], markup=False)
    Prompt.ask("\nPress Enter to continue")

@pool_mutation_flow
def manage_pool_ports_flow(pool_name: str):
    while True:
        pools = get_pools()
        if pool_name not in pools:
            break
        pool = pools[pool_name]
        current_ports = pool.get("client_ports", [])

        console.print(f"\n[bold green]=== Forwarded Client Ports for '{pool_name}' ===[/bold green]")
        console.print(f"Current Active Ports: [bold yellow]{', '.join(current_ports)}[/bold yellow]\n")

        console.print("  [1] ➕ Add New Forwarded Port(s)")
        console.print("  [2] ➖ Remove a Forwarded Port")
        console.print("  [0] 🔙 Back to Pool Operations\n")

        opt = Prompt.ask("Select option", choices=["1", "2", "0"], default="1")

        if opt == "0":
            break
        elif opt == "1":
            raw_input = Prompt.ask("Enter port(s) to add (comma-separated, e.g. 443, 8080)")
            new_ports = []
            for p in raw_input.split(","):
                p = p.strip()
                if p.isdigit() and 1 <= int(p) <= 65535:
                    if p not in current_ports and p not in new_ports:
                        new_ports.append(p)
                else:
                    console.print(f"[red]Invalid port number: {p}[/red]")
            
            if not new_ports:
                console.print("[yellow]No new valid ports entered.[/yellow]")
                time.sleep(1.5)
                continue

            def log_cb(msg: str):
                console.print(f"  [cyan]•[/cyan] {msg}")

            with console.status("Applying new ports to all Iran nodes..."):
                ok, msg = LoadBalancerManager.add_client_ports(pool_name, new_ports, callback=log_cb)

            if ok:
                console.print(f"[bold green]Success: {msg}[/bold green]")
            else:
                console.print(f"[bold red]Error: {msg}[/bold red]")
            Prompt.ask("\nPress Enter to continue")

        elif opt == "2":
            if len(current_ports) <= 1:
                console.print("[yellow]Cannot remove: this pool only has 1 port. A pool must have at least one active port.[/yellow]")
                Prompt.ask("\nPress Enter to continue")
                continue

            console.print("\n[bold cyan]Select port to remove:[/bold cyan]")
            for idx, p in enumerate(current_ports, 1):
                console.print(f"  [{idx}] Port {p}")
            
            p_sel = Prompt.ask("Choose port index", choices=[str(i) for i in range(1, len(current_ports)+1)])
            target_port = current_ports[int(p_sel)-1]

            if Confirm.ask(f"Remove port {target_port} from all Iran nodes in '{pool_name}'?", default=True):
                def log_cb(msg: str):
                    console.print(f"  [cyan]•[/cyan] {msg}")

                with console.status(f"Removing port {target_port} from all nodes..."):
                    ok, msg = LoadBalancerManager.remove_client_port(pool_name, target_port, callback=log_cb)

                if ok:
                    console.print(f"[bold green]Success: {msg}[/bold green]")
                else:
                    console.print(f"[bold red]Error: {msg}[/bold red]")
                Prompt.ask("\nPress Enter to continue")

@pool_mutation_flow
def add_node_to_pool_flow(pool_name: str):
    iran_srvs = get_servers("iran")
    pools = get_pools()
    current_ips = [n["ip"] for n in pools[pool_name].get("nodes", [])]

    available = [s for s in iran_srvs if s["ip"] not in current_ips]
    if not available:
        console.print("[yellow]All registered Iran servers are already part of this pool. Add a new server first via Server Management.[/yellow]")
        Prompt.ask("\nPress Enter to return")
        return

    console.print(f"\n[bold cyan]Select new Iran server to add to '{pool_name}':[/bold cyan]")
    for idx, s in enumerate(available, 1):
        console.print(f"  [{idx}] {s['name']} ({s['ip']})")

    sel = Prompt.ask("Choose server index", choices=[str(i) for i in range(1, len(available)+1)])
    selected_srv = available[int(sel)-1]

    def log_cb(msg: str):
        console.print(f"  [cyan]•[/cyan] {msg}")

    with console.status(f"Attaching node {selected_srv['name']} to load balancer..."):
        ok, msg = LoadBalancerManager.add_node(pool_name, selected_srv, callback=log_cb)

    if ok:
        console.print(f"[bold green]Success: {msg}[/bold green]")
    else:
        console.print(f"[bold red]Error: {msg}[/bold red]")
    time.sleep(2)

@pool_mutation_flow
def remove_node_from_pool_flow(pool_name: str):
    pools = get_pools()
    nodes = pools[pool_name].get("nodes", [])

    if len(nodes) <= 1:
        console.print("[bold red]Warning: This pool only has 1 node left. To remove all, use Delete Entire Pool option.[/bold red]")
        time.sleep(2)
        return

    console.print(f"\n[bold yellow]Select node to remove from '{pool_name}':[/bold yellow]")
    for idx, n in enumerate(nodes, 1):
        console.print(f"  [{idx}] {n['server_name']} ({n['ip']})")

    sel = Prompt.ask("Choose node index to remove", choices=[str(i) for i in range(1, len(nodes)+1)])
    target_ip = nodes[int(sel)-1]["ip"]

    if Confirm.ask(f"Are you sure you want to remove node {target_ip}?", default=True):
        def log_cb(msg: str):
            console.print(f"  [cyan]•[/cyan] {msg}")

        with console.status(f"Tearing down tunnel for node {target_ip}..."):
            ok, msg = LoadBalancerManager.remove_node(pool_name, target_ip, callback=log_cb)

        if ok:
            console.print(f"[bold green]Success: {msg}[/bold green]")
        else:
            console.print(f"[bold red]Error: {msg}[/bold red]")
    time.sleep(2)

def cloudflare_watchdog_menu():
    while True:
        show_banner()
        console.print("[bold green]=== Cloudflare Auto-Failover Watchdog ===[/bold green]\n")

        data = load_data()
        cf_cfg = data.get("cloudflare")
        pools = data.get("pools", {})

        console.print("[bold cyan]Active Load Balancer Pools & DNS Endpoints:[/bold cyan]")
        if not pools:
            console.print("  [yellow]No pools configured yet.[/yellow]")
        else:
            for p_name, p_data in pools.items():
                p_cf = p_data.get("cloudflare") or cf_cfg or {}
                sub = p_cf.get("subdomain", "None")
                ports_str = ", ".join(p_data.get("client_ports", []))
                kh_ip = p_data.get("kharej_server", {}).get("ip", "unknown")
                console.print(f"  • [bold white]Pool '{p_name}':[/bold white] [bold cyan]{sub}[/bold cyan] ➔ Kharej [blue]{kh_ip}[/blue] (Ports: [yellow]{ports_str}[/yellow])")

        is_running = watchdog.is_daemon_running() or watchdog._running
        daemon_pid = watchdog.get_daemon_pid()
        if is_running:
            pid_str = f" (PID: {daemon_pid})" if daemon_pid else ""
            daemon_status = f"[bold green]Running (Active){pid_str}[/bold green]"
        else:
            daemon_status = "[dim]Stopped[/dim]"
        console.print(f"\n• [white]Watchdog Daemon Status:[/white] {daemon_status}")
        
        ws = data.get("watchdog_status")
        if ws and ws.get("last_check"):
            console.print(f"• [white]Last Auto-Sync:[/white] [cyan]{ws['last_check']}[/cyan]")
        console.print()

        console.print("[1] 🔄 Run Live User Telemetry Check & DNS Sync Now")
        daemon_label = "⏹️  Stop Background Daemon" if is_running else "▶️  Start Background Auto-Switch Daemon (Every 30s)"
        console.print(f"[2] {daemon_label}")
        console.print("[3] ⚙️  Update Global Default Cloudflare Credentials")
        console.print("[4] 📜 View Live User Connection Logs on Nodes")
        console.print("[5] 📋 View Background Daemon Activity Log")
        console.print("[0] 🔙 Back to Main Menu\n")

        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "0"], default="1")

        if choice == "0":
            break
        elif choice == "1":
            console.print("\n[cyan]Inspecting live user connection telemetry across all pools...[/cyan]\n")
            report = watchdog.run_check_cycle(callback=lambda m: console.print(f"  [cyan]•[/cyan] {m}"))
            
            pool_reports = report.get("pool_reports", {})
            for p_name, p_rep in pool_reports.items():
                sub = p_rep.get("subdomain") or "No Subdomain configured"
                table = Table(title=f"Pool '{p_name}' Diagnostics (DNS: {sub})", show_header=True, header_style="bold magenta")
                table.add_column("Node IP", style="cyan", width=16)
                table.add_column("Status", width=12)
                table.add_column("Diagnosis / Telemetry Details", style="white")

                for ip, info in p_rep.get("nodes", {}).items():
                    st_raw = info.get("status", "UNKNOWN")
                    if st_raw == "HEALTHY":
                        st = "[bold green]HEALTHY[/bold green]"
                    elif st_raw == "CANARY":
                        st = "[bold yellow]CANARY (Trial)[/bold yellow]"
                    elif st_raw == "DEGRADED":
                        st = "[yellow]DEGRADED[/yellow]"
                    elif st_raw == "IDLE":
                        st = "[dim white]IDLE[/dim white]"
                    else:
                        st = "[bold red]FILTERED[/bold red]"
                    table.add_row(ip, st, info["reason"])

                console.print("\n")
                console.print(table)
                console.print(f"  • [bold green]Active DNS IPs for {p_name}:[/bold green] [bold yellow]{', '.join(p_rep.get('healthy_ips', [])) or 'None'}[/bold yellow]")
                console.print(f"  • [bold red]Filtered IPs for {p_name}:[/bold red] [bold red]{', '.join(p_rep.get('filtered_ips', [])) or 'None'}[/bold red]\n")
            Prompt.ask("Press Enter to return")
        elif choice == "2":
            if watchdog.is_daemon_running() or watchdog._running:
                watchdog.stop_background_daemon()
                console.print("[yellow]Watchdog daemon stopped.[/yellow]")
            else:
                watchdog.start_background_daemon()
                console.print("[bold green]Watchdog background daemon started (Runs quietly every 30s and logs to data/watchdog.log)![/bold green]")
            time.sleep(1.5)
        elif choice == "3":
            tok = Prompt.ask("Enter Cloudflare API Token", password=True, default=cf_cfg.get("api_token", "") if cf_cfg else "")
            zid = Prompt.ask("Enter Zone ID", default=cf_cfg.get("zone_id", "") if cf_cfg else "")
            sub = Prompt.ask("Enter Subdomain", default=cf_cfg.get("subdomain", "lb.example.com") if cf_cfg else "lb.example.com")
            TelemetryWatchdog.set_cloudflare_config(tok, zid, sub, enabled=True)
            console.print("[bold green]Cloudflare configuration saved successfully.[/bold green]")
            time.sleep(1.5)
        elif choice == "5":
            log_path = LOG_FILE
            if os.path.exists(log_path):
                with open(log_path, "r") as f:
                    lines = f.readlines()
                log_text = "".join(lines[-35:])
            else:
                log_text = "No daemon activity recorded yet."
            console.print(Panel(log_text.strip(), title="Background Watchdog Daemon Log", border_style="cyan"))
            Prompt.ask("\nPress Enter to return")
        elif choice == "4":
            data = load_data()
            pools = data.get("pools", {})
            if not pools:
                console.print("[red]No load balancer pools configured.[/red]")
                time.sleep(1.5)
                continue

            if len(pools) > 1:
                console.print("\n[bold cyan]Select Load Balancer Pool to View Connection Logs:[/bold cyan]")
                p_keys = list(pools.keys())
                for idx, p_name in enumerate(p_keys, 1):
                    console.print(f"  [{idx}] Pool '{p_name}'")
                p_idx = Prompt.ask("Choose pool", choices=[str(i) for i in range(1, len(p_keys) + 1)])
                pool = pools[p_keys[int(p_idx) - 1]]
            else:
                pool = list(pools.values())[0]

            nodes = pool.get("nodes", [])
            if not nodes:
                console.print("[yellow]No nodes configured in this pool.[/yellow]")
                time.sleep(1.5)
                continue

            console.print(f"\n[bold cyan]Select Node from Pool '{pool['name']}' to View Connection Logs:[/bold cyan]")
            for idx, n in enumerate(nodes, 1):
                console.print(f"[{idx}] {n['server_name']} ({n['ip']})")
            node_idx = Prompt.ask("Select node", choices=[str(i) for i in range(1, len(nodes) + 1)])
            target_node = nodes[int(node_idx) - 1]
            ssh = SSHManager(target_node["ip"], target_node.get("port", 22), target_node.get("username", "root"), target_node.get("password"))
            ok, msg = ssh.connect()
            if not ok:
                console.print(f"[red]Failed to connect: {msg}[/red]")
            else:
                _, log_text, _ = ssh.execute("tail -n 35 /var/log/vxlb-user-connections.log 2>/dev/null || echo 'No logs recorded yet.'")
                ssh.close()
                console.print(Panel(log_text.strip() or "No logs recorded.", title=f"User Connection Log ({target_node['ip']})", border_style="cyan"))
            Prompt.ask("\nPress Enter to return")

def manage_web_menu():
    while True:
        show_banner()
        is_running = is_web_running()
        w_pid = get_web_pid() if is_running else 0
        w_port = get_web_port()
        
        web_pass = load_data().get("web_password")
        pass_status = "[bold green]Configured[/bold green]" if web_pass else "[yellow]Not set — use option [5] below[/yellow]"
        status_text = f"[bold green]RUNNING (PID: {w_pid})[/bold green]" if is_running else "[bold red]STOPPED[/bold red]"
        bind_host = os.environ.get("VX_LB_WEB_HOST", "0.0.0.0")

        console.print("[bold cyan]=== Mobile Web Dashboard (Phone Control Panel) ===[/bold cyan]\n")
        console.print(f"  [white]Status:[/white] {status_text}")
        console.print(f"  [white]Bind Address:[/white] [yellow]{bind_host}[/yellow]  (VX_LB_WEB_HOST to change)")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _s:
                _s.connect(("8.8.8.8", 80))
                public_ip = _s.getsockname()[0]
        except Exception:
            public_ip = "YOUR_SERVER_IP"

        console.print(f"  [white]Listening Port:[/white] [yellow]{w_port}[/yellow]")
        console.print(f"  [white]Dashboard URL:[/white] [cyan]http://{public_ip}:{w_port}[/cyan]")
        console.print(f"  [white]Web Password:[/white] {pass_status}")

        try:
            import io as _io
            import qrcode as _qr
            _q = _qr.QRCode(border=1)
            _q.add_data(f"http://{public_ip}:{w_port}")
            _q.make(fit=True)
            _buf = _io.StringIO()
            _q.print_ascii(out=_buf, invert=True)
            console.print(_buf.getvalue())
        except ImportError:
            pass
        
        console.print("  [1] ▶️  Start Mobile Dashboard in Background")
        console.print("  [2] ⏹️  Stop Mobile Dashboard")
        console.print("  [3] 🔄 Restart Mobile Dashboard")
        console.print("  [4] ⚙️  Change Dashboard Port (default: 8088)")
        console.print("  [5] 🔐 Set / Reset Dashboard Password")
        console.print("  [6] 🧯 Open dashboard port in firewall")
        console.print("  [0] 🔙 Back to Main Menu\n")

        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6", "0"], default="1" if not is_running else "0")

        if choice == "1":
            if is_running:
                console.print(f"[yellow]Web Dashboard is already running on port {w_port}.[/yellow]")
            else:
                console.print(f"[cyan]Starting Web Dashboard on port {w_port}...[/cyan]")
                if start_background_web(w_port):
                    console.print(f"[bold green]Success: Web Dashboard started successfully! (PID: {get_web_pid()})[/bold green]")
                    console.print(f"[cyan]📱 Dashboard URL: http://{public_ip}:{w_port}[/cyan]")
                else:
                    console.print("[bold red]Error: Failed to start Web Dashboard.[/bold red]")
            Prompt.ask("\nPress Enter to continue")
        elif choice == "2":
            if not is_running:
                console.print("[yellow]Web Dashboard is not running.[/yellow]")
            else:
                if stop_background_web():
                    console.print("[bold green]Success: Web Dashboard stopped successfully.[/bold green]")
                else:
                    console.print("[bold red]Error: Failed to stop Web Dashboard.[/bold red]")
            Prompt.ask("\nPress Enter to continue")
        elif choice == "3":
            console.print("[cyan]Restarting Web Dashboard...[/cyan]")
            stop_background_web()
            time.sleep(1)
            if start_background_web(w_port):
                console.print(f"[bold green]Success: Web Dashboard restarted! (PID: {get_web_pid()})[/bold green]")
            else:
                console.print("[bold red]Error: Failed to restart Web Dashboard.[/bold red]")
            Prompt.ask("\nPress Enter to continue")
        elif choice == "4":
            new_port_str = Prompt.ask("Enter new dashboard port (e.g. 8088)", default=str(w_port))
            if new_port_str.isdigit() and 1 <= int(new_port_str) <= 65535:
                new_port = int(new_port_str)
                if is_running:
                    console.print(f"[cyan]Restarting on new port {new_port}...[/cyan]")
                    stop_background_web()
                    time.sleep(1)
                    start_background_web(new_port)
                else:
                    from core.web_server import PORT_FILE
                    with open(PORT_FILE, "w") as f:
                        f.write(str(new_port))
                console.print(f"[bold green]Success: Dashboard port updated to {new_port}[/bold green]")
            else:
                console.print("[red]Invalid port number.[/red]")
            Prompt.ask("\nPress Enter to continue")
        elif choice == "5":
            new_pass = Prompt.ask("Enter new Web Dashboard password (at least 8 chars)", password=True)
            if len(new_pass) >= 8:
                from core.storage import atomic_update
                from core.web_server import _hash_password
                def _set_p(d: dict):
                    d["web_password"] = _hash_password(new_pass)
                atomic_update(_set_p)
                console.print("[bold green]Success: Web Dashboard password updated successfully.[/bold green]")
            else:
                console.print("[red]Password too short (minimum 8 characters).[/red]")
            Prompt.ask("\nPress Enter to continue")
        elif choice == "6":
            from core.web_server import open_web_port
            ok, msg = open_web_port(w_port)
            if ok:
                console.print(f"[bold green]Success:[/bold green] {msg}")
            else:
                console.print(f"[bold red]Error:[/bold red] {msg}")
            Prompt.ask("\nPress Enter to continue")
        elif choice == "0":
            break

def main():
    while True:
        try:
            show_banner()
            console.print("[bold white]Main Menu:[/bold white]\n")
            console.print("  [bold cyan][1][/bold cyan] 🖥️  Server Management (Add & Test Iran / Kharej Servers via SSH)")
            console.print("  [bold cyan][2][/bold cyan] Create Load Balancer (Multi-Iran ⇄ 1-Kharej + Auto Tunnel)")
            console.print("  [bold cyan][3][/bold cyan] Manage Load Balancers (Status, IP Endpoints, Add/Remove Nodes)")
            console.print("  [bold cyan][4][/bold cyan] 🛡️  Cloudflare Auto-Failover Watchdog (Live Auto-Switch)")
            console.print("  [bold cyan][5][/bold cyan] Web Dashboard (Mobile Control Panel for Phone Access)")
            console.print("  [bold cyan][0][/bold cyan] 🚪 Exit\n")

            choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "0"], default="5")

            if choice == "1":
                manage_servers_menu()
            elif choice == "2":
                create_load_balancer_flow()
            elif choice == "3":
                manage_pools_menu()
            elif choice == "4":
                cloudflare_watchdog_menu()
            elif choice == "5":
                manage_web_menu()
            elif choice == "0":
                if watchdog._thread and watchdog._running:
                    watchdog.stop_background_daemon()
                if watchdog.is_daemon_running():
                    console.print("[bold green]Goodbye! 👋 (Watchdog background daemon remains active)[/bold green]")
                else:
                    console.print("[bold green]Goodbye! 👋[/bold green]")
                sys.exit(0)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Press 0 to exit or select an option.[/yellow]")
            time.sleep(1)

def _cli_set_web_password():
    """Non-interactive dashboard password bootstrap: python3 main.py --set-web-password"""
    import getpass
    pw = getpass.getpass("New dashboard password (min 8 chars): ")
    if len(pw) < 8:
        console.print("[red]Password too short (minimum 8 characters).[/red]")
        sys.exit(1)
    pw2 = getpass.getpass("Repeat password: ")
    if pw != pw2:
        console.print("[red]Passwords do not match.[/red]")
        sys.exit(1)
    from core.storage import atomic_update
    from core.web_server import _hash_password
    def _set_p(d: dict):
        d["web_password"] = _hash_password(pw)
    atomic_update(_set_p)
    console.print("[bold green]Success: Dashboard password set.[/bold green]")
    sys.exit(0)


def _cli_list_capabilities():
    """Prints a structured table of all registered tunnel engines and capabilities."""
    from core.capabilities import list_all_capabilities
    caps = list_all_capabilities()
    table = Table(title="VX-LB Multi-Tunnel Platform Capabilities Catalog")
    table.add_column("Engine ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Layer", style="magenta")
    table.add_column("Protocols", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Status Reason / Description", style="dim")

    for eid, c in sorted(caps.items()):
        status_style = "bold green" if c["support_status"] == "verified" else ("yellow" if c["support_status"] == "experimental" else "red")
        table.add_row(
            eid,
            c["display_name"],
            c["layer"],
            "/".join(c["supported_protocols"]).upper(),
            f"[{status_style}]{c['support_status'].upper()}[/{status_style}]",
            c["status_reason"]
        )
    console.print(table)
    sys.exit(0)

def _cli_list_links():
    """Prints all independent Layer 2/3 private links."""
    data = load_data()
    links = data.get("custom_links", {})
    if not links:
        console.print("[yellow]No custom private links registered.[/yellow]")
        sys.exit(0)
    table = Table(title="Registered Multi-Destination Private Links")
    table.add_column("Link Name", style="cyan")
    table.add_column("Engine", style="bold")
    table.add_column("Iran Server", style="green")
    table.add_column("Kharej Server", style="magenta")
    table.add_column("Subnet", style="yellow")
    table.add_column("MTU", style="white")

    for name, l in links.items():
        table.add_row(
            name,
            l.get("engine_id", "unknown"),
            f"{l['iran_server']['ip']} ({l['iran_server'].get('private_ip')})",
            f"{l['kharej_server']['ip']} ({l['kharej_server'].get('private_ip')})",
            l.get("private_subnet", ""),
            str(l.get("mtu", 1400))
        )
    console.print(table)
    sys.exit(0)

def _cli_list_compositions():
    """Prints a structured table of available layered tunnel compositions."""
    from core.composition import get_available_compositions
    comps = get_available_compositions()
    table = Table(title="VX-LB Available Tunnel Compositions")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Layer", style="magenta")
    table.add_column("Security", style="green")
    table.add_column("Description", style="white")

    for c in comps:
        table.add_row(
            c["id"],
            c["name"],
            c.get("layer", "L3"),
            c.get("security", "none"),
            c.get("description", "")
        )
    console.print(table)
    sys.exit(0)

def _cli_telemetry_summary():
    """Prints server online link telemetry counts."""
    from core.telemetry_supervisor import TelemetrySupervisor
    counts = TelemetrySupervisor.count_server_online_links(load_data())
    if not counts:
        console.print("[yellow]No server link telemetry found.[/yellow]")
        sys.exit(0)
    table = Table(title="Server Endpoint & Link Status Summary")
    table.add_column("Server IP", style="cyan")
    table.add_column("Total Links", style="white")
    table.add_column("Online Links", style="green")
    table.add_column("Degraded", style="yellow")
    table.add_column("Offline", style="red")

    for ip, rec in counts.items():
        table.add_row(
            ip,
            str(rec["total_links"]),
            str(rec["online_links"]),
            str(rec["degraded_links"]),
            str(rec["offline_links"]),
        )
    console.print(table)
    sys.exit(0)

def _cli_reconfig_status():
    """Prints current reconfig bot status and recent audit log."""
    from core.reconfig_bot import ReconfigBot
    st = ReconfigBot.get_status()
    console.print(f"[bold cyan]Reconfig Bot State:[/bold cyan] {st['state']}")
    console.print(f"Paused: {st['paused']}, Current Step: {st['current_step']}/{st['total_steps']}")
    console.print(f"Notifications Opt-in Enabled: {st['notifications_enabled']}")
    logs = ReconfigBot.get_audit_logs(limit=5)
    if logs:
        console.print("\n[bold]Recent Audit Logs:[/bold]")
        for l in logs:
            console.print(f"  {l['timestamp']} [{l['actor']}] {l['action']} -> {l['target']}")
    sys.exit(0)

def _cli_reconfig_pause():
    from core.reconfig_bot import ReconfigBot
    res = ReconfigBot.pause()
    console.print(f"[bold yellow]Reconfig bot paused:[/bold yellow] {res}")
    sys.exit(0)

def _cli_reconfig_resume():
    from core.reconfig_bot import ReconfigBot
    res = ReconfigBot.resume()
    console.print(f"[bold green]Reconfig bot resumed:[/bold green] {res}")
    sys.exit(0)

def _cli_reconfig_rollback():
    from core.reconfig_bot import ReconfigBot
    try:
        res = ReconfigBot.rollback()
        console.print(f"[bold green]Reconfig rollback successful:[/bold green] {res}")
    except Exception as e:
        console.print(f"[bold red]Reconfig rollback failed:[/bold red] {e}")
    sys.exit(0)

if __name__ == "__main__":
    if "--set-web-password" in sys.argv:
        _cli_set_web_password()
    elif "--web" in sys.argv:
        w_port = get_web_port()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _s:
                _s.connect(("8.8.8.8", 80))
                public_ip = _s.getsockname()[0]
        except OSError:
            public_ip = "YOUR_SERVER_IP"
        if is_web_running():
            console.print(f"[yellow]Web Dashboard is already running on port {w_port} (PID: {get_web_pid()}).[/yellow]")
        else:
            console.print(f"[cyan]Starting Web Dashboard on port {w_port}...[/cyan]")
            if start_background_web(w_port):
                console.print(f"[bold green]Web Dashboard started successfully at http://{public_ip}:{w_port} (PID: {get_web_pid()})[/bold green]")
            else:
                console.print("[bold red]Failed to start Web Dashboard.[/bold red]")
        sys.exit(0)
    elif "--list-capabilities" in sys.argv:
        _cli_list_capabilities()
    elif "--list-links" in sys.argv:
        _cli_list_links()
    elif "--list-compositions" in sys.argv:
        _cli_list_compositions()
    elif "--telemetry-summary" in sys.argv:
        _cli_telemetry_summary()
    elif "--reconfig-status" in sys.argv:
        _cli_reconfig_status()
    elif "--reconfig-pause" in sys.argv:
        _cli_reconfig_pause()
    elif "--reconfig-resume" in sys.argv:
        _cli_reconfig_resume()
    elif "--reconfig-rollback" in sys.argv:
        _cli_reconfig_rollback()
    try:
        main()

    except KeyboardInterrupt:
        if watchdog._running:
            watchdog.stop_background_daemon()
        console.print("\n[yellow]Operation aborted by user.[/yellow]")
        sys.exit(0)
