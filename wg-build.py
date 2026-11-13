#!/usr/bin/env python3
"""Build a WireGuard tunnel: key pairs and one <interface>.conf per node in the tunnel folder.

Mirrors the manual workflow:
  wg genkey | tee server.key | wg pubkey > server.pub
  wg genkey | tee client.key | wg pubkey > client.pub
  paste the keys into the configs

Can also add clients to an existing subnet tunnel (new [Peer] on the server).

Requires: python3, wireguard-tools (Ubuntu: apt install wireguard-tools)
"""
import argparse
import ipaddress
import json
import shutil
import sys
from pathlib import Path

from common import (BuildError, Progress, address, ask, choice, count, ifname, menu,
                    network, port, run, tunnel_name, write_private)

KEEPALIVE = 10


# ---------- keys ----------

def find_wg():
    path = shutil.which("wg")
    if not path:
        sys.exit("wg not found. Install it with: sudo apt install wireguard-tools")
    return path


def build_keypair(bar, wg, keys_dir, stem, label):
    """wg genkey | tee <stem>.key | wg pubkey > <stem>.pub; returns (private, public)."""
    bar.step(f"Generating keys for {label}")
    private = run([wg, "genkey"]).strip()
    public = run([wg, "pubkey"], input=private + "\n").strip()
    write_private(keys_dir / f"{stem}.key", private + "\n")
    (keys_dir / f"{stem}.pub").write_text(public + "\n")
    return private, public


def read_key(keys_dir, stem, kind):
    return (keys_dir / f"{stem}.{kind}").read_text().strip()


# ---------- configs ----------

def peer_block(public, allowed):
    return f"""
[Peer]
PublicKey = {public}
AllowedIPs = {allowed}
"""


def server_conf(cfg, server_private, peers):
    """peers: list of (public_key, tunnel_ip)."""
    if cfg["topology"] == "subnet":
        addr = f"{cfg['server_ip']}/{cfg['network'].prefixlen}"
    else:
        addr = f"{cfg['server_ip']}/32"
    text = f"""\
[Interface]
PrivateKey = {server_private}
Address = {addr}
ListenPort = {cfg['port']}
"""
    for public, ip in peers:
        text += peer_block(public, f"{ip}/32")
    return text


def client_conf(cfg, client_private, client_ip, server_public):
    allowed = cfg["network"] if cfg["topology"] == "subnet" else f"{cfg['server_ip']}/32"
    return f"""\
[Interface]
PrivateKey = {client_private}
Address = {client_ip}/32

[Peer]
PublicKey = {server_public}
Endpoint = {cfg['remote']}:{cfg['port']}
AllowedIPs = {allowed}
PersistentKeepalive = {KEEPALIVE}
"""


# ---------- tunnel metadata (lets "add" extend a tunnel later) ----------

def save_meta(tunnel_dir, cfg, clients):
    meta = {k: v if isinstance(v, int) else str(v) for k, v in cfg.items()}
    meta["clients"] = [{k: str(c[k]) for k in ("name", "ip", "dev") if k in c} for c in clients]
    (tunnel_dir / "tunnel.json").write_text(json.dumps(meta, indent=2) + "\n")


def load_meta(tunnel_dir):
    path = tunnel_dir / "tunnel.json"
    if not path.exists():
        sys.exit(f"No tunnel.json in {tunnel_dir}; was this tunnel built with this tool?")
    meta = json.loads(path.read_text())
    clients = [dict(c, ip=ipaddress.IPv4Address(c["ip"])) for c in meta.pop("clients")]
    meta["server_ip"] = ipaddress.IPv4Address(meta["server_ip"])
    if "network" in meta:
        meta["network"] = ipaddress.IPv4Network(meta["network"])
    return meta, clients


def free_ips(net, used, n):
    """Next n host addresses in net not already in use."""
    found = [ip for ip in net.hosts() if ip not in used][:n]
    if len(found) < n:
        sys.exit(f"Only {len(found)} free address(es) left in {net}.")
    return found


def conf_path(tunnel_dir, node, dev):
    """wg-quick names the interface after the file, so configs are <tunnel>/<iface>.conf.
    Tunnels built before interface names were asked for (dev=None) use <tunnel>/<node>.conf."""
    return tunnel_dir / f"{dev or node}.conf"


def unique_ifname(taken):
    """Validator: a valid interface name not already used in this tunnel (they share a folder)."""
    def check(val):
        val = ifname(val)
        if val in taken:
            raise ValueError(f"'{val}' is already used in this tunnel.")
        taken.add(val)
        return val
    return check


def ask_client_ifaces(clients, taken):
    for c in clients:
        c["dev"] = ask(f"Interface name for {c['name']}", validate=unique_ifname(taken))


# ---------- main ----------

def new_tunnel(wg, base_dir):
    cfg = {}
    cfg["name"] = ask("Tunnel name", validate=tunnel_name)
    tunnel_dir = base_dir / cfg["name"]
    if tunnel_dir.exists():
        sys.exit(f"{tunnel_dir} already exists; refusing to overwrite an existing tunnel.")

    cfg["topology"] = ask("Topology (subnet/p2p)", "subnet", choice(["subnet", "p2p"]))

    if cfg["topology"] == "subnet":
        cfg["network"] = ask("Tunnel network (e.g. 10.10.0.0/24)", validate=network)
        cfg["dev"] = ask("Server interface name", validate=ifname)
        cfg["remote"] = ask("Server public IP/hostname (client Endpoint)")
        cfg["port"] = ask("ListenPort", 51820, port)
        room = cfg["network"].num_addresses - 3  # network, broadcast, server

        def fits(val):
            n = count(val)
            if n > room:
                raise ValueError(f"{cfg['network']} only has room for {room} client(s).")
            return n

        n_clients = ask("Number of clients", 1, fits)
        cfg["server_ip"], *ips = free_ips(cfg["network"], set(), n_clients + 1)
        clients = [{"name": f"{cfg['name']}-client{i}", "ip": ip, "stem": f"client{i}"}
                   for i, ip in enumerate(ips, 1)]
        ask_client_ifaces(clients, {cfg["dev"]})
    else:
        cfg["server_ip"] = ask("Server tunnel IP", validate=address)
        while True:
            client_ip = ask("Client tunnel IP", cfg["server_ip"] + 1, address)
            if client_ip != cfg["server_ip"]:
                break
            print("  Client IP must differ from the server IP.")
        cfg["dev"] = ask("Server interface name", validate=ifname)
        clients = [{"name": f"{cfg['name']}-client", "ip": client_ip, "stem": "client"}]
        ask_client_ifaces(clients, {cfg["dev"]})
        cfg["remote"] = ask("Server public IP/hostname (client Endpoint)")
        cfg["port"] = ask("ListenPort", 51820, port)

    try:
        base_dir.mkdir(parents=True, exist_ok=True)
        tunnel_dir.mkdir(mode=0o700)
        keys_dir = tunnel_dir / "keys"
        keys_dir.mkdir(mode=0o700)
    except PermissionError:
        sys.exit(f"Cannot write to {base_dir}. Re-run with sudo or use --base-dir.")

    print()
    # server keys, configs + a key pair per client
    with Progress(2 + len(clients)) as bar:
        server_private, server_public = build_keypair(bar, wg, keys_dir, "server",
                                                      f"{cfg['name']}-server")
        for c in clients:
            c["private"], c["public"] = build_keypair(bar, wg, keys_dir, c["stem"], c["name"])

        bar.step("Writing configs")
        server_path = conf_path(tunnel_dir, f"{cfg['name']}-server", cfg["dev"])
        peers = [(c["public"], c["ip"]) for c in clients]
        write_private(server_path, server_conf(cfg, server_private, peers))
        for c in clients:
            c["path"] = conf_path(tunnel_dir, c["name"], c["dev"])
            write_private(c["path"], client_conf(cfg, c["private"], c["ip"], server_public))
        save_meta(tunnel_dir, cfg, clients)

    print(f"\nDone. Tunnel '{cfg['name']}' written to {tunnel_dir}")
    print(f"  server: {server_path}  ({cfg['name']}-server, {cfg['server_ip']})")
    for c in clients:
        print(f"  client: {c['path']}  ({c['name']}, {c['ip']})")


def add_clients(wg, base_dir):
    name = ask("Tunnel name", validate=tunnel_name)
    tunnel_dir = base_dir / name
    if not tunnel_dir.is_dir():
        sys.exit(f"No tunnel found at {tunnel_dir}.")
    cfg, clients = load_meta(tunnel_dir)
    if cfg["topology"] != "subnet":
        sys.exit(f"'{name}' is a p2p tunnel; clients can only be added to subnet tunnels.")
    print(f"  '{name}' has {len(clients)} client(s):")
    for c in clients:
        print(f"    {c['name']}  {c.get('dev', '-')}  {c['ip']}")

    n_new = ask("Number of clients to add", 1, count)
    used = {cfg["server_ip"]} | {c["ip"] for c in clients}
    ips = free_ips(cfg["network"], used, n_new)
    start = max(int(c["name"].rsplit("client", 1)[1]) for c in clients) + 1
    new = [{"name": f"{name}-client{i}", "ip": ip, "stem": f"client{i}"}
           for i, ip in enumerate(ips, start)]
    if cfg.get("dev"):
        ask_client_ifaces(new, {cfg["dev"]} | {c["dev"] for c in clients if "dev" in c})

    keys_dir = tunnel_dir / "keys"
    server_public = read_key(keys_dir, "server", "pub")
    server_path = conf_path(tunnel_dir, f"{name}-server", cfg.get("dev"))
    server_iface = server_path.stem

    print()
    with Progress(n_new + 1) as bar:
        for c in new:
            c["private"], c["public"] = build_keypair(bar, wg, keys_dir, c["stem"], c["name"])
        bar.step("Writing configs")
        for c in new:
            c["path"] = conf_path(tunnel_dir, c["name"], c.get("dev"))
            write_private(c["path"], client_conf(cfg, c["private"], c["ip"], server_public))
        with open(server_path, "a") as f:
            for c in new:
                f.write(peer_block(c["public"], f"{c['ip']}/32"))
        save_meta(tunnel_dir, cfg, clients + new)

    print(f"\nDone. Added {n_new} client(s) to '{name}'")
    for c in new:
        print(f"  client: {c['path']}  ({c['name']}, {c['ip']})")
    print(f"\nThe server config gained {n_new} [Peer] block(s): {server_path}"
          "\nCopy it to the server node, then load it without dropping existing peers:"
          f"\n  wg syncconf {server_iface} <(wg-quick strip {server_iface})")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-dir", default="/opt/wireguard",
                        help="parent directory for tunnel folders (default: /opt/wireguard)")
    args = parser.parse_args()

    wg = find_wg()
    base_dir = Path(args.base_dir)

    print("WireGuard tunnel builder\n")
    action = menu("What would you like to do?", [
        ("new", "Build a new tunnel"),
        ("add", "Add clients to an existing tunnel"),
    ])
    print()
    if action == "new":
        new_tunnel(wg, base_dir)
    else:
        add_clients(wg, base_dir)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nAborted.")
    except BuildError as e:
        if e.output:
            sys.stderr.write(e.output.rstrip() + "\n")
        sys.exit(f"Error: {e}")
