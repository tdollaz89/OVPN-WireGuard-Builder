#!/usr/bin/env python3
"""Build an OpenVPN tunnel: its own CA, server/client certs, tls-crypt-v2 keys,
and inline <name>-server.conf / <name>-clientN.conf files.

Mirrors the manual workflow:
  easyrsa init-pki / build-ca / build-server-full / build-client-full
  openvpn --genkey tls-crypt-v2-server / tls-crypt-v2-client
  paste everything inline into the configs

Can also add clients to an existing subnet tunnel (new cert + tls-crypt-v2 key).

Requires: python3, easy-rsa, openvpn >= 2.5 (Ubuntu: apt install easy-rsa openvpn)
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import sys
from pathlib import Path

from common import (BuildError, Progress, address, ask, choice, count, menu, ifname,
                    network, port, run, tunnel_name, write_private)

VARS_SETTINGS = {
    "EASYRSA_DIGEST": '"sha384"',
    "EASYRSA_NO_PASS": "1",
    "EASYRSA_ALGO": "ec",
}
PEM_RE = re.compile(r"-----BEGIN ([^\n]+?)-----.*?-----END \1-----", re.S)


# ---------- tooling ----------

def find_easyrsa():
    path = shutil.which("easyrsa")
    if path:
        return path
    for p in ("/usr/share/easy-rsa/easyrsa", "/etc/easy-rsa/easyrsa"):
        if os.access(p, os.X_OK):
            return p
    sys.exit("easyrsa not found. Install it with: sudo apt install easy-rsa")


def find_openvpn():
    path = shutil.which("openvpn") or "/usr/sbin/openvpn"
    if not os.access(path, os.X_OK):
        sys.exit("openvpn not found. Install it with: sudo apt install openvpn")
    return path


def pem(path):
    """Return only the PEM block(s); easy-rsa 3.0 issued certs carry a text dump first."""
    blocks = [m.group(0) for m in PEM_RE.finditer(Path(path).read_text())]
    if not blocks:
        raise BuildError(f"No PEM data found in {path}")
    return "\n".join(blocks)


# ---------- build steps ----------

def configure_vars(vars_file):
    """Apply VARS_SETTINGS to the PKI's vars file, uncommenting/replacing existing
    set_var lines and appending any that are missing (easy-rsa 3.0 has no pki/vars)."""
    text = vars_file.read_text() if vars_file.exists() else ""
    for key, value in VARS_SETTINGS.items():
        line = f"set_var {key}\t{value}"
        pattern = re.compile(rf"^[ \t]*#?[ \t]*set_var[ \t]+{key}\b.*$", re.M)
        text, n = pattern.subn(lambda m: line, text, count=1)
        if not n:
            text += ("\n" if text and not text.endswith("\n") else "") + line + "\n"
    vars_file.write_text(text)


def easyrsa_env(pki):
    env = dict(os.environ, EASYRSA_PKI=str(pki), EASYRSA_BATCH="1")
    if (pki / "vars").exists():
        env["EASYRSA_VARS_FILE"] = str(pki / "vars")
    return env


def build_pki(bar, easyrsa, tunnel_dir, name):
    pki = tunnel_dir / "pki"
    env = easyrsa_env(pki)

    bar.step("Initializing PKI")
    run([easyrsa, "init-pki"], env=env, cwd=tunnel_dir)
    bar.step("Configuring vars (sha384, EC, no pass)")
    configure_vars(pki / "vars")
    env = easyrsa_env(pki)

    # nopass is redundant with EASYRSA_NO_PASS but keeps older easy-rsa versions honest
    bar.step(f"Building CA {name}-ca")
    run([easyrsa, f"--req-cn={name}-ca", "build-ca", "nopass"], env=env, cwd=tunnel_dir)
    bar.step(f"Building server cert {name}-server")
    run([easyrsa, "build-server-full", f"{name}-server", "nopass"], env=env, cwd=tunnel_dir)
    return pki


def build_server_tls_key(bar, openvpn, tunnel_dir):
    tls = tunnel_dir / "tls"
    tls.mkdir(mode=0o700)
    server_key = tls / "server_tls.key"
    bar.step("Generating tls-crypt-v2 server key")
    run([openvpn, "--genkey", "tls-crypt-v2-server", server_key])
    return server_key


def build_client(bar, easyrsa, openvpn, tunnel_dir, client, n):
    """Client cert + tls-crypt-v2 client key; returns the key path."""
    pki = tunnel_dir / "pki"
    bar.step(f"Building client cert {client}")
    run([easyrsa, "build-client-full", client, "nopass"], env=easyrsa_env(pki), cwd=tunnel_dir)
    bar.step(f"Generating tls-crypt-v2 key for {client}")
    tls = tunnel_dir / "tls"
    key = tls / f"client{n}_tls.key"
    run([openvpn, "--tls-crypt-v2", tls / "server_tls.key", "--genkey", "tls-crypt-v2-client", key])
    return key


def inline_blocks(pki, cn, tls_key):
    return (
        f"<ca>\n{pem(pki / 'ca.crt')}\n</ca>\n"
        f"<cert>\n{pem(pki / 'issued' / f'{cn}.crt')}\n</cert>\n"
        f"<key>\n{pem(pki / 'private' / f'{cn}.key')}\n</key>\n"
        f"<tls-crypt-v2>\n{pem(tls_key)}\n</tls-crypt-v2>\n"
    )


def server_conf(cfg, pki, tls_key):
    if cfg["topology"] == "p2p":
        return p2p_server_conf(cfg, pki, tls_key)
    name = cfg["name"]
    net = cfg["network"]
    proto = "tcp-server" if cfg["proto"] == "tcp" else "udp"
    return f"""\
log {name}-server.log
verb 4
status {name}-status.log
dev-type tun
dev {cfg['dev']}
topology subnet
server {net.network_address} {net.netmask}
port {cfg['port']}
proto {proto}
data-ciphers AES-128-GCM
auth SHA256
keepalive 10 60
remote-cert-tls client
verify-x509-name {name}-client name-prefix
chroot {name}-jail
tls-ciphersuites TLS_AES_256_GCM_SHA384
tls-version-min 1.3
user nobody
group nogroup
persist-key
persist-tun
tls-server
dh none

{inline_blocks(pki, f"{name}-server", tls_key)}"""


def client_conf(cfg, pki, client, tls_key):
    if cfg["topology"] == "p2p":
        return p2p_client_conf(cfg, pki, client, tls_key)
    proto = "tcp-client" if cfg["proto"] == "tcp" else "udp"
    return f"""\
log {client}.log
verb 4
dev tun
client
remote {cfg['remote']}
proto {proto}
port {cfg['port']}
remote-cert-tls server
verify-x509-name {cfg['name']}-server name

{inline_blocks(pki, client, tls_key)}"""


def p2p_proto(cfg, side):
    """UDP is OpenVPN's default, so the line is only needed for TCP; fast-io is UDP-only."""
    if cfg["proto"] == "tcp":
        return f"proto tcp-{side}\n", ""
    return "", "fast-io\n"


def p2p_server_conf(cfg, pki, tls_key):
    name = cfg["name"]
    proto, fast_io = p2p_proto(cfg, "server")
    return f"""\
log {name}-server.log
verb 4
dev-type tun
dev {cfg['dev']}
topology p2p
ifconfig {cfg['server_ip']} {cfg['client_ip']}
port {cfg['port']}
{proto}data-ciphers AES-256-GCM
auth SHA384
remote-cert-tls client
verify-x509-name {name}-client name
tls-ciphersuites TLS_AES_256_GCM_SHA384
tls-version-min 1.3
chroot {name}-jail
user nobody
group nogroup
persist-key
persist-tun
keepalive 10 60
{fast_io}dh none
tls-server

{inline_blocks(pki, f"{name}-server", tls_key)}"""


def p2p_client_conf(cfg, pki, client, tls_key):
    name = cfg["name"]
    proto, fast_io = p2p_proto(cfg, "client")
    return f"""\
log {client}.log
verb 4
dev-type tun
dev {cfg['client_dev']}
client
topology p2p
ifconfig {cfg['client_ip']} {cfg['server_ip']}
remote {cfg['remote']}
port {cfg['port']}
{proto}nobind
data-ciphers AES-256-GCM
auth SHA384
remote-cert-tls server
verify-x509-name {name}-server name
tls-ciphersuites TLS_AES_256_GCM_SHA384
tls-version-min 1.3
chroot {name}-jail
user nobody
group nogroup
persist-key
persist-tun
keepalive 10 60
{fast_io}
{inline_blocks(pki, client, tls_key)}"""


# ---------- tunnel metadata (lets "add" extend a tunnel later) ----------

def save_meta(tunnel_dir, cfg, clients):
    meta = {k: str(v) if not isinstance(v, int) else v for k, v in cfg.items()}
    meta["clients"] = clients
    (tunnel_dir / "tunnel.json").write_text(json.dumps(meta, indent=2) + "\n")


def load_meta(tunnel_dir):
    path = tunnel_dir / "tunnel.json"
    if not path.exists():
        sys.exit(f"No tunnel.json in {tunnel_dir}; was this tunnel built with this tool?")
    meta = json.loads(path.read_text())
    clients = meta.pop("clients")
    if "network" in meta:
        meta["network"] = ipaddress.IPv4Network(meta["network"])
    for key in ("server_ip", "client_ip"):
        if key in meta:
            meta[key] = ipaddress.IPv4Address(meta[key])
    return meta, clients


def client_number(client):
    return int(re.search(r"(\d+)$", client).group(1))


# ---------- main ----------

def new_tunnel(easyrsa, openvpn, base_dir):
    cfg = {}
    cfg["name"] = ask("Tunnel name", validate=tunnel_name)
    tunnel_dir = base_dir / cfg["name"]
    if tunnel_dir.exists():
        sys.exit(f"{tunnel_dir} already exists; refusing to overwrite an existing tunnel.")

    cfg["topology"] = ask("Topology (subnet/p2p)", "subnet", choice(["subnet", "p2p"]))

    if cfg["topology"] == "subnet":
        cfg["network"] = ask("Tunnel network (e.g. 172.21.0.0/24)", validate=network)
        cfg["dev"] = ask("Server tun device name", validate=ifname)
        cfg["remote"] = ask("Server public IP/hostname (client 'remote')")
        cfg["proto"] = ask("Protocol (tcp/udp)", "tcp", choice(["tcp", "udp"]))
        cfg["port"] = ask("Port", 443, port)
        n_clients = ask("Number of clients", 1, count)
        clients = [f"{cfg['name']}-client{i}" for i in range(1, n_clients + 1)]
    else:
        cfg["server_ip"] = ask("Server tunnel IP", validate=address)
        while True:
            cfg["client_ip"] = ask("Client tunnel IP", cfg["server_ip"] + 1, address)
            if cfg["client_ip"] != cfg["server_ip"]:
                break
            print("  Client IP must differ from the server IP.")
        cfg["dev"] = ask("Server tun device name", validate=ifname)
        cfg["client_dev"] = ask("Client tun device name", validate=ifname)
        cfg["remote"] = ask("Server public IP/hostname (client 'remote')")
        cfg["proto"] = ask("Protocol (tcp/udp)", "udp", choice(["tcp", "udp"]))
        cfg["port"] = ask("Port", 30001, port)
        clients = [f"{cfg['name']}-client"]

    try:
        base_dir.mkdir(parents=True, exist_ok=True)
        tunnel_dir.mkdir(mode=0o700)
    except PermissionError:
        sys.exit(f"Cannot write to {base_dir}. Re-run with sudo or use --base-dir.")

    print()
    # init-pki, vars, CA, server cert, tls server key, configs + a cert and tls key per client
    with Progress(6 + 2 * len(clients)) as bar:
        pki = build_pki(bar, easyrsa, tunnel_dir, cfg["name"])
        server_key = build_server_tls_key(bar, openvpn, tunnel_dir)
        client_keys = {client: build_client(bar, easyrsa, openvpn, tunnel_dir, client, n)
                       for n, client in enumerate(clients, 1)}

        bar.step("Writing configs")
        server_path = tunnel_dir / f"{cfg['name']}-server.conf"
        write_private(server_path, server_conf(cfg, pki, server_key))
        client_paths = []
        for client in clients:
            path = tunnel_dir / f"{client}.conf"
            write_private(path, client_conf(cfg, pki, client, client_keys[client]))
            client_paths.append(path)
        save_meta(tunnel_dir, cfg, clients)

    print(f"\nDone. Tunnel '{cfg['name']}' written to {tunnel_dir}")
    print(f"  server: {server_path}")
    for p in client_paths:
        print(f"  client: {p}")
    jail = f"/etc/openvpn/{cfg['name']}-jail/tmp"
    nodes = "the server and client nodes" if cfg["topology"] == "p2p" else "the server node"
    print(f"\nReminder: build the chroot jail on {nodes}:"
          f"\n  mkdir -p {jail}"
          f"\n  chmod 1777 {jail}")


def add_clients(easyrsa, openvpn, base_dir):
    name = ask("Tunnel name", validate=tunnel_name)
    tunnel_dir = base_dir / name
    if not tunnel_dir.is_dir():
        sys.exit(f"No tunnel found at {tunnel_dir}.")
    cfg, clients = load_meta(tunnel_dir)
    if cfg["topology"] != "subnet":
        sys.exit(f"'{name}' is a p2p tunnel; clients can only be added to subnet tunnels.")
    print(f"  '{name}' has {len(clients)} client(s): {', '.join(clients)}")

    n_new = ask("Number of clients to add", 1, count)
    start = max(client_number(c) for c in clients) + 1
    new = [f"{name}-client{i}" for i in range(start, start + n_new)]

    print()
    pki = tunnel_dir / "pki"
    with Progress(2 * n_new + 1) as bar:
        keys = {client: build_client(bar, easyrsa, openvpn, tunnel_dir, client, client_number(client))
                for client in new}
        bar.step("Writing configs")
        paths = []
        for client in new:
            path = tunnel_dir / f"{client}.conf"
            write_private(path, client_conf(cfg, pki, client, keys[client]))
            paths.append(path)
        save_meta(tunnel_dir, cfg, clients + new)

    print(f"\nDone. Added {n_new} client(s) to '{name}'")
    for p in paths:
        print(f"  client: {p}")
    print("\nThe server config is unchanged (it accepts any cert named"
          f" {name}-client*), so there is nothing to redeploy on the server.")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-dir", default="/opt/openvpn",
                        help="parent directory for tunnel folders (default: /opt/openvpn)")
    args = parser.parse_args()

    easyrsa = find_easyrsa()
    openvpn = find_openvpn()
    base_dir = Path(args.base_dir)

    print("OpenVPN tunnel builder\n")
    action = menu("What would you like to do?", [
        ("new", "Build a new tunnel"),
        ("add", "Add clients to an existing tunnel"),
    ])
    print()
    if action == "new":
        new_tunnel(easyrsa, openvpn, base_dir)
    else:
        add_clients(easyrsa, openvpn, base_dir)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nAborted.")
    except BuildError as e:
        if e.output:
            sys.stderr.write(e.output.rstrip() + "\n")
        sys.exit(f"Error: {e}")
