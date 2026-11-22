#!/usr/bin/env python3
"""Outbound-only NetScope desktop agent for authorized local networks."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from app import connected_networks, parse_nmap, scan_services


DEFAULT_CONFIG = Path.home() / ".config" / "netscope-agent" / "config.json"
PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def safe_networks() -> list[dict]:
    results = []
    for item in connected_networks():
        network = ipaddress.ip_network(item["cidr"])
        if (
            item["scannable"]
            and network.num_addresses <= 4096
            and any(network.subnet_of(private) for private in PRIVATE_RANGES)
        ):
            results.append({"cidr": str(network), "interface": item["interface"]})
    return results


def request(server: str, path: str, method: str = "GET", token: str | None = None, payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{server.rstrip('/')}{path}", data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            message = json.loads(exc.read()).get("error", str(exc))
        except (json.JSONDecodeError, UnicodeDecodeError):
            message = str(exc)
        raise RuntimeError(message) from exc


def save_config(path: Path, config: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def load_config(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError("Agent is not paired. Run with --server URL --pair CODE first.") from exc


def perform_scan(network_value: str) -> list[dict]:
    allowed = {item["cidr"] for item in safe_networks()}
    try:
        network = ipaddress.ip_network(network_value, strict=False)
    except ValueError as exc:
        raise RuntimeError("Controller supplied an invalid network.") from exc
    if str(network) not in allowed:
        raise RuntimeError("Refusing target: it is not a directly connected private network.")
    result = subprocess.run(
        ["nmap", "-sn", "-oX", "-", "--reason", str(network)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Host discovery failed.")
    devices = parse_nmap(result.stdout)
    try:
        return scan_services(devices)
    except Exception as exc:
        print(f"Service detection warning: {exc}")
        return devices


def pair(server: str, code: str, name: str, path: Path) -> None:
    response = request(server, "/api/global/agent/pair", "POST", payload={"code": code, "name": name})
    save_config(path, {"server": server.rstrip("/"), "agentId": response["agentId"], "token": response["agentToken"], "name": name})
    print(f"Paired {name}. Configuration saved to {path}")


def cycle(config: dict) -> bool:
    server = config["server"]
    token = config["token"]
    networks = safe_networks()
    request(server, "/api/global/agent/heartbeat", "POST", token, {"networks": networks})
    response = request(server, "/api/global/agent/tasks", token=token)
    task = response.get("task")
    if not task:
        return False
    print(f"Scanning authorized local network {task['network']}...")
    try:
        devices = perform_scan(task["network"])
    except Exception as exc:
        print(f"Scan failed: {exc}")
        devices = []
    result = request(
        server,
        "/api/global/agent/results",
        "POST",
        token,
        {"taskId": task["id"], "devices": devices},
    )
    print(f"Uploaded {result['accepted']} device(s).")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the NetScope desktop agent.")
    parser.add_argument("--server", help="Public NetScope controller URL")
    parser.add_argument("--pair", help="Short-lived pairing code")
    parser.add_argument("--name", default=socket.gethostname(), help="Agent display name")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--once", action="store_true", help="Check for one task and exit")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    args = parser.parse_args()

    if args.pair:
        if not args.server or not args.server.startswith("https://") and not args.server.startswith("http://127.0.0.1"):
            parser.error("--server must use HTTPS (or localhost for testing).")
        pair(args.server, args.pair, args.name[:80], args.config)
        return

    config = load_config(args.config)
    while True:
        try:
            cycle(config)
        except (RuntimeError, urllib.error.URLError, TimeoutError) as exc:
            print(f"Agent connection error: {exc}")
        if args.once:
            return
        time.sleep(max(args.interval, 3))


if __name__ == "__main__":
    main()
