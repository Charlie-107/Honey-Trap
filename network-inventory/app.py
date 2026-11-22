#!/usr/bin/env python3
"""Local network inventory dashboard backed by nmap host discovery."""

from __future__ import annotations

import argparse
import base64
import errno
import hmac
import ipaddress
import json
import mimetypes
import os
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "static"
MAX_SCAN_HOSTS = 4096
MAX_SERVICE_HOSTS = 128
SERVICE_PORT_COUNT = 50

STATE_LOCK = threading.Lock()
STATE = {
    "devices": [],
    "activity": [],
    "scanning": False,
    "phase": None,
    "network": None,
    "startedAt": None,
    "lastScanAt": None,
    "durationSeconds": None,
    "error": None,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record_activity(kind: str, title: str, detail: str) -> None:
    event = {
        "id": f"{time.time_ns()}",
        "kind": kind,
        "title": title,
        "detail": detail,
        "timestamp": utc_now(),
    }
    with STATE_LOCK:
        STATE["activity"] = [event, *STATE["activity"]][:100]


def run_json_command(command: list[str]) -> list[dict]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return json.loads(result.stdout)


def connected_networks() -> list[dict]:
    """Return directly connected, non-loopback IPv4 networks."""
    networks: dict[str, dict] = {}
    try:
        interfaces = run_json_command(["ip", "-j", "-4", "address", "show", "up"])
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []

    for interface in interfaces:
        if_name = interface.get("ifname", "")
        if if_name == "lo":
            continue
        for address in interface.get("addr_info", []):
            local = address.get("local")
            prefix = address.get("prefixlen")
            if not local or prefix is None:
                continue
            try:
                ip = ipaddress.ip_address(local)
                network = ipaddress.ip_network(f"{local}/{prefix}", strict=False)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or network.num_addresses <= 1:
                continue
            cidr = str(network)
            networks[cidr] = {
                "cidr": cidr,
                "interface": if_name,
                "address": local,
                "hostCount": max(network.num_addresses - 2, 1),
                "scannable": network.num_addresses <= MAX_SCAN_HOSTS,
            }
    return sorted(networks.values(), key=lambda item: (item["interface"], item["cidr"]))


def validate_network(value: str) -> ipaddress.IPv4Network:
    try:
        requested = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 network, for example 192.168.1.0/24.") from exc

    if requested.version != 4:
        raise ValueError("Only IPv4 networks are supported in this version.")
    if requested.num_addresses > MAX_SCAN_HOSTS:
        raise ValueError(f"Network is too large. The limit is {MAX_SCAN_HOSTS} addresses per scan.")

    local_networks = [ipaddress.ip_network(item["cidr"]) for item in connected_networks()]
    if not any(requested.subnet_of(local) for local in local_networks):
        raise ValueError("The target must be inside a directly connected local network.")
    return requested


def neighbor_table() -> dict[str, str]:
    try:
        entries = run_json_command(["ip", "-j", "neighbor", "show"])
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return {}
    return {
        entry["dst"]: entry["lladdr"].upper()
        for entry in entries
        if entry.get("dst") and entry.get("lladdr")
    }


def classify_device(name: str, vendor: str) -> tuple[str, str]:
    haystack = f"{name} {vendor}".lower()
    rules = [
        ("printer", "Printer", ("printer", "laserjet", "officejet", "epson", "brother", "xerox")),
        ("network", "Network", ("router", "gateway", "switch", "access point", "ubiquiti", "mikrotik", "cisco", "netgear", "tp-link")),
        ("mobile", "Mobile", ("iphone", "ipad", "android", "pixel", "oneplus", "mobile")),
        ("computer", "Computer", ("macbook", "imac", "desktop", "laptop", "windows", "thinkpad", "dell", "lenovo")),
        ("iot", "IoT", ("camera", "doorbell", "thermostat", "sensor", "bulb", "light", "plug", "speaker", "alexa", "echo", "nest", "tuya", "sonoff", "espressif", "raspberry", "shelly", "roku", "chromecast", "smart tv", "television")),
    ]
    for device_type, label, keywords in rules:
        if any(keyword in haystack for keyword in keywords):
            return device_type, label
    return "unknown", "Unknown"


def parse_nmap(xml_output: str) -> list[dict]:
    root = ET.fromstring(xml_output)
    neighbors = neighbor_table()
    devices = []
    seen_ips = set()

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        addresses = {node.get("addrtype"): node for node in host.findall("address")}
        ipv4_node = addresses.get("ipv4")
        if ipv4_node is None or not ipv4_node.get("addr"):
            continue
        ip = ipv4_node.get("addr", "")
        seen_ips.add(ip)
        mac_node = addresses.get("mac")
        mac = mac_node.get("addr", "").upper() if mac_node is not None else neighbors.get(ip, "")
        vendor = mac_node.get("vendor", "") if mac_node is not None else ""
        hostname_node = host.find("hostnames/hostname")
        hostname = hostname_node.get("name", "") if hostname_node is not None else ""
        device_type, type_label = classify_device(hostname, vendor)
        times = host.find("times")
        latency = None
        if times is not None and times.get("srtt"):
            latency = round(int(times.get("srtt", "0")) / 1000, 1)

        fallback_name = f"{vendor or 'Unknown device'} - {ip.rsplit('.', 1)[-1]}"
        devices.append(
            {
                "id": mac or ip,
                "name": hostname or fallback_name,
                "hostname": hostname or None,
                "ip": ip,
                "mac": mac or None,
                "vendor": vendor or "Unknown vendor",
                "type": device_type,
                "typeLabel": type_label,
                "group": "IoT" if device_type == "iot" else "Other",
                "status": "online",
                "latencyMs": latency,
                "lastSeen": utc_now(),
                "services": [],
            }
        )

    devices.sort(key=lambda item: ipaddress.ip_address(item["ip"]))
    return devices


def enrich_services(xml_output: str, devices: list[dict]) -> list[dict]:
    root = ET.fromstring(xml_output)
    devices_by_ip = {device["ip"]: device for device in devices}

    for host in root.findall("host"):
        ipv4_node = next(
            (node for node in host.findall("address") if node.get("addrtype") == "ipv4"),
            None,
        )
        if ipv4_node is None:
            continue
        device = devices_by_ip.get(ipv4_node.get("addr", ""))
        if device is None:
            continue

        services = []
        for port_node in host.findall("ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue
            service_node = port_node.find("service")
            attributes = service_node.attrib if service_node is not None else {}
            product = attributes.get("product", "")
            version = attributes.get("version", "")
            extra = attributes.get("extrainfo", "")
            description = " ".join(part for part in (product, version, extra) if part)
            services.append(
                {
                    "port": int(port_node.get("portid", "0")),
                    "protocol": port_node.get("protocol", "tcp"),
                    "name": attributes.get("name", "unknown"),
                    "product": product or None,
                    "version": version or None,
                    "detail": description or None,
                    "secure": attributes.get("tunnel") == "ssl",
                }
            )

        services.sort(key=lambda service: service["port"])
        device["services"] = services
        if device["type"] == "unknown" and any(
            service["name"] in {"rtsp", "mqtt", "coap"} for service in services
        ):
            device["type"] = "iot"
            device["typeLabel"] = "IoT service"
            device["group"] = "IoT"

    return devices


def scan_services(devices: list[dict]) -> list[dict]:
    targets = [device["ip"] for device in devices[:MAX_SERVICE_HOSTS]]
    if not targets:
        return devices
    result = subprocess.run(
        [
            "nmap",
            "-sT",
            "-sV",
            "--version-light",
            "--top-ports",
            str(SERVICE_PORT_COUNT),
            "--host-timeout",
            "45s",
            "--max-retries",
            "1",
            "-oX",
            "-",
            *targets,
        ],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or "nmap could not identify services."
        raise RuntimeError(message)
    return enrich_services(result.stdout, devices)


def perform_scan(network: ipaddress.IPv4Network) -> None:
    started = time.monotonic()
    try:
        with STATE_LOCK:
            STATE["phase"] = "Discovering online devices"
        result = subprocess.run(
            ["nmap", "-sn", "-oX", "-", "--reason", str(network)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if result.returncode != 0:
            message = result.stderr.strip() or "nmap could not complete the scan."
            raise RuntimeError(message)
        devices = parse_nmap(result.stdout)
        record_activity(
            "discovery",
            "Host discovery complete",
            f"Found {len(devices)} online device(s) on {network}.",
        )
        with STATE_LOCK:
            STATE["devices"] = devices

        if devices:
            with STATE_LOCK:
                STATE["phase"] = "Identifying network services"
            record_activity(
                "services",
                "Service identification started",
                f"Checking the {SERVICE_PORT_COUNT} most common TCP ports on up to {MAX_SERVICE_HOSTS} devices.",
            )
            try:
                devices = scan_services(devices)
                service_count = sum(len(device["services"]) for device in devices)
                record_activity(
                    "services",
                    "Service identification complete",
                    f"Identified {service_count} open network service(s).",
                )
            except (OSError, subprocess.SubprocessError, ET.ParseError, RuntimeError) as exc:
                record_activity("warning", "Service identification incomplete", str(exc))

        duration = round(time.monotonic() - started, 1)
        finished_at = utc_now()
        with STATE_LOCK:
            STATE["devices"] = devices
            STATE["lastScanAt"] = finished_at
            STATE["durationSeconds"] = duration
            STATE["error"] = None
            STATE["phase"] = "Complete"
        record_activity(
            "complete",
            "Inventory scan complete",
            f"Updated {len(devices)} device(s) in {duration} seconds.",
        )
    except (OSError, subprocess.SubprocessError, ET.ParseError, RuntimeError) as exc:
        with STATE_LOCK:
            STATE["error"] = str(exc)
            STATE["phase"] = "Failed"
        record_activity("error", "Inventory scan failed", str(exc))
    finally:
        with STATE_LOCK:
            STATE["scanning"] = False


def start_scan(network_value: str) -> dict:
    network = validate_network(network_value)
    with STATE_LOCK:
        if STATE["scanning"]:
            raise RuntimeError("A scan is already running.")
        STATE["scanning"] = True
        STATE["network"] = str(network)
        STATE["startedAt"] = utc_now()
        STATE["error"] = None
        STATE["phase"] = "Starting"
    record_activity("scan", "Inventory scan started", f"Scanning authorized local network {network}.")
    thread = threading.Thread(target=perform_scan, args=(network,), daemon=True)
    thread.start()
    return {"message": "Scan started.", "network": str(network)}


def state_snapshot() -> dict:
    with STATE_LOCK:
        return dict(STATE)


class InventoryHandler(BaseHTTPRequestHandler):
    server_version = "NetworkInventory/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def require_authorization(self) -> bool:
        username = os.environ.get("NETSCOPE_USERNAME")
        password = os.environ.get("NETSCOPE_PASSWORD")
        if not username or not password:
            return True
        header = self.headers.get("Authorization", "")
        try:
            scheme, encoded = header.split(" ", 1)
            supplied = base64.b64decode(encoded, validate=True).decode("utf-8")
            supplied_username, supplied_password = supplied.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            supplied_username = supplied_password = ""
            scheme = ""
        authorized = (
            scheme.lower() == "basic"
            and hmac.compare_digest(supplied_username, username)
            and hmac.compare_digest(supplied_password, password)
        )
        if authorized:
            return True
        body = b"Authentication required."
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="NetScope", charset="UTF-8"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def do_GET(self) -> None:
        if not self.require_authorization():
            return
        path = urlparse(self.path).path
        if path == "/api/interfaces":
            self.send_json({"networks": connected_networks(), "maxScanHosts": MAX_SCAN_HOSTS})
            return
        if path == "/api/status":
            self.send_json(state_snapshot())
            return
        if path == "/api/devices":
            snapshot = state_snapshot()
            self.send_json({"devices": snapshot["devices"], "lastScanAt": snapshot["lastScanAt"]})
            return
        if path == "/api/activity":
            snapshot = state_snapshot()
            self.send_json({"activity": snapshot["activity"]})
            return
        self.serve_static(path)

    def do_POST(self) -> None:
        if not self.require_authorization():
            return
        path = urlparse(self.path).path
        if path != "/api/scan":
            self.send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 4096:
                raise ValueError("Invalid request body.")
            payload = json.loads(self.rfile.read(length))
            network = str(payload.get("network", "")).strip()
            response = start_scan(network)
            self.send_json(response, HTTPStatus.ACCEPTED)
        except json.JSONDecodeError:
            self.send_json({"error": "Request body must be valid JSON."}, HTTPStatus.BAD_REQUEST)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.CONFLICT)

    def serve_static(self, request_path: str) -> None:
        page_routes = {
            "/": "index.html",
            "/inventory": "index.html",
            "/inventory/": "index.html",
            "/assessments": "assessments.html",
            "/assessments/": "assessments.html",
            "/activity": "activity.html",
            "/activity/": "activity.html",
        }
        relative = page_routes.get(request_path, request_path.lstrip("/"))
        candidate = (STATIC_ROOT / relative).resolve()
        try:
            candidate.relative_to(STATIC_ROOT.resolve())
        except ValueError:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not candidate.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content = candidate.read_bytes()
        mime_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{mime_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local network inventory dashboard.")
    parser.add_argument("--host", default="127.0.0.1", help="Address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
    args = parser.parse_args()

    try:
        server = ThreadingHTTPServer((args.host, args.port), InventoryHandler)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            parser.error(
                f"port {args.port} is already in use; stop the existing server "
                f"or run ./run.sh --port {args.port + 1}"
            )
        raise
    print(f"Network Inventory is running at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
