#!/usr/bin/env python3
"""Public NetScope controller for isolated, agent-backed network inventories."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import mimetypes
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "public"
DB_PATH = Path(os.environ.get("NETSCOPE_DB", ROOT / "data" / "controller.db"))
MAX_SCAN_ADDRESSES = 4096
PAIR_CODE_TTL = 600
CREATE_LIMIT = 30
CREATE_WINDOW = 3600
RATE_LOCK = threading.Lock()
CREATE_ATTEMPTS: dict[str, list[float]] = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as connection:
        connection.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                admin_hash TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pair_codes (
                code TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                networks_json TEXT NOT NULL DEFAULT '[]',
                last_seen TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                network TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS devices (
                agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                device_id TEXT NOT NULL,
                data_json TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (agent_id, device_id)
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


def new_pair_code(connection: sqlite3.Connection, workspace_id: str) -> str:
    connection.execute("DELETE FROM pair_codes WHERE expires_at < ?", (int(time.time()),))
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        try:
            connection.execute(
                "INSERT INTO pair_codes(code, workspace_id, expires_at) VALUES (?, ?, ?)",
                (code, workspace_id, int(time.time()) + PAIR_CODE_TTL),
            )
            return code
        except sqlite3.IntegrityError:
            continue


def is_safe_network(value: str) -> bool:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    private_ranges = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    return (
        network.version == 4
        and network.num_addresses <= MAX_SCAN_ADDRESSES
        and any(network.subnet_of(private) for private in private_ranges)
    )


def add_event(connection: sqlite3.Connection, workspace_id: str, kind: str, title: str, detail: str) -> None:
    connection.execute(
        "INSERT INTO events(workspace_id, kind, title, detail, created_at) VALUES (?, ?, ?, ?, ?)",
        (workspace_id, kind, title[:120], detail[:500], now_iso()),
    )


class ControllerHandler(BaseHTTPRequestHandler):
    server_version = "NetScopeController/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, maximum: int = 2_000_000) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > maximum:
            raise ValueError("Invalid request size.")
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise ValueError("JSON object required.")
        return payload

    def bearer(self) -> str:
        header = self.headers.get("Authorization", "")
        return header[7:].strip() if header.startswith("Bearer ") else ""

    def workspace(self, connection: sqlite3.Connection) -> sqlite3.Row | None:
        value = self.bearer()
        if not value:
            return None
        return connection.execute("SELECT * FROM workspaces WHERE admin_hash = ?", (token_hash(value),)).fetchone()

    def agent(self, connection: sqlite3.Connection) -> sqlite3.Row | None:
        value = self.bearer()
        if not value:
            return None
        return connection.execute("SELECT * FROM agents WHERE token_hash = ?", (token_hash(value),)).fetchone()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/global/workspace":
            self.get_workspace()
        elif path == "/api/global/agent/tasks":
            self.get_agent_task()
        else:
            self.serve_static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        routes = {
            "/api/global/workspaces": self.create_workspace,
            "/api/global/pair-code": self.create_pair_code,
            "/api/global/scans": self.create_scan,
            "/api/global/agent/pair": self.pair_agent,
            "/api/global/agent/heartbeat": self.agent_heartbeat,
            "/api/global/agent/results": self.agent_results,
        }
        handler = routes.get(path)
        if handler is None:
            self.send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
            return
        try:
            handler()
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except sqlite3.Error:
            self.send_json({"error": "Database operation failed."}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def create_workspace(self) -> None:
        client = self.headers.get("CF-Connecting-IP") or self.client_address[0]
        current = time.time()
        with RATE_LOCK:
            recent = [stamp for stamp in CREATE_ATTEMPTS.get(client, []) if current - stamp < CREATE_WINDOW]
            if len(recent) >= CREATE_LIMIT:
                self.send_json({"error": "Workspace creation limit reached. Try later."}, HTTPStatus.TOO_MANY_REQUESTS)
                return
            recent.append(current)
            CREATE_ATTEMPTS[client] = recent
        workspace_id = secrets.token_hex(12)
        admin_token = secrets.token_urlsafe(32)
        with db() as connection:
            connection.execute(
                "INSERT INTO workspaces(id, admin_hash, created_at) VALUES (?, ?, ?)",
                (workspace_id, token_hash(admin_token), now_iso()),
            )
            code = new_pair_code(connection, workspace_id)
            add_event(connection, workspace_id, "workspace", "Workspace created", "Private inventory workspace initialized.")
        self.send_json({"workspaceToken": admin_token, "pairCode": code, "expiresIn": PAIR_CODE_TTL}, HTTPStatus.CREATED)

    def create_pair_code(self) -> None:
        with db() as connection:
            workspace = self.workspace(connection)
            if workspace is None:
                self.send_json({"error": "Unauthorized."}, HTTPStatus.UNAUTHORIZED)
                return
            connection.execute("DELETE FROM pair_codes WHERE workspace_id = ?", (workspace["id"],))
            code = new_pair_code(connection, workspace["id"])
        self.send_json({"pairCode": code, "expiresIn": PAIR_CODE_TTL})

    def pair_agent(self) -> None:
        payload = self.read_json(4096)
        code = str(payload.get("code", "")).replace("-", "").upper()
        name = str(payload.get("name", "Desktop agent")).strip()[:80] or "Desktop agent"
        with db() as connection:
            row = connection.execute(
                "SELECT * FROM pair_codes WHERE code = ? AND expires_at >= ?", (code, int(time.time()))
            ).fetchone()
            if row is None:
                self.send_json({"error": "Pairing code is invalid or expired."}, HTTPStatus.UNAUTHORIZED)
                return
            agent_id = secrets.token_hex(12)
            agent_token = secrets.token_urlsafe(32)
            connection.execute(
                "INSERT INTO agents(id, workspace_id, name, token_hash, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (agent_id, row["workspace_id"], name, token_hash(agent_token), now_iso(), now_iso()),
            )
            connection.execute("DELETE FROM pair_codes WHERE code = ?", (code,))
            add_event(connection, row["workspace_id"], "agent", "Agent paired", f"{name} connected.")
        self.send_json({"agentId": agent_id, "agentToken": agent_token}, HTTPStatus.CREATED)

    def agent_heartbeat(self) -> None:
        payload = self.read_json(100_000)
        networks = payload.get("networks", [])
        safe_networks = []
        if isinstance(networks, list):
            for item in networks[:32]:
                if not isinstance(item, dict) or not is_safe_network(str(item.get("cidr", ""))):
                    continue
                safe_networks.append(
                    {"cidr": str(ipaddress.ip_network(item["cidr"], strict=False)), "interface": str(item.get("interface", ""))[:40]}
                )
        with db() as connection:
            agent = self.agent(connection)
            if agent is None:
                self.send_json({"error": "Unauthorized."}, HTTPStatus.UNAUTHORIZED)
                return
            connection.execute(
                "UPDATE agents SET networks_json = ?, last_seen = ? WHERE id = ?",
                (json.dumps(safe_networks), now_iso(), agent["id"]),
            )
        self.send_json({"ok": True})

    def get_agent_task(self) -> None:
        with db() as connection:
            agent = self.agent(connection)
            if agent is None:
                self.send_json({"error": "Unauthorized."}, HTTPStatus.UNAUTHORIZED)
                return
            connection.execute("UPDATE agents SET last_seen = ? WHERE id = ?", (now_iso(), agent["id"]))
            task = connection.execute(
                "SELECT * FROM tasks WHERE agent_id = ? AND status = 'pending' ORDER BY id LIMIT 1", (agent["id"],)
            ).fetchone()
            if task is None:
                self.send_json({"task": None})
                return
            connection.execute("UPDATE tasks SET status = 'running' WHERE id = ?", (task["id"],))
            self.send_json({"task": {"id": task["id"], "network": task["network"]}})

    def create_scan(self) -> None:
        payload = self.read_json(4096)
        agent_id = str(payload.get("agentId", ""))
        network = str(payload.get("network", ""))
        with db() as connection:
            workspace = self.workspace(connection)
            if workspace is None:
                self.send_json({"error": "Unauthorized."}, HTTPStatus.UNAUTHORIZED)
                return
            agent = connection.execute(
                "SELECT * FROM agents WHERE id = ? AND workspace_id = ?", (agent_id, workspace["id"])
            ).fetchone()
            if agent is None:
                raise ValueError("Unknown agent.")
            reported = {item["cidr"] for item in json.loads(agent["networks_json"])}
            normalized = str(ipaddress.ip_network(network, strict=False)) if is_safe_network(network) else ""
            if not normalized or normalized not in reported:
                raise ValueError("Scan target must be a private, directly connected agent network.")
            running = connection.execute(
                "SELECT 1 FROM tasks WHERE agent_id = ? AND status IN ('pending', 'running')", (agent_id,)
            ).fetchone()
            if running:
                self.send_json({"error": "This agent already has a scan queued."}, HTTPStatus.CONFLICT)
                return
            cursor = connection.execute(
                "INSERT INTO tasks(agent_id, network, status, created_at) VALUES (?, ?, 'pending', ?)",
                (agent_id, normalized, now_iso()),
            )
            add_event(connection, workspace["id"], "scan", "Scan queued", f"{agent['name']} will scan {normalized}.")
        self.send_json({"taskId": cursor.lastrowid}, HTTPStatus.ACCEPTED)

    def agent_results(self) -> None:
        payload = self.read_json()
        task_id = int(payload.get("taskId", 0))
        devices = payload.get("devices", [])
        if not isinstance(devices, list) or len(devices) > 512:
            raise ValueError("Invalid device result set.")
        with db() as connection:
            agent = self.agent(connection)
            if agent is None:
                self.send_json({"error": "Unauthorized."}, HTTPStatus.UNAUTHORIZED)
                return
            task = connection.execute(
                "SELECT * FROM tasks WHERE id = ? AND agent_id = ? AND status = 'running'", (task_id, agent["id"])
            ).fetchone()
            if task is None:
                raise ValueError("Unknown or completed task.")
            network = ipaddress.ip_network(task["network"])
            connection.execute("DELETE FROM devices WHERE agent_id = ?", (agent["id"],))
            accepted = 0
            for device in devices:
                if not isinstance(device, dict):
                    continue
                try:
                    address = ipaddress.ip_address(str(device.get("ip", "")))
                except ValueError:
                    continue
                if address not in network:
                    continue
                clean = dict(device)
                clean["services"] = clean.get("services", [])[:100] if isinstance(clean.get("services"), list) else []
                device_id = str(clean.get("id") or clean["ip"])[:100]
                connection.execute(
                    "INSERT INTO devices(agent_id, device_id, data_json, last_seen) VALUES (?, ?, ?, ?)",
                    (agent["id"], device_id, json.dumps(clean), now_iso()),
                )
                accepted += 1
            connection.execute(
                "UPDATE tasks SET status = 'complete', completed_at = ? WHERE id = ?", (now_iso(), task_id)
            )
            add_event(connection, agent["workspace_id"], "complete", "Agent scan complete", f"{agent['name']} found {accepted} device(s).")
        self.send_json({"accepted": accepted})

    def get_workspace(self) -> None:
        with db() as connection:
            workspace = self.workspace(connection)
            if workspace is None:
                self.send_json({"error": "Unauthorized."}, HTTPStatus.UNAUTHORIZED)
                return
            agents = []
            for row in connection.execute("SELECT * FROM agents WHERE workspace_id = ? ORDER BY created_at", (workspace["id"],)):
                agents.append(
                    {
                        "id": row["id"],
                        "name": row["name"],
                        "networks": json.loads(row["networks_json"]),
                        "lastSeen": row["last_seen"],
                    }
                )
            agent_ids = {agent["id"] for agent in agents}
            devices = [
                {**json.loads(row["data_json"]), "agentId": row["agent_id"]}
                for row in connection.execute(
                    "SELECT d.* FROM devices d JOIN agents a ON a.id = d.agent_id WHERE a.workspace_id = ?",
                    (workspace["id"],),
                )
                if row["agent_id"] in agent_ids
            ]
            events = [dict(row) for row in connection.execute(
                "SELECT kind, title, detail, created_at AS timestamp FROM events WHERE workspace_id = ? ORDER BY id DESC LIMIT 50",
                (workspace["id"],),
            )]
            tasks = [dict(row) for row in connection.execute(
                "SELECT t.id, t.agent_id AS agentId, t.network, t.status, t.created_at AS createdAt FROM tasks t JOIN agents a ON a.id = t.agent_id WHERE a.workspace_id = ? ORDER BY t.id DESC LIMIT 20",
                (workspace["id"],),
            )]
            pair = connection.execute(
                "SELECT code FROM pair_codes WHERE workspace_id = ? AND expires_at >= ? ORDER BY expires_at DESC LIMIT 1",
                (workspace["id"], int(time.time())),
            ).fetchone()
        self.send_json({"agents": agents, "devices": devices, "events": events, "tasks": tasks, "pairCode": pair["code"] if pair else None})

    def serve_static(self, request_path: str) -> None:
        pages = {"/", "/global", "/global/", "/inventory", "/inventory/", "/agents", "/agents/", "/activity", "/activity/"}
        relative = "index.html" if request_path in pages else request_path.lstrip("/")
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
        mime = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{mime}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(content)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the public NetScope controller.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    initialize_database()
    server = ThreadingHTTPServer((args.host, args.port), ControllerHandler)
    print(f"NetScope public controller is running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
