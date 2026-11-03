"""Client WebSocket minimal (bibliothèque standard) pour l'API de Home Assistant.

Sert uniquement à LIRE les registres (appareils, entités, pièces), que l'API
REST ne fournit pas :
  config/device_registry/list, config/entity_registry/list,
  config/area_registry/list
Aucune autre commande n'est envoyée (liste blanche dans `READ_ONLY`).
"""

import base64
import hashlib
import json
import os
import socket
import struct

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
READ_ONLY = {"config/device_registry/list", "config/entity_registry/list", "config/area_registry/list"}
MAX_MESSAGE = 64 * 1024 * 1024


class WsError(Exception):
    pass


def encode_frame(payload: bytes, opcode: int = 0x1, mask_key: bytes | None = None) -> bytes:
    """Trame client (toujours masquée, RFC 6455)."""
    mask_key = mask_key or os.urandom(4)
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack("!Q", n)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return head + mask_key + masked


class Connection:
    def __init__(self, sock: socket.socket, leftover: bytes = b""):
        self.sock = sock
        self.buf = leftover

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self.buf)))
            if not chunk:
                raise WsError("connexion fermée")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send_json(self, obj) -> None:
        self.sock.sendall(encode_frame(json.dumps(obj).encode("utf-8")))

    def recv_json(self):
        parts, total = [], 0
        while True:
            b1, b2 = self._read(2)
            fin, opcode = b1 & 0x80, b1 & 0x0F
            n = b2 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._read(8))[0]
            mask = self._read(4) if b2 & 0x80 else None
            data = self._read(n)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x8:
                raise WsError("connexion fermée par Home Assistant")
            if opcode == 0x9:  # ping -> pong
                self.sock.sendall(encode_frame(data, opcode=0xA))
                continue
            if opcode == 0xA:
                continue
            total += n
            if total > MAX_MESSAGE:
                raise WsError("message trop grand")
            parts.append(data)
            if fin:
                return json.loads(b"".join(parts).decode("utf-8"))


def connect(host: str, port: int, path: str, timeout: float = 20) -> Connection:
    sock = socket.create_connection((host, port), timeout=timeout)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall((
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise WsError("pas de réponse à l'ouverture du WebSocket")
        data += chunk
    head, leftover = data.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    if " 101 " not in lines[0] + " ":
        raise WsError(f"ouverture refusée ({lines[0][:60]})")
    expected = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
    if headers.get("sec-websocket-accept") != expected:
        raise WsError("réponse WebSocket invalide")
    return Connection(sock, leftover)


def read_registries(token: str, host: str = "supervisor", port: int = 80, path: str = "/core/websocket", timeout: float = 20):
    """Renvoie {"devices": [...], "entities": [...], "areas": [...]}."""
    conn = connect(host, port, path, timeout)
    try:
        if conn.recv_json().get("type") != "auth_required":
            raise WsError("authentification non demandée")
        conn.send_json({"type": "auth", "access_token": token})
        if conn.recv_json().get("type") != "auth_ok":
            raise WsError("authentification refusée")
        out = {}
        for i, (name, cmd) in enumerate((("devices", "config/device_registry/list"),
                                         ("entities", "config/entity_registry/list"),
                                         ("areas", "config/area_registry/list")), start=1):
            assert cmd in READ_ONLY
            conn.send_json({"id": i, "type": cmd})
            while True:
                msg = conn.recv_json()
                if msg.get("id") == i:
                    break
            if not msg.get("success"):
                raise WsError(f"{cmd} refusé")
            out[name] = msg.get("result") or []
        return out
    finally:
        try:
            conn.sock.sendall(encode_frame(b"", opcode=0x8))
        except OSError:
            pass
        conn.sock.close()
