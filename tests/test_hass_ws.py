"""Client WebSocket des registres Home Assistant, contre un faux serveur local."""

import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "home_relay", "app"))

import hass_ws  # noqa: E402


def server_frame(payload: bytes, opcode=0x1, fin=True) -> bytes:
    n = len(payload)
    head = bytes([(0x80 if fin else 0) | opcode])
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack("!H", n)
    else:
        head += bytes([127]) + struct.pack("!Q", n)
    return head + payload


def read_client_frame(conn) -> tuple[int, bytes]:
    def rd(n):
        b = b""
        while len(b) < n:
            b += conn.recv(n - len(b))
        return b
    b1, b2 = rd(2)
    assert b2 & 0x80, "trame client non masquée"
    n = b2 & 0x7F
    if n == 126:
        n = struct.unpack("!H", rd(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", rd(8))[0]
    mask = rd(4)
    data = bytes(b ^ mask[i % 4] for i, b in enumerate(rd(n)))
    return b1 & 0x0F, data


class FakeHA(threading.Thread):
    def __init__(self, token="jeton", big=False):
        super().__init__(daemon=True)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.token, self.big, self.commands = token, big, []

    def run(self):
        conn, _ = self.srv.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.recv(4096)
        key = [l.split(":", 1)[1].strip() for l in data.decode().split("\r\n") if l.lower().startswith("sec-websocket-key")][0]
        accept = base64.b64encode(hashlib.sha1((key + hass_ws.GUID).encode()).digest()).decode()
        conn.sendall(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n".encode()
                     + server_frame(json.dumps({"type": "auth_required"}).encode()))
        _, auth = read_client_frame(conn)
        ok = json.loads(auth).get("access_token") == self.token
        conn.sendall(server_frame(json.dumps({"type": "auth_ok" if ok else "auth_invalid"}).encode()))
        if not ok:
            conn.close()
            return
        results = {
            "config/device_registry/list": [{"id": "d1", "name": "Vanne"}] * (3000 if self.big else 1),
            "config/entity_registry/list": [{"entity_id": "climate.x", "device_id": "d1"}],
            "config/area_registry/list": [{"area_id": "a", "name": "Salon"}],
        }
        while True:
            opcode, payload = read_client_frame(conn)
            if opcode == 0x8:
                break
            if opcode == 0xA:
                continue
            msg = json.loads(payload)
            self.commands.append(msg["type"])
            body = json.dumps({"id": msg["id"], "type": "result", "success": True, "result": results[msg["type"]]}).encode()
            half = len(body) // 2   # message fragmenté + ping au milieu
            conn.sendall(server_frame(body[:half], fin=False) + server_frame(b"x", opcode=0x9)
                         + server_frame(body[half:], opcode=0x0))
        conn.close()


class HassWs(unittest.TestCase):
    def test_reads_the_three_registries_only(self):
        srv = FakeHA(big=True)
        srv.start()
        out = hass_ws.read_registries("jeton", host="127.0.0.1", port=srv.port, path="/core/websocket")
        srv.join(5)
        self.assertEqual(len(out["devices"]), 3000)
        self.assertEqual(out["areas"][0]["name"], "Salon")
        self.assertEqual(srv.commands, ["config/device_registry/list", "config/entity_registry/list", "config/area_registry/list"])
        self.assertTrue(set(srv.commands) <= hass_ws.READ_ONLY)

    def test_bad_token(self):
        srv = FakeHA(token="autre")
        srv.start()
        with self.assertRaises(hass_ws.WsError):
            hass_ws.read_registries("jeton", host="127.0.0.1", port=srv.port)
        srv.join(5)

    def test_frame_encoding_is_masked(self):
        f = hass_ws.encode_frame(b"abc", mask_key=b"\x01\x02\x03\x04")
        self.assertEqual(f[:2], bytes([0x81, 0x83]))
        self.assertEqual(f[6:], bytes([ord("a") ^ 1, ord("b") ^ 2, ord("c") ^ 3]))


if __name__ == "__main__":
    unittest.main()
