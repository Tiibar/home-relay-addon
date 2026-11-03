"""Tests du module Home Relay (bibliothèque standard uniquement).

    python3 -m unittest discover -s tests -v
"""

import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "home_relay", "app"))

import homeassistant  # noqa: E402
import main  # noqa: E402
import unifi  # noqa: E402
from privacy import clean_text, hashed_id, normalize_mac  # noqa: E402
from sender import Queue  # noqa: E402

SECRET = "s" * 40
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC = re.compile(r"\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b", re.I)

DEVICES = [
    {"mac": "AA:00:00:00:00:01", "type": "udm", "model": "UCGULTRA", "name": "Passerelle", "state": 1,
     "version": "4.1.13", "upgradable": False, "uptime": 86400, "ip": "198.51.100.1",
     "speedtest-status": {"rundate": 1762171200, "xput_download": 512.3, "xput_upload": 41.2, "latency": 9}},
    {"mac": "aa:00:00:00:00:02", "type": "usw", "model": "USW Flex Mini", "name": "Switch 1", "state": 1,
     "version": "2.1.6", "uptime": 3600, "ip": "198.51.100.2",
     "uplink": {"type": "wire", "uplink_mac": "aa:00:00:00:00:01", "speed": 1000}},
    {"mac": "aa:00:00:00:00:03", "type": "uap", "model": "U6 Mesh", "name": "Borne A", "state": 1,
     "version": "6.6.77.15516", "upgradable": True, "uptime": 7200, "num_sta": 5, "satisfaction": 93,
     "radio_table_stats": [{"radio": "na", "channel": 36, "cu_total": 21, "satisfaction": 95, "num_sta": 4},
                           {"radio": "ng", "channel": 6, "cu_total": 48, "satisfaction": 88, "num_sta": 1}],
     "uplink": {"type": "wireless", "uplink_mac": "aa:00:00:00:00:04", "signal": -61, "tx_rate": 866000}},
    {"mac": "aa:00:00:00:00:04", "type": "uap", "model": "U6 Lite", "name": "Borne B", "state": 0},
]

CLIENTS_NOW = [
    {"mac": "bb:00:00:00:00:01", "hostname": "iPhone-de-X", "ip": "198.51.100.50", "is_wired": False,
     "ap_mac": "aa:00:00:00:00:03", "signal": -58, "tx_bytes": 1000, "rx_bytes": 2000, "uptime": 600,
     "network": "Famille", "vlan": 0, "last_seen": 1762171500},
    {"mac": "bb:00:00:00:00:02", "name": "NAS", "ip": "198.51.100.12", "is_wired": True,
     "sw_mac": "aa:00:00:00:00:02", "sw_port": 3, "wired-tx_bytes": 5, "wired-rx_bytes": 6, "uptime": 99999,
     "network_id": "n2", "last_seen": 1762171500},
    {"mac": "bb:00:00:00:00:03", "ip": "198.51.100.43", "is_wired": False, "network": "IoT", "vlan": 20,
     "ap_mac": "aa:00:00:00:00:04", "tx_bytes": 1, "rx_bytes": 1},
]
HISTORY = [
    {"mac": "bb:00:00:00:00:01", "last_seen": 1762171500},          # déjà connecté : ignoré
    {"mac": "BB-00-00-00-00-09", "display_name": "Tablette", "last_seen": 1762100000, "last_uplink_name": "Borne B"},
]
NETWORKS = [{"_id": "n2", "name": "Famille"}]


class Privacy(unittest.TestCase):
    def test_hmac_reference(self):
        expected = hmac.new(SECRET.encode(), b"aa:bb:cc:dd:ee:ff", hashlib.sha256).hexdigest()[:32]
        self.assertEqual(hashed_id("AA-BB-CC-DD-EE-FF", SECRET), expected)
        # vecteur figé : changerait tous les identifiants s'il bougeait
        # vecteur figé (calculé avec openssl) : s'il changeait, tous les identifiants changeraient
        self.assertEqual(hashed_id("AA:BB:CC:DD:EE:FF", "x" * 40), "3bdd8d2fb714f276133d13ddef9cbb30")

    def test_stable_and_normalized(self):
        a = hashed_id("aa:bb:cc:dd:ee:ff", SECRET)
        self.assertEqual(a, hashed_id("AABBCCDDEEFF", SECRET))
        self.assertEqual(a, hashed_id("aabb.ccdd.eeff", SECRET))
        self.assertRegex(a, r"^[0-9a-f]{32}$")
        self.assertNotEqual(a, hashed_id("aa:bb:cc:dd:ee:ff", "t" * 40))
        self.assertNotIn("aabbccddeeff", a)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            normalize_mac("pas une mac")
        with self.assertRaises(ValueError):
            hashed_id("aa:bb:cc:dd:ee:ff", "")

    def test_clean_text(self):
        self.assertIsNone(clean_text("198.51.100.10"))
        self.assertIsNone(clean_text("aa:bb:cc:dd:ee:ff"))
        self.assertIsNone(clean_text("   "))
        self.assertEqual(clean_text(" Borne A "), "Borne A")


class UnifiMapping(unittest.TestCase):
    def test_devices(self):
        out = unifi.map_devices(DEVICES, SECRET)
        kinds = [d["kind"] for d in out]
        self.assertEqual(kinds, ["gateway", "switch", "ap", "ap"])
        cuisine = out[2]
        self.assertEqual(cuisine["radios"][0], {"band": "5g", "channel": 36, "utilization_pct": 21.0, "satisfaction": 95, "clients": 4})
        self.assertEqual(cuisine["uplink"], {"type": "wireless", "parent": "Borne B", "signal_dbm": -61, "rate_mbps": 866.0})
        self.assertEqual(out[1]["uplink"]["parent"], "Passerelle")
        self.assertEqual(out[3]["state"], "offline")

    def test_clients(self):
        out = unifi.map_clients(CLIENTS_NOW, HISTORY, NETWORKS, DEVICES, SECRET, now=1762171560)
        self.assertEqual(len(out), 4)
        iphone, nas, iot, tablette = out
        self.assertEqual(iphone["name"], "iPhone-de-X")
        self.assertEqual(iphone["uplink"], "Borne A")
        self.assertEqual(iphone["connected_since"], "2025-11-03T11:56:00Z")
        self.assertEqual((iphone["tx_bytes"], iphone["rx_bytes"]), (1000, 2000))
        self.assertEqual(nas["uplink"], "Switch 1 · port 3")
        self.assertEqual(nas["network"], "Famille")
        self.assertEqual((nas["tx_bytes"], nas["rx_bytes"]), (5, 6))
        self.assertIsNone(iot["name"])                       # jamais l'IP à la place du nom
        self.assertEqual(iot["network"], "IoT (VLAN 20)")
        self.assertFalse(tablette["online"])
        self.assertIsNone(tablette["tx_bytes"])
        self.assertEqual(tablette["id"], hashed_id("bb:00:00:00:00:09", SECRET))

    def test_threats_and_wan(self):
        threats = unifi.map_threats([
            {"_id": "abc", "timestamp": 1762171000000, "inner_alert_signature": "ET SCAN Suspicious inbound",
             "inner_alert_severity": 2, "inner_alert_category": "Attempted Information Leak",
             "inner_alert_action": "blocked", "src_ip": "203.0.113.4", "dest_ip": "198.51.100.50"},
            {"_id": "no-title", "timestamp": 1762171000000},
        ], SECRET)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["action"], "blocked")
        self.assertRegex(threats[0]["id"], r"^[0-9a-f]{32}$")
        wan, speed = unifi.map_wan([
            {"subsystem": "wan", "status": "ok", "wan_ip": "203.0.113.3", "isp_name": "FAI", "nameservers": ["192.0.2.53"]},
            {"subsystem": "www", "status": "ok", "latency": 9, "uptime": 1000, "drops": 0},
        ], DEVICES)
        self.assertEqual(wan["isp"], "FAI")
        self.assertEqual(speed["down_mbps"], 512.3)

    def test_no_ip_or_mac_leaves_home(self):
        payload = {
            "devices": unifi.map_devices(DEVICES, SECRET),
            "clients": unifi.map_clients(CLIENTS_NOW, HISTORY, NETWORKS, DEVICES, SECRET),
            "wan": unifi.map_wan([{"subsystem": "wan", "wan_ip": "203.0.113.3", "gateways": ["203.0.113.1"]}], DEVICES),
        }
        text = json.dumps(payload)
        self.assertIsNone(IP.search(text), IP.search(text) and IP.search(text).group(0))
        self.assertIsNone(MAC.search(text))


class HomeAssistantMapping(unittest.TestCase):
    STATES = [
        {"entity_id": "sensor.porte_battery", "state": "18", "attributes": {"device_class": "battery", "unit_of_measurement": "%", "friendly_name": "Porte batterie"}},
        {"entity_id": "sensor.cuisine_battery", "state": "unknown", "attributes": {"device_class": "battery", "unit_of_measurement": "%"}},
        {"entity_id": "light.garage", "state": "unavailable", "attributes": {"friendly_name": "Garage"}},
        {"entity_id": "climate.salon", "state": "heat", "attributes": {"friendly_name": "Salon", "current_temperature": 20.5, "current_humidity": 48, "temperature": 21}},
        {"entity_id": "update.home_assistant_core_update", "state": "on", "attributes": {"title": "Home Assistant Core", "installed_version": "2026.11.0", "latest_version": "2026.11.1"}},
        {"entity_id": "binary_sensor.somfy_etat", "state": "off", "attributes": {"friendly_name": "Alarme état"}},
    ]

    def test_map(self):
        out = homeassistant.map_states({"version": "2026.11.0"}, self.STATES, alarm_entities=["binary_sensor.somfy_etat"])
        self.assertEqual(out["batteries"], [{"entity_id": "sensor.porte_battery", "name": "Porte batterie", "level": 18.0}])
        self.assertEqual(out["unavailable"], [{"entity_id": "light.garage", "name": "Garage"}])
        self.assertEqual(out["climate"], [{"name": "Salon", "temperature": 20.5, "humidity": 48.0, "target": 21.0}])
        self.assertEqual(out["updates"][0]["latest"], "2026.11.1")
        self.assertEqual(out["alarm"], [{"name": "Alarme état", "state": "off"}])
        self.assertEqual(out["version"], "2026.11.0")


class SendQueue(unittest.TestCase):
    def test_keeps_on_failure_and_sends_in_order(self):
        with tempfile.TemporaryDirectory() as d:
            q = Queue(os.path.join(d, "q.json"))
            q.push({"n": 1})
            sent, err = q.flush(lambda p: ("retry", "hors ligne"))
            self.assertEqual((sent, err), (0, "hors ligne"))
            q.push({"n": 2})
            q2 = Queue(os.path.join(d, "q.json"))           # survit à un redémarrage
            self.assertEqual([i["n"] for i in q2.items], [1, 2])
            order = []
            sent, err = q2.flush(lambda p: (order.append(p["n"]) or ("ok", None)))
            self.assertEqual((sent, err, order, q2.items), (2, None, [1, 2], []))

    def test_drops_rejected_and_caps_size(self):
        q = Queue(None, max_items=3)
        for n in range(5):
            q.push({"n": n})
        self.assertEqual([i["n"] for i in q.items], [2, 3, 4])
        sent, err = q.flush(lambda p: ("drop", "invalide") if p["n"] == 2 else ("ok", None))
        self.assertEqual((sent, err, q.items), (2, "invalide", []))


class Options(unittest.TestCase):
    def test_validation(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "o.json")
            base = {"unifi_url": "https://gw", "unifi_username": "u", "unifi_password": "p",
                    "supabase_function_url": "https://x.supabase.co/functions/v1/ingest-home", "shared_secret": SECRET}
            for bad in ({"shared_secret": "court"}, {"supabase_function_url": "http://x"}, {"unifi_password": ""}):
                with open(p, "w") as f:
                    json.dump({**base, **bad}, f)
                with self.assertRaises(SystemExit):
                    main.load_options(p)
            with open(p, "w") as f:
                json.dump(base, f)
            self.assertEqual(main.load_options(p)["shared_secret"], SECRET)

    def test_version_matches_config(self):
        cfg = open(os.path.join(os.path.dirname(__file__), "..", "home_relay", "config.yaml"), encoding="utf-8").read()
        self.assertIn(f'version: "{main.VERSION}"', cfg)


if __name__ == "__main__":
    unittest.main()


class SupervisorToken(unittest.TestCase):
    def test_env_then_s6_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(homeassistant.supervisor_token({"SUPERVISOR_TOKEN": "abc"}, d), "abc")
            self.assertIsNone(homeassistant.supervisor_token({}, d))
            with open(os.path.join(d, "SUPERVISOR_TOKEN"), "w") as f:
                f.write("from-s6\n")
            self.assertEqual(homeassistant.supervisor_token({}, d), "from-s6")
            self.assertEqual(homeassistant.supervisor_token({"HASSIO_TOKEN": "old"}, d), "old")


class FakeClient(unifi.UnifiClient):
    def __init__(self, answers):
        super().__init__("https://gw.invalid", "u", "p")
        self.answers, self.calls = answers, []

    def get(self, path, params=None):
        self.calls.append(path)
        for key, value in self.answers.items():
            if path.endswith(key):
                if isinstance(value, Exception):
                    raise value
                return value
        raise unifi.UnifiError("HTTP 404 sur " + path)


class Threats(unittest.TestCase):
    def test_first_get_endpoint_that_answers_is_kept(self):
        c = FakeClient({"system-log/threat": unifi.UnifiError("HTTP 405 sur x"),
                        "stat/ips/event": [{"_id": "1", "inner_alert_signature": "ET SCAN", "timestamp": 1762171000000}]})
        rows, name = c.threats()
        self.assertEqual((len(rows), name), (1, "stat/ips/event"))
        c.calls.clear()
        c.threats()
        self.assertTrue(c.calls[0].endswith("stat/ips/event"))   # retenu, essayé en premier

    def test_v2_shape_and_redaction(self):
        c = FakeClient({"system-log/threat": {"data": [{"id": "x", "timestamp": 1762171000000, "severity": "HIGH",
                        "category": "SECURITY", "subcategory": "Scan",
                        "message": "Threat blocked from " + "203.0.113.9" + " to " + "198.51.100.50"}]}})
        rows, name = c.threats()
        self.assertEqual(name, "v2 system-log/threat")
        t = unifi.map_threats(rows, SECRET)[0]
        self.assertEqual(t["title"], "Threat blocked from [adresse] to [adresse]")
        self.assertEqual((t["severity"], t["category"]), ("HIGH", "Scan"))

    def test_general_logs_keep_only_ips(self):
        c = FakeClient({"stat/event": [{"key": "EVT_WU_Connected", "msg": "x"},
                                       {"key": "EVT_IPS_IpsAlert", "msg": "alerte", "time": 1762171000000}]})
        rows, name = c.threats()
        self.assertEqual((name, len(rows)), ("stat/event", 1))

    def test_disabled_cleanly_when_nothing_answers(self):
        c = FakeClient({})
        with self.assertRaises(unifi.ThreatsUnavailable) as e:
            c.threats()
        self.assertIn("HTTP 404", str(e.exception))
        n = len(c.calls)
        with self.assertRaises(unifi.ThreatsUnavailable):
            c.threats()
        self.assertEqual(len(c.calls), n)                         # pas de nouvel essai avant 24 h

    def test_collect_reports_disabled_source(self):
        c = FakeClient({"stat/device": DEVICES, "stat/sta": CLIENTS_NOW, "rest/networkconf": NETWORKS,
                        "stat/health": [], "clients/history": []})
        orig = homeassistant.read
        homeassistant.read = lambda: ({"version": "2026.11.0"}, [])
        try:
            p = main.collect({"shared_secret": SECRET}, c)
        finally:
            homeassistant.read = orig
        self.assertTrue(p["sources"]["unifi_threats"].startswith("désactivée"))
        self.assertEqual(p["sources"]["home_assistant"], "ok")
        self.assertEqual(p["unifi"]["threats"], [])
