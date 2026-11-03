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
import urllib.error

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
     "radio_table": [{"radio": "na", "ht": "VHT80"}, {"radio": "ng", "ht": "bogus"}],
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
        self.assertEqual(cuisine["radios"][0], {"band": "5g", "channel": 36, "utilization_pct": 21.0, "satisfaction": 95, "clients": 4, "width_mhz": 80})
        self.assertIsNone(cuisine["radios"][1]["width_mhz"])
        self.assertEqual(cuisine["uplink"], {"type": "wireless", "parent": "Borne B", "signal_dbm": -61, "rate_mbps": 866.0, "port": None})
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

    def test_map_without_registry(self):
        """Repli sans registres : par entité, sans les entités non physiques."""
        states = self.STATES + [{"entity_id": "button.reboot", "state": "unavailable", "attributes": {}}]
        out = homeassistant.map_states({"version": "2026.11.0"}, states, alarm_entities=["binary_sensor.somfy_etat"])
        self.assertEqual(out["batteries"], [{"name": "Porte batterie", "area": None, "level": 18.0, "low": None}])
        self.assertEqual(out["unavailable"], [{"entity_id": "light.garage", "name": "Garage"}])
        self.assertEqual(out["unavailable_devices"], [])
        self.assertEqual(out["climate"], [{"entity_id": "climate.salon", "kind": "zone", "name": "Salon", "area": None, "temperature": 20.5,
                                           "humidity": 48.0, "target": 21.0, "hvac_mode": "heat", "hvac_action": None}])
        self.assertEqual(out["updates"][0]["latest"], "2026.11.1")
        self.assertEqual(out["alarm"], [{"name": "Alarme état", "state": "off"}])
        self.assertEqual(out["version"], "2026.11.0")


def st(eid, state, **attrs):
    return {"entity_id": eid, "state": state, "attributes": attrs}


class HomeAssistantByDevice(unittest.TestCase):
    """Cas réels : vanne Tado (HomeKit) hors ligne, lumières Hue, piles."""

    REGISTRY = {
        "areas": [{"area_id": "sam", "name": "Salle à manger"}, {"area_id": "hall", "name": "Hall d'entrée"},
                  {"area_id": "bureau", "name": "Bureau A&L"}, {"area_id": "salon", "name": "Salon"}],
        "devices": [
            {"id": "d_tado_sam", "name": "Tado Thermostat SàM", "manufacturer": "tado", "model": "VA02", "area_id": "sam"},
            {"id": "d_tado_bureau", "name": "Thermostat Bureau", "name_by_user": "Tado Bureau A&L", "manufacturer": "tado", "area_id": "bureau"},
            {"id": "d_hue_lamp", "name": "Lampe salon", "manufacturer": "Signify Netherlands B.V.", "area_id": "salon"},
            {"id": "d_hue_sensor", "name": "Sensor Hall d'entrée", "manufacturer": "Signify Netherlands B.V.", "area_id": "hall"},
            {"id": "d_shelly", "name": "Shelly garage", "manufacturer": "Shelly"},
            {"id": "d_meteo", "name": "Météo", "entry_type": "service"},
        ],
        "entities": [
            {"entity_id": "climate.tado_sam", "device_id": "d_tado_sam", "platform": "homekit_controller"},
            {"entity_id": "sensor.tado_sam_temperature", "device_id": "d_tado_sam", "platform": "homekit_controller"},
            {"entity_id": "sensor.tado_sam_humidity", "device_id": "d_tado_sam", "platform": "homekit_controller"},
            {"entity_id": "select.tado_sam_unit", "device_id": "d_tado_sam", "platform": "homekit_controller", "entity_category": "config"},
            {"entity_id": "binary_sensor.tado_bureau_low_battery", "device_id": "d_tado_bureau", "platform": "homekit_controller", "entity_category": "diagnostic"},
            {"entity_id": "climate.tado_bureau", "device_id": "d_tado_bureau", "platform": "homekit_controller"},
            {"entity_id": "light.lampe_salon", "device_id": "d_hue_lamp", "platform": "hue"},
            {"entity_id": "light.salon_groupe", "platform": "hue"},
            {"entity_id": "binary_sensor.hall_motion", "device_id": "d_hue_sensor", "platform": "hue"},
            {"entity_id": "switch.shelly_garage", "device_id": "d_shelly", "platform": "shelly"},
            {"entity_id": "sensor.shelly_garage_signal", "device_id": "d_shelly", "platform": "shelly", "entity_category": "diagnostic"},
            {"entity_id": "update.shelly_garage_firmware", "device_id": "d_shelly", "platform": "shelly"},
            {"entity_id": "weather.maison", "device_id": "d_meteo", "platform": "met"},
            {"entity_id": "light.vieux_shelly", "device_id": "d_shelly", "platform": "shelly", "disabled_by": "user"},
        ],
    }
    STATES = [
        st("climate.tado_sam", "unavailable", friendly_name="Tado SàM"),
        st("sensor.tado_sam_temperature", "unavailable"),
        st("sensor.tado_sam_humidity", "unavailable"),
        st("select.tado_sam_unit", "unavailable"),
        st("binary_sensor.tado_bureau_low_battery", "on", device_class="battery"),
        st("climate.tado_bureau", "heat", current_temperature=19.5, current_humidity=52, temperature=20),
        st("light.lampe_salon", "unavailable"),
        st("light.salon_groupe", "unavailable", is_hue_group=True),
        st("binary_sensor.hall_motion", "off", device_class="motion", battery_level=22),
        st("switch.shelly_garage", "on"),
        st("sensor.shelly_garage_signal", "unavailable"),
        st("update.shelly_garage_firmware", "unavailable"),
        st("weather.maison", "unavailable"),
        st("light.groupe_cuisine", "unavailable", entity_id=["light.a", "light.b"]),
        st("scene.soir", "unavailable"),
    ]

    def setUp(self):
        self.out = homeassistant.map_states({"version": "2026.11.0"}, self.STATES, registry=self.REGISTRY)

    def test_one_line_per_device(self):
        u = self.out["unavailable_devices"]
        self.assertEqual([(d["name"], d["area"], d["status"]) for d in u], [
            ("Tado Thermostat SàM", "Salle à manger", "offline"),
            ("Lampe salon", "Salon", "hue_off"),
        ])
        self.assertEqual((u[0]["unavailable"], u[0]["total"]), (3, 3))   # le réglage « unité » ne compte pas

    def test_ignores_groups_non_physical_and_diagnostics(self):
        names = {d["name"] for d in self.out["unavailable_devices"]}
        self.assertNotIn("Shelly garage", names)   # seul son capteur de diagnostic / sa mise à jour sont indisponibles
        self.assertNotIn("Météo", names)
        self.assertEqual(self.out["unavailable"], [])

    def test_batteries_all_sources_sorted(self):
        b = self.out["batteries"]
        self.assertEqual(b[0], {"name": "Tado Bureau A&L", "area": "Bureau A&L", "level": None, "low": True})
        self.assertEqual(b[1], {"name": "Sensor Hall d'entrée", "area": "Hall d'entrée", "level": 22.0, "low": None})

    def test_climate_uses_device_names(self):
        self.assertIn({"entity_id": "climate.tado_bureau", "kind": "zone", "name": "Tado Bureau A&L", "area": "Bureau A&L",
                       "temperature": 19.5, "humidity": 52.0, "target": 20.0, "hvac_mode": "heat", "hvac_action": None}, self.out["climate"])

    def test_no_entity_id_needed_for_display(self):
        for d in self.out["unavailable_devices"] + self.out["batteries"]:
            self.assertNotIn("entity_id", d)


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
        with open(os.path.join(os.path.dirname(__file__), "..", "home_relay", "config.yaml"), encoding="utf-8") as f:
            cfg = f.read()
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
    """Passerelle simulée : remplace seulement l'envoi réseau (_send) ; la liste
    blanche (_allowed) reste celle du vrai client."""

    def __init__(self, answers):
        super().__init__("https://gw.invalid", "u", "p")
        self.answers, self.calls = answers, []

    def _send(self, method, path, params, body):
        self.calls.append((method, path, body))
        if method == "POST" and path == unifi.LOGIN_PATH:
            return {}
        for (m, key), value in self.answers.items():
            if m == method and path.endswith(key):
                value = value(body) if callable(value) else value
                if isinstance(value, int):
                    raise urllib.error.HTTPError(path, value, "erreur", {}, None)
                return value
        raise urllib.error.HTTPError(path, 404, "Not Found", {}, None)

    def get(self, path, params=None):   # les tests GET répondent sans enveloppe « data »
        return super().get(path, params)


SYSLOG = "system-log/all"
THREAT = {"id": "65f0", "timestamp": 1762171000000, "category": "SECURITY", "subcategory": "INTRUSION_PREVENTION",
          "key": "THREAT_BLOCKED_V3", "severity": "HIGH", "title_raw": "Threat blocked",
          "message_raw": "{SRC_IP} tried to reach {CLIENT} — {SIGNATURE}",
          "parameters": {"SRC_IP": {"id": "203.0.113.9"}, "CLIENT": {"id": "aa:00:00:00:00:09", "name": "TV salon"},
                         "SIGNATURE": {"name": "ET SCAN Suspicious inbound"}}}


class Whitelist(unittest.TestCase):
    """Toute requête non-GET hors liste blanche est refusée AVANT l'envoi."""

    def setUp(self):
        self.c = FakeClient({})

    def test_only_two_non_get_requests(self):
        self.assertEqual(set(unifi.ALLOWED_NON_GET), {("POST", unifi.LOGIN_PATH), ("POST", unifi.SYSTEM_LOG_PATH)})

    def test_refuses_other_posts_and_methods(self):
        for method, path in [("POST", "/proxy/network/api/s/default/cmd/devmgr"),
                             ("POST", "/proxy/network/v2/api/site/default/system-log/critical"),
                             ("POST", "/proxy/network/v2/api/site/autre/system-log/all"),
                             ("PUT", "/proxy/network/api/s/default/rest/networkconf/1"),
                             ("DELETE", "/proxy/network/api/s/default/rest/user/1"),
                             ("PATCH", unifi.LOGIN_PATH),
                             ("POST", "/proxy/network/v2/api/site/default/system-log/all/../../cmd")]:
            with self.assertRaises(unifi.ForbiddenRequest, msg=f"{method} {path}"):
                self.c._request(method, path, body={})
        self.assertEqual(self.c.calls, [])        # rien n'est parti

    def test_refuses_unknown_body_fields(self):
        path = unifi.SYSTEM_LOG_PATH.format(site="default")
        with self.assertRaises(unifi.ForbiddenRequest):
            self.c._request("POST", path, body={"timestampFrom": 1, "cmd": "restart"})
        with self.assertRaises(unifi.ForbiddenRequest):
            self.c._request("GET", "/proxy/network/api/s/default/stat/sta", body={"x": 1})
        self.assertEqual(self.c.calls, [])

    def test_allowed_search_goes_through(self):
        self.c.answers = {("POST", SYSLOG): {"data": [], "total_element_count": 0}}
        self.c.search_system_log(0, 1)
        method, path, body = self.c.calls[-1]
        self.assertEqual((method, path), ("POST", "/proxy/network/v2/api/site/default/system-log/all"))
        self.assertEqual(set(body), {"timestampFrom", "timestampTo", "pageSize", "pageNumber", "categories"})
        self.assertEqual(body["categories"], ["SECURITY"])


class Threats(unittest.TestCase):
    def test_system_log_threats_redacted_with_direction_and_blocked(self):
        c = FakeClient({("POST", SYSLOG): {"data": [THREAT, {"id": "x", "timestamp": 1762171000000,
                                                             "category": "CLIENT_DEVICES", "key": "CLIENT_ROAMED"}],
                                           "total_element_count": 2}})
        rows, name = c.threats()
        self.assertEqual((name, len(rows)), ("system-log", 1))     # seule la catégorie SECURITY est gardée
        t = unifi.map_threats(rows, SECRET)[0]
        self.assertEqual(t["title"], "Threat blocked")
        self.assertEqual((t["severity"], t["category"], t["blocked"], t["action"]), ("HIGH", "INTRUSION_PREVENTION", True, "blocked"))
        self.assertIsNone(t["direction"])                         # pas indiquée : rien d'inventé
        self.assertIsNone(IP.search(json.dumps(t)))
        self.assertIsNone(MAC.search(json.dumps(t)))

    def test_message_rendered_and_redacted_when_no_title(self):
        t = unifi.map_threats([{**THREAT, "title_raw": None, "key": "THREAT_DETECTED_INBOUND"}], SECRET)[0]
        self.assertEqual(t["title"], "[adresse] tried to reach TV salon — ET SCAN Suspicious inbound")
        self.assertEqual((t["direction"], t["blocked"]), ("entrant", False))

    def test_category_filter_refused_then_filtered_locally(self):
        seen = []

        def answer(body):
            seen.append(body.get("categories"))
            return 400 if body.get("categories") else {"data": [THREAT], "total_element_count": 1}
        c = FakeClient({("POST", SYSLOG): answer})
        rows, _ = c.threats()
        self.assertEqual((seen, len(rows)), ([["SECURITY"], None], 1))

    def test_pages_and_window_since_last_read(self):
        page = [dict(THREAT, id=f"t{i}") for i in range(100)]
        c = FakeClient({("POST", SYSLOG): lambda b: {"data": page if b["pageNumber"] == 0 else page[:3],
                                                    "total_element_count": 103}})
        rows, _ = c.threats()
        self.assertEqual(len(rows), 103)
        first_until = c.calls[-1][2]["timestampTo"]
        c.threats()
        self.assertEqual(c.calls[-1][2]["timestampFrom"], first_until)   # pas de relecture de 24 h

    def test_legacy_get_still_used_on_old_versions(self):
        c = FakeClient({("POST", SYSLOG): 405,
                        ("GET", "stat/ips/event"): [{"_id": "1", "inner_alert_signature": "ET SCAN", "timestamp": 1762171000000}]})
        rows, name = c.threats()
        self.assertEqual((len(rows), name), (1, "stat/ips/event"))

    def test_disabled_cleanly_with_short_message(self):
        c = FakeClient({})
        with self.assertRaises(unifi.ThreatsUnavailable) as e:
            c.threats()
        self.assertEqual(str(e.exception), "menaces non disponibles sur cette passerelle")
        self.assertIn("HTTP 404", c.threats_reason)                # détail gardé pour le journal du module
        n = len(c.calls)
        with self.assertRaises(unifi.ThreatsUnavailable):
            c.threats()
        self.assertEqual(len(c.calls), n)                         # pas de nouvel essai avant 24 h

    def test_collect_reports_disabled_source(self):
        c = FakeClient({("GET", "stat/device"): DEVICES, ("GET", "stat/sta"): CLIENTS_NOW,
                        ("GET", "rest/networkconf"): NETWORKS, ("GET", "stat/health"): [],
                        ("GET", "clients/history"): []})
        orig = homeassistant.read
        homeassistant.read = lambda: {"config": {"version": "2026.11.0"}, "states": [], "registry": None,
                                      "registry_error": "test"}
        try:
            p = main.collect({"shared_secret": SECRET}, c)
        finally:
            homeassistant.read = orig
        self.assertTrue(p["sources"]["unifi_threats"].startswith("désactivée"))
        self.assertEqual(p["sources"]["home_assistant"], "ok")
        self.assertEqual(p["sources"]["home_assistant_registry"], "erreur : test")
        self.assertEqual(p["unifi"]["threats"], [])


class SystemLogCategories(unittest.TestCase):
    """Extension autorisée : même recherche, catégories CLIENT_DEVICES et INTERNET_AND_WAN."""

    def test_only_three_categories_allowed(self):
        self.assertEqual(unifi.SYSTEM_LOG_CATEGORIES, {"SECURITY", "CLIENT_DEVICES", "INTERNET_AND_WAN"})
        c = FakeClient({})
        path = unifi.SYSTEM_LOG_PATH.format(site="default")
        for cats in (["ADMIN_ACTIVITY"], ["SECURITY", "SYSTEM"], "SECURITY", [{"x": 1}]):
            with self.assertRaises(unifi.ForbiddenRequest, msg=str(cats)):
                c._request("POST", path, body={"timestampFrom": 0, "timestampTo": 1, "categories": cats})
        self.assertEqual(c.calls, [])

    def test_threats_backfill_30_days_then_incremental_then_daily(self):
        c = FakeClient({("POST", SYSLOG): {"data": [], "total_element_count": 0}})
        c.threats()
        b = c.calls[-1][2]
        self.assertAlmostEqual((b["timestampTo"] - b["timestampFrom"]) / 86400_000, 30, places=2)
        until = b["timestampTo"]
        c.threats()
        self.assertEqual(c.calls[-1][2]["timestampFrom"], until)
        c.threats_backfill_ms -= 86401                     # un jour plus tard : relecture des 30 jours
        c.threats()
        b = c.calls[-1][2]
        self.assertAlmostEqual((b["timestampTo"] - b["timestampFrom"]) / 86400_000, 30, places=2)

    def test_log_events_backfill_and_batches(self):
        rows = [{"id": f"e{i}", "timestamp": 1762171000000 + i, "category": "CLIENT_DEVICES", "key": "CLIENT_ROAMED"}
                for i in range(100)]
        c = FakeClient({("POST", SYSLOG): lambda b: {"data": rows if b["pageNumber"] < 20 else [], "total_element_count": 2000}})
        out = c.log_events("CLIENT_DEVICES", 7)
        b = next(call[2] for call in c.calls if call[2] and "categories" in call[2])
        self.assertEqual(b["categories"], ["CLIENT_DEVICES"])
        self.assertAlmostEqual((b["timestampTo"] - b["timestampFrom"]) / 86400_000, 7, places=2)
        self.assertEqual(len(out), unifi.EVENTS_PER_SEND)
        self.assertEqual(len(c.pending_events["CLIENT_DEVICES"]), 2000 - unifi.EVENTS_PER_SEND)
        c.answers = {("POST", SYSLOG): {"data": [], "total_element_count": 0}}
        self.assertEqual(len(c.log_events("CLIENT_DEVICES", 7)), 2000 - unifi.EVENTS_PER_SEND)

    def test_threat_origin_internal_or_internet(self):
        internal = {**THREAT, "parameters": {"SRC_IP": {"id": "198.51.100.20"}, "SIGNATURE": {"name": "ET POLICY"}}}
        t_int = unifi.map_threats([internal], SECRET, {"198.51.100.20": "Caméra jardin"})[0]
        self.assertEqual((t_int["origin"], t_int["device_name"]), ("interne", "Caméra jardin"))
        t_ext = unifi.map_threats([THREAT], SECRET)[0]
        self.assertEqual((t_ext["origin"], t_ext["device_name"]), ("internet", None))
        self.assertIsNone(IP.search(json.dumps([t_int, t_ext])))

    def test_threat_source_and_target(self):
        """Apple TV → iPhone : source = Apple TV (adresse connue), cible = le CLIENT (iPhone)."""
        ip_names, mac_ips = unifi.client_lookup([
            {"ip": "198.51.100.30", "mac": "aa:00:00:00:00:51", "name": "Apple TV"},
            {"ip": "198.51.100.31", "mac": "aa:00:00:00:00:52", "name": "iPhone de Léa"},
        ])
        t = {**THREAT, "title_raw": "Threat Detected", "parameters": {
            "SRC_IP": {"id": "198.51.100.30"}, "CLIENT": {"id": "aa:00:00:00:00:52", "name": "iPhone de Léa"}}}
        m = unifi.map_threats([t], SECRET, ip_names, mac_ips)[0]
        self.assertEqual((m["origin"], m["device_name"], m["target_name"]), ("interne", "Apple TV", "iPhone de Léa"))
        ext = unifi.map_threats([THREAT], SECRET, ip_names, mac_ips)[0]
        self.assertEqual((ext["origin"], ext["device_name"], ext["target_name"]), ("internet", None, "TV salon"))
        out = {**THREAT, "key": "THREAT_DETECTED_OUTBOUND", "parameters": {"CLIENT": {"id": "aa:00:00:00:00:51", "name": "Apple TV"},
                                                                           "DST_IP": {"id": "203.0.113.7"}}}
        o = unifi.map_threats([out], SECRET, ip_names, mac_ips)[0]
        self.assertEqual((o["origin"], o["device_name"], o["target_name"]), ("interne", "Apple TV", None))
        self.assertIsNone(IP.search(json.dumps([m, ext, o])))

    def test_client_events_mapping_without_ssid_or_address(self):
        rows = [
            {"id": "1", "timestamp": 1762171000000, "key": "CLIENT_ROAMED", "category": "CLIENT_DEVICES",
             "parameters": {"CLIENT": {"id": "aa:00:00:00:00:31", "name": "iPhone"}, "DEVICE_FROM": {"id": "x", "name": "Borne salon"},
                            "DEVICE_TO": {"id": "y", "name": "Borne bureau"}, "SSID": {"name": "MaisonWifi"}}},
            {"id": "2", "timestamp": 1762171060000, "key": "CLIENT_DISCONNECTED_WIRELESS",
             "parameters": {"CLIENT": {"id": "aa:00:00:00:00:31", "name": "iPhone"}, "DEVICE": {"name": "Borne bureau"},
                            "DURATION": {"name": "1h 2m 3s"}}},
            {"id": "3", "timestamp": 1762171120000, "key": "CLIENT_CONNECTED_WIRELESS",
             "parameters": {"CLIENT": {"id": "aa:00:00:00:00:31", "name": "iPhone"}, "DEVICE": {"name": "Borne salon"}}},
            {"id": "4", "timestamp": 1762171120000, "key": "SOMETHING_ELSE"},
        ]
        out = unifi.map_client_events(rows, SECRET)
        self.assertEqual([e["kind"] for e in out], ["roaming", "deconnexion", "connexion"])
        self.assertEqual((out[0]["ap_from"], out[0]["ap_to"]), ("Borne salon", "Borne bureau"))
        self.assertEqual(out[1]["duration_s"], 3723)
        self.assertEqual(out[0]["client_id"], hashed_id("aa:00:00:00:00:31", SECRET))
        text = json.dumps(out)
        self.assertNotIn("MaisonWifi", text)
        self.assertIsNone(MAC.search(text))

    def test_wan_events_mapping(self):
        out = unifi.map_wan_events([
            {"id": "a", "timestamp": 1762171000000, "key": "WAN_HIGH_LATENCY", "title_raw": "High Latency Detected"},
            {"id": "b", "timestamp": 1762171000000, "key": "WAN_PACKET_LOSS", "title_raw": "Packet loss on 203.0.113.1"},
        ], SECRET)
        self.assertEqual([e["kind"] for e in out], ["latence_elevee", "perte_paquets"])
        self.assertIsNone(IP.search(json.dumps(out)))


class NetworkOfClient(unittest.TestCase):
    """Un client sans champ `network` (ex. Apple TV) n'est pas « sans réseau »."""

    def test_fallbacks(self):
        nets = [{"_id": "n1", "name": "Famille"}, {"_id": "n3", "name": "IoT", "vlan": 20}]
        rows = [
            {"mac": "aa:00:00:00:00:41", "name": "Apple TV", "is_wired": True, "vlan": 20},
            {"mac": "aa:00:00:00:00:42", "name": "HomePod", "last_connection_network_id": "n3"},
            {"mac": "aa:00:00:00:00:43", "name": "iPad", "essid": "WifiMaison"},
            {"mac": "aa:00:00:00:00:44", "name": "Mac", "last_connection_network_name": "Famille"},
        ]
        out = {c["name"]: c["network"] for c in unifi.map_clients(rows, [], nets, [], SECRET)}
        self.assertEqual(out, {"Apple TV": "IoT (VLAN 20)", "HomePod": "IoT", "iPad": "WifiMaison", "Mac": "Famille"})


class AlarmReadOnly(unittest.TestCase):
    """Panneau d'alarme désactivé volontairement : entités Somfy restantes, sinon « non suivi »."""

    def test_somfy_entities_when_panel_disabled(self):
        states = [
            {"entity_id": "select.somfy_security_level", "state": "disarmed", "attributes": {"friendly_name": "Niveau de sécurité"}},
            {"entity_id": "binary_sensor.porte_entree", "state": "off", "attributes": {"friendly_name": "Porte d'entrée", "device_class": "door"}},
            {"entity_id": "sensor.porte_entree_signal", "state": "80", "attributes": {"friendly_name": "Signal"}},
            {"entity_id": "binary_sensor.cuisine_motion", "state": "off", "attributes": {"device_class": "motion"}},
        ]
        registry = {
            "devices": [{"id": "d1", "manufacturer": "Somfy", "name": "Somfy Protect"},
                        {"id": "d2", "manufacturer": "Somfy", "name": "Porte d'entrée"},
                        {"id": "d3", "manufacturer": "Philips", "name": "Cuisine"}],
            "entities": [{"entity_id": "select.somfy_security_level", "device_id": "d1", "platform": "mqtt"},
                         {"entity_id": "binary_sensor.porte_entree", "device_id": "d2", "platform": "mqtt"},
                         {"entity_id": "sensor.porte_entree_signal", "device_id": "d2", "platform": "mqtt"},
                         {"entity_id": "binary_sensor.cuisine_motion", "device_id": "d3", "platform": "hue"}],
            "areas": [],
        }
        out = homeassistant.map_states({}, states, registry=registry)
        self.assertEqual(out["alarm_tracking"], "suivi")
        self.assertEqual(sorted(a["name"] for a in out["alarm"]), ["Niveau de sécurité", "Porte d'entrée"])

    def test_not_tracked_is_reported_as_deliberate(self):
        out = homeassistant.map_states({}, [{"entity_id": "light.salon", "state": "on", "attributes": {}}])
        self.assertEqual((out["alarm"], out["alarm_tracking"]), ([], "non_suivi"))
        c = FakeClient({})
        orig = homeassistant.read
        homeassistant.read = lambda: {"config": {}, "states": [], "registry": None, "registry_error": "test"}
        try:
            p = main.collect({"shared_secret": SECRET}, c)
        finally:
            homeassistant.read = orig
        self.assertEqual(p["sources"]["alarme"], "désactivée : état non suivi volontairement (lecture seule)")


class LocalTime(unittest.TestCase):
    def test_timezone_sources(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main.local_timezone({"TZ": "Europe/Paris"}, d), "Europe/Paris")
            self.assertEqual(main.local_timezone({}, d), "Europe/Brussels")
            with open(os.path.join(d, "TZ"), "w") as f:
                f.write("Europe/Brussels\n")
            self.assertEqual(main.local_timezone({}, d), "Europe/Brussels")

    def test_log_time_is_local(self):
        import logging as lg
        rec = lg.LogRecord("x", lg.INFO, __file__, 1, "m", None, None)
        rec.created = 1762171200.0                      # 2025-11-03 12:00 UTC
        self.assertEqual(main.LocalFormatter("Europe/Brussels").formatTime(rec), "2025-11-03 13:00:00")
        self.assertEqual(main.LocalFormatter("Pas/UnFuseau").formatTime(rec), "2025-11-03 13:00:00")


class UplinkPortAndVendor(unittest.TestCase):
    def test_port_and_vendor(self):
        devs = [dict(DEVICES[1], uplink={"type": "wire", "uplink_mac": "aa:00:00:00:00:01", "speed": 1000, "uplink_remote_port": 4})]
        self.assertEqual(unifi.map_devices(devs, SECRET)[0]["uplink"]["port"], 4)
        self.assertIsNone(unifi.map_devices(DEVICES, SECRET)[2]["uplink"]["port"])        # sans fil
        c = unifi.map_clients([dict(CLIENTS_NOW[0], oui="Espressif Inc.")], [], [], DEVICES, SECRET)[0]
        self.assertEqual(c["vendor"], "Espressif Inc.")


class Heating(unittest.TestCase):
    REGISTRY = {
        "areas": [{"area_id": "sam", "name": "Salle à manger"}],
        "devices": [{"id": "d1", "name": "Tado SàM fenêtre", "manufacturer": "tado", "area_id": "sam"}],
        "entities": [
            {"entity_id": "climate.tado_sam", "device_id": "d1", "platform": "homekit_controller"},
            {"entity_id": "sensor.tado_sam_humidity", "device_id": "d1", "platform": "homekit_controller"},
            {"entity_id": "weather.maison", "platform": "met"},
        ],
    }
    STATES = [
        st("climate.tado_sam", "heat", current_temperature=19.4, temperature=20.5, hvac_action="heating"),
        st("sensor.tado_sam_humidity", "54", device_class="humidity", unit_of_measurement="%"),
        st("weather.maison", "rainy", temperature=8.2, humidity=91),
    ]

    def test_thermostat_and_outdoor(self):
        out = homeassistant.map_states({}, self.STATES, registry=self.REGISTRY)
        zone, outdoor = out["climate"]
        self.assertEqual(zone, {"entity_id": "climate.tado_sam", "kind": "zone", "name": "Tado SàM fenêtre", "area": "Salle à manger",
                                "temperature": 19.4, "humidity": 54.0, "target": 20.5, "hvac_mode": "heat", "hvac_action": "heating"})
        self.assertEqual(outdoor["kind"], "outdoor")
        self.assertEqual((outdoor["name"], outdoor["temperature"], outdoor["humidity"]), ("Extérieur", 8.2, 91.0))

    def test_unavailable_thermostat_and_chosen_weather(self):
        states = [st("climate.tado_sam", "unavailable"), st("sensor.exterieur", "6.5", device_class="temperature")]
        out = homeassistant.map_states({}, states, registry=self.REGISTRY, weather_entity="sensor.exterieur")
        self.assertEqual(out["climate"][0]["hvac_mode"], None)
        self.assertEqual(out["climate"][1]["temperature"], 6.5)
