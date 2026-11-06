"""Reolink (1.2.6) : lecture seule de la sonnette et du hub via Home Assistant."""
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "home_relay", "app"))
import homeassistant  # noqa: E402

REGISTRY = {
    "devices": [
        {"id": "d-bell", "name": "Sonnette", "model": "Reolink Video Doorbell Battery", "manufacturer": "Reolink"},
        {"id": "d-hub", "name": "Hub Reolink", "model": "Reolink Home Hub Mini", "manufacturer": "Reolink"},
    ],
    "entities": [
        {"entity_id": "sensor.sonnette_battery", "device_id": "d-bell", "platform": "reolink", "translation_key": "battery"},
        {"entity_id": "sensor.sonnette_wi_fi_signal", "device_id": "d-bell", "platform": "reolink", "translation_key": "wifi_signal"},
        {"entity_id": "binary_sensor.sonnette_visitor", "device_id": "d-bell", "platform": "reolink", "translation_key": "visitor"},
        {"entity_id": "binary_sensor.sonnette_motion", "device_id": "d-bell", "platform": "reolink", "translation_key": "motion"},
        {"entity_id": "binary_sensor.sonnette_person", "device_id": "d-bell", "platform": "reolink", "translation_key": "person"},
        {"entity_id": "siren.sonnette_siren", "device_id": "d-bell", "platform": "reolink", "translation_key": "siren"},
        {"entity_id": "light.sonnette_status_led", "device_id": "d-bell", "platform": "reolink", "disabled_by": "user"},
        {"entity_id": "camera.sonnette_fluent", "device_id": "d-bell", "platform": "reolink"},
        {"entity_id": "update.hub_reolink_firmware", "device_id": "d-hub", "platform": "reolink"},
        {"entity_id": "sensor.hub_reolink_sd_0_storage", "device_id": "d-hub", "platform": "reolink"},
    ],
    "areas": [],
}
STATES = [
    {"entity_id": "sensor.sonnette_battery", "state": "87", "attributes": {"unit_of_measurement": "%"}},
    {"entity_id": "sensor.sonnette_wi_fi_signal", "state": "4", "attributes": {"unit_of_measurement": "bars", "ip": "192.168.4.196"}},
    {"entity_id": "binary_sensor.sonnette_visitor", "state": "off", "last_changed": "2026-11-06T10:41:03.512+00:00"},
    {"entity_id": "binary_sensor.sonnette_motion", "state": "off", "last_changed": "2026-11-06T10:50:00+00:00"},
    {"entity_id": "binary_sensor.sonnette_person", "state": "off", "last_changed": "2026-11-06T10:52:10+00:00"},
    {"entity_id": "siren.sonnette_siren", "state": "off"},
    {"entity_id": "camera.sonnette_fluent", "state": "idle", "attributes": {"entity_picture": "/api/camera_proxy/camera.sonnette_fluent?token=SECRET"}},
    {"entity_id": "update.hub_reolink_firmware", "state": "off"},
    {"entity_id": "sensor.hub_reolink_sd_0_storage", "state": "12"},
]


class Reolink(unittest.TestCase):
    def test_reads_only_the_few_values(self):
        out = homeassistant.map_reolink(STATES, REGISTRY)
        self.assertEqual(out["doorbell"], {
            "name": "Sonnette", "online": True, "battery_pct": 87.0, "wifi_signal": 4.0, "wifi_unit": "bars",
            "ring_state": "off", "last_ring_at": "2026-11-06T10:41:03Z", "last_motion_at": "2026-11-06T10:52:10Z",
        })
        self.assertEqual(out["hub"], {"name": "Hub Reolink", "online": True})

    def test_no_image_no_stream_no_address_no_token(self):
        text = json.dumps(homeassistant.map_reolink(STATES, REGISTRY))
        for bad in ("camera_proxy", "token", "SECRET", "192.168", "siren", "entity_picture", "fluent"):
            self.assertNotIn(bad, text)

    def test_offline_and_absent(self):
        off = [dict(s, state="unavailable") if s["entity_id"].startswith(("sensor.sonnette", "binary_sensor.sonnette", "siren", "camera"))
               else s for s in STATES]
        out = homeassistant.map_reolink(off, REGISTRY)
        self.assertFalse(out["doorbell"]["online"])
        self.assertIsNone(out["doorbell"]["battery_pct"])
        self.assertTrue(out["hub"]["online"])
        self.assertIsNone(homeassistant.map_reolink(STATES, {"devices": [], "entities": [], "areas": []}))

    def test_control_entities_are_never_read(self):
        self.assertIsNone(homeassistant._reolink_kind("switch.sonnette_battery", {"translation_key": "battery"}))
        self.assertIsNone(homeassistant._reolink_kind("number.sonnette_motion", {"translation_key": "motion"}))
        self.assertIsNone(homeassistant._reolink_kind("binary_sensor.sonnette_battery_state", {}))


if __name__ == "__main__":
    unittest.main()
