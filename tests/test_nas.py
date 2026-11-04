"""Tests du NAS Synology (lecture seule, liste blanche).

    python3 -m unittest discover -s tests -v
"""

import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "home_relay", "app"))

import main  # noqa: E402
import nas  # noqa: E402

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

STORAGE = {
    "disks": [
        {"id": "sata1", "num_id": 1, "device": "/dev/sata1", "model": "ST4000VN008", "vendor": "Seagate", "serial": "ZDH0SERIAL1",
         "size_total": "4000787030016", "temp": 37, "status": "normal", "overview_status": "normal", "smart_status": "normal"},
        {"id": "sata2", "num_id": 2, "device": "/dev/sata2", "model": "ST4000VN008", "vendor": "Seagate", "serial": "ZDH0SERIAL2",
         "size_total": "4000787030016", "temp": 47, "status": "normal", "overview_status": "warning"},
    ],
    "storagePools": [{"id": "reuse_1", "num_id": 1, "status": "normal", "device_type": "shr_with_1_disk_protect",
                      "scrubbing": {"status": "done", "last_done_time": 1761962400}}],
    "volumes": [{"id": "volume_1", "vol_path": "/volume1", "status": "normal", "size": {"total": "11000000000000", "used": "6600000000000"}}],
}
SYSTEM = {"model": "DS418play", "firmware_ver": "DSM 7.1.1-42962 Update 6", "sys_temp": 42, "sys_tempwarn": False,
          "up_time": "1234:05:06", "serial": "SERIALNAS", "lan_ip": "198.51.100.12"}
HEALTH = {"healthInfo": {"overview": {"smart": "normal", "ihm": "normal"},
                         "last_test": {"type": "quick", "result": "normal", "time": 1761962400}}}
SMART = {"smartInfo": [{"id": "9", "name": "Power_On_Hours", "raw": "70123"}]}


class FakeNas(nas.NasClient):
    """Remplace le réseau : enregistre chaque requête, répond d'après une table."""

    def __init__(self, answers=None, **kw):
        super().__init__("https://nas.example", "home-relay", "x", False)
        self.sent = []
        self.answers = answers or {}

    def _send(self, http_method, path, params):
        self.sent.append((http_method, path, dict(params)))
        key = (params["api"], params["method"])
        if key == ("SYNO.API.Info", "query"):
            return {"success": True, "data": {"SYNO.API.Auth": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 7}}}
        if key == ("SYNO.API.Auth", "login"):
            return {"success": True, "data": {"sid": "SID"}}
        a = self.answers.get(key, {"success": False, "error": {"code": 105}})
        return a


def full_answers():
    ok = lambda d: {"success": True, "data": d}  # noqa: E731
    return {
        ("SYNO.Core.System", "info"): ok(SYSTEM),
        ("SYNO.Core.System.Utilization", "get"): ok({"cpu": {"user_load": 3, "system_load": 2, "other_load": 1}, "memory": {"real_usage": 31}}),
        ("SYNO.Storage.CGI.Storage", "load_info"): ok(STORAGE),
        ("SYNO.Storage.CGI.Smart", "get_health_info"): ok(HEALTH),
        ("SYNO.Storage.CGI.Smart", "get_smart_info"): ok(SMART),
        ("SYNO.Core.Upgrade.Server", "check"): ok({"update": {"available": True, "version": "DSM 7.2.2-72806"}}),
        ("SYNO.Core.Package", "list"): ok({"packages": [{"id": "SynologyPhotos", "name": "Synology Photos", "version": "1.6.1-0217"},
                                                         {"id": "HyperBackup", "name": "Hyper Backup", "version": "4.1.0-3718"}]}),
        ("SYNO.Core.Package.Server", "list"): ok({"packages": [{"id": "SynologyPhotos", "version": "1.7.0-0300"},
                                                                {"id": "HyperBackup", "version": "4.1.0-3718"}]}),
    }


class Whitelist(unittest.TestCase):
    def test_only_read_calls(self):
        for api, method in nas.ALLOWED_CALLS:
            self.assertRegex(method, r"^(query|login|info|get|list|load_info|get_health_info|get_smart_info|check)$")
            nas.check_call(api, method, "POST" if (api, method) in nas.POST_CALLS else "GET", {"api": api, "version": "1", "method": method})

    def test_write_calls_refused_before_sending(self):
        c = FakeNas()
        for api, method in [("SYNO.Core.System", "reboot"), ("SYNO.Core.System", "shutdown"), ("SYNO.Core.Package", "uninstall"),
                            ("SYNO.Core.Upgrade", "start"), ("SYNO.Storage.CGI.Smart", "do_smart_test"), ("SYNO.Core.Share", "list"),
                            ("SYNO.FileStation.Delete", "start"), ("SYNO.Core.User", "set")]:
            with self.assertRaises(nas.ForbiddenCall):
                c.get(api, method, 1)
        self.assertEqual(c.sent, [])

    def test_post_only_for_login_and_no_free_params(self):
        with self.assertRaises(nas.ForbiddenCall):
            nas.check_call("SYNO.Core.System", "info", "POST", {"api": "SYNO.Core.System", "version": "1", "method": "info"})
        with self.assertRaises(nas.ForbiddenCall):
            nas.check_call("SYNO.Core.System", "info", "GET", {"api": "SYNO.Core.System", "version": "1", "method": "info", "action": "x"})
        with self.assertRaises(nas.ForbiddenCall):
            nas.check_call("SYNO.Core.System", "info", "DELETE", {"api": "SYNO.Core.System", "version": "1", "method": "info"})

    def test_password_never_in_an_url(self):
        c = FakeNas(full_answers())
        c.read()
        logins = [s for s in c.sent if s[2]["method"] == "login"]
        self.assertEqual(len(logins), 1)
        self.assertEqual(logins[0][0], "POST")
        for http_method, _, params in c.sent:
            if http_method == "GET":
                self.assertNotIn("passwd", params)

    def test_session_kept_and_renewed_once(self):
        answers = full_answers()
        c = FakeNas(answers)
        c.read()
        c.read()
        self.assertEqual(len([s for s in c.sent if s[2]["method"] == "login"]), 1)
        answers[("SYNO.Core.System", "info")] = {"success": False, "error": {"code": 119}}
        c.get("SYNO.Core.System.Utilization", "get", 1)
        with self.assertRaises(nas.DsmError):
            c.get("SYNO.Core.System", "info", 3)
        self.assertEqual(len([s for s in c.sent if s[2]["method"] == "login"]), 2)


class Mapping(unittest.TestCase):
    def test_full_read(self):
        out = nas.map_nas(FakeNas(full_answers()).read())
        self.assertEqual(out["model"], "DS418play")
        self.assertEqual(out["dsm_update"], {"available": True, "version": "DSM 7.2.2-72806"})
        self.assertEqual(out["cpu_pct"], 6)
        self.assertEqual(out["ram_pct"], 31)
        self.assertEqual(out["uptime_h"], 1234.1)
        self.assertEqual(out["volumes"], [{"name": "Volume 1", "status": "normal", "used_bytes": 6.6e12, "total_bytes": 1.1e13}])
        self.assertEqual(out["pools"][0]["raid"], "shr_with_1_disk_protect")
        self.assertEqual(out["pools"][0]["scrub_last_at"], "2025-11-01T02:00:00Z")
        d1, d2 = out["disks"]
        self.assertEqual((d1["slot"], d1["temp_c"], d1["power_on_hours"], d1["test_result"], d1["ihm_status"]),
                         ("Disque 1", 37, 70123, "normal", "normal"))
        self.assertEqual(d2["status"], "warning")
        self.assertEqual(out["packages"], [{"name": "Synology Photos", "installed": "1.6.1-0217", "latest": "1.7.0-0300"}])
        self.assertEqual(out["packages_installed"], 2)
        self.assertEqual(out["unavailable"], {})

    def test_nothing_identifying_is_sent(self):
        text = json.dumps(nas.map_nas(FakeNas(full_answers()).read()))
        self.assertNotIn("SERIAL", text)
        self.assertNotIn("home-relay", text)
        self.assertIsNone(IP.search(text))

    def test_non_admin_account_gets_unavailable_with_reason(self):
        answers = full_answers()
        for k in [("SYNO.Storage.CGI.Storage", "load_info"), ("SYNO.Core.Package.Server", "list")]:
            answers[k] = {"success": False, "error": {"code": 105}}
        out = nas.map_nas(FakeNas(answers).read())
        self.assertEqual(out["disks"], [])
        self.assertIn("code DSM 105", out["unavailable"]["storage"])
        self.assertIn("administrateurs", out["unavailable"]["storage"])
        self.assertIn("package_updates", out["unavailable"])
        self.assertEqual(out["packages"], [])
        self.assertEqual(out["model"], "DS418play")

    def test_login_refused_reason(self):
        class Refused(FakeNas):
            def _send(self, http_method, path, params):
                if params["method"] == "login":
                    return {"success": False, "error": {"code": 403}}
                return super()._send(http_method, path, params)
        with self.assertRaises(nas.NasError) as e:
            Refused().read()
        self.assertIn("double authentification", str(e.exception))


class Collect(unittest.TestCase):
    def test_every_30_minutes_and_disabled_without_url(self):
        c = FakeNas(full_answers())
        self.assertTrue(c.due())
        c.read()
        self.assertFalse(c.due())
        self.assertTrue(c.due(now=c.last_read + nas.READ_EVERY_S))
        self.assertIsNone(main.make_nas_client({"nas_url": ""}))


if __name__ == "__main__":
    unittest.main()
