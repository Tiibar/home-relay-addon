"""Tests du NAS Synology (SNMPv3, lecture seule, liste blanche d'OID).

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
S = "1.3.6.1.4.1.6574"

# Réponses d'un NAS (sortie net-snmp -On -OQ -Oe -Ot), y compris le numéro de série (jamais demandé)
AGENT = {
    f"{S}.1.1.0": "1", f"{S}.1.2.0": "41", f"{S}.1.5.1.0": '"DS418play"', f"{S}.1.5.2.0": '"SERIALNAS123"',
    f"{S}.1.5.3.0": '"DSM 7.1.1-42962"', f"{S}.1.5.4.0": "2",
    "1.3.6.1.2.1.25.1.1.0": "360000000",
    "1.3.6.1.4.1.2021.4.5.0": "2000000", "1.3.6.1.4.1.2021.4.6.0": "800000",
    "1.3.6.1.4.1.2021.4.14.0": "100000", "1.3.6.1.4.1.2021.4.15.0": "500000",
    f"{S}.2.1.1.2.0": '"Disk 1"', f"{S}.2.1.1.2.1": '"Disk 2"',
    f"{S}.2.1.1.3.0": '"ST4000VN008-2DR166"', f"{S}.2.1.1.3.1": '"WD40EFRX-68N32N0"',
    f"{S}.2.1.1.5.0": "1", f"{S}.2.1.1.5.1": "5",
    f"{S}.2.1.1.6.0": "36", f"{S}.2.1.1.6.1": "47",
    f"{S}.2.1.1.13.0": "1", f"{S}.2.1.1.13.1": "4",
    f"{S}.3.1.1.2.0": '"Storage Pool 1"', f"{S}.3.1.1.3.0": "11",
    f"{S}.3.1.1.4.0": "4000000000000", f"{S}.3.1.1.5.0": "11000000000000",
    f"{S}.5.1.1.2.0": '"sata1"', f"{S}.5.1.1.4.0": "9", f"{S}.5.1.1.8.0": '"70123"',
    f"{S}.5.1.1.2.1": '"sata1"', f"{S}.5.1.1.4.1": "194", f"{S}.5.1.1.8.1": '"36"',
    f"{S}.5.1.1.2.2": '"sata2"', f"{S}.5.1.1.4.2": "9", f"{S}.5.1.1.8.2": '"3001h+0m"',
    "1.3.6.1.2.1.25.3.3.1.2.196608": "4", "1.3.6.1.2.1.25.3.3.1.2.196609": "8",
    "1.3.6.1.2.1.25.2.3.1.3.31": '"/volume1"', "1.3.6.1.2.1.25.2.3.1.4.31": "4096",
    "1.3.6.1.2.1.25.2.3.1.5.31": "2685546875", "1.3.6.1.2.1.25.2.3.1.6.31": "1611328125",
    "1.3.6.1.2.1.25.2.3.1.3.1": '"Physical memory"', "1.3.6.1.2.1.25.2.3.1.4.1": "1024",
    "1.3.6.1.2.1.25.2.3.1.5.1": "2000000", "1.3.6.1.2.1.25.2.3.1.6.1": "1900000",
}


class FakeAgent:
    """Remplace net-snmp : enregistre chaque commande, répond d'après AGENT."""

    def __init__(self, agent=None, fail=None):
        self.agent = AGENT if agent is None else agent
        self.calls = []
        self.fail = fail

    def __call__(self, command, oids):
        self.calls.append((command, list(oids)))
        if self.fail:
            return 1, "", self.fail
        lines = []
        for oid in oids:
            if command == "snmpget":
                lines.append(f".{oid} = {self.agent.get(oid, 'No Such Object available on this agent at this OID')}")
            else:
                lines += [f".{k} = {v}" for k, v in self.agent.items() if k.startswith(oid + ".")]
        return 0, "\n".join(lines), ""


def client(agent=None, fail=None):
    runner = FakeAgent(agent, fail)
    return nas.NasClient("nas.example", "home-relay-snmp", "auth-pass-123", "priv-pass-456", runner=runner), runner


class Whitelist(unittest.TestCase):
    def test_set_is_refused_before_anything_runs(self):
        c, runner = client()
        for command in ("snmpset", "snmptrap", "snmpbulkset", "snmpusm", "snmpvacm", "sh"):
            with self.assertRaises(nas.ForbiddenRequest):
                c.request(command, [f"{S}.1.1.0"])
        self.assertEqual(runner.calls, [])

    def test_only_whitelisted_oids(self):
        c, runner = client()
        for oid in (f"{S}.1.5.2.0", "1.3.6.1", f"{S}", "1.3.6.1.2.1.1.5.0", f"{S}.1.1.0; rm -rf /", "-v1"):  # check-secrets: allow (OID, pas une adresse)
            with self.assertRaises(nas.ForbiddenRequest):
                c.request("snmpget", [oid])
        with self.assertRaises(nas.ForbiddenRequest):
            c.request("snmpwalk", [S])                 # pas de marche sur toute la branche Synology
        with self.assertRaises(nas.ForbiddenRequest):
            c.request("snmpwalk", [f"{S}.1.1.0"])      # une valeur unique ne se « marche » pas
        self.assertEqual(runner.calls, [])

    def test_serial_number_never_requested_nor_kept(self):
        c, runner = client()
        out = nas.map_nas(c.read())
        requested = [o for _, oids in runner.calls for o in oids]
        self.assertNotIn(f"{S}.1.5.2.0", requested)
        self.assertTrue(all(cmd in nas.ALLOWED_COMMANDS for cmd, _ in runner.calls))
        text = json.dumps(out)
        self.assertNotIn("SERIAL", text)
        self.assertIsNone(IP.search(text))
        # une réponse hors liste blanche (même si l'agent l'envoie) est ignorée
        self.assertEqual(nas.parse_output(f".{S}.1.5.2.0 = \"SERIALNAS123\"\n.{S}.1.1.0 = 1"), {f"{S}.1.1.0": "1"})

    def test_passwords_never_on_the_command_line(self):
        c = nas.NasClient("nas.example", "home-relay-snmp", "auth-pass-123", "priv-pass-456")
        conf = c._conf()
        path = os.path.join(conf, "snmp.conf")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("defSecurityLevel authPriv", text)
        self.assertIn("defAuthType SHA", text)
        self.assertIn("defPrivType AES", text)
        seen = {}

        def fake_run(args, **kw):
            seen["args"], seen["env"] = args, kw["env"]

            class P:
                returncode, stdout, stderr = 0, f".{S}.1.1.0 = 1", ""
            return P()

        import subprocess
        orig, orig_which = subprocess.run, nas.shutil.which
        subprocess.run, nas.shutil.which = fake_run, (lambda name: f"/usr/bin/{name}")
        try:
            c.request("snmpget", [f"{S}.1.1.0"])
        finally:
            subprocess.run, nas.shutil.which = orig, orig_which
        self.assertNotIn("auth-pass-123", " ".join(seen["args"]))
        self.assertNotIn("priv-pass-456", " ".join(seen["args"]))
        self.assertEqual(seen["env"]["SNMPCONFPATH"], conf)
        self.assertEqual(seen["args"][0], "/usr/bin/snmpget")

    def test_refuses_unsafe_options(self):
        for host in ("https://nas", "nas:161", "", "a b"):
            with self.assertRaises(nas.NasError):
                nas.NasClient(host, "u", "auth-pass-123", "priv-pass-456")
        with self.assertRaises(nas.NasError):
            nas.NasClient("nas.example", "u", 'pa"ss-123', "priv-pass-456")
        with self.assertRaises(nas.NasError):
            nas.NasClient("nas.example", "u", "short", "priv-pass-456")


class Mapping(unittest.TestCase):
    def test_full_read(self):
        c, _ = client()
        out = nas.map_nas(c.read())
        self.assertEqual((out["model"], out["dsm_version"], out["system_status"], out["temperature_c"]),
                         ("DS418play", "DSM 7.1.1-42962", "normal", 41))
        self.assertEqual(out["dsm_update"], {"available": False, "version": None})
        self.assertEqual(out["cpu_pct"], 6)
        self.assertEqual(out["ram_pct"], 30)
        self.assertEqual(out["uptime_h"], 1000)
        # pas de dskTable dans AGENT : repli sur hrStorage (taille relue en non signé)
        self.assertEqual(out["volumes"], [{"name": "Volume 1", "status": None, "source": "hr_storage",
                                           "used_bytes": 1611328125 * 4096, "total_bytes": 2685546875 * 4096}])
        self.assertEqual(out["pools"], [{"name": "Groupe de stockage 1", "status": "degrade", "free_bytes": 4e12, "total_bytes": 11e12}])
        d1, d2 = out["disks"]
        self.assertEqual(d1, {"slot": "Disque 1", "model": "ST4000VN008-2DR166", "temp_c": 36, "status": "normal", "health_status": "normal", "power_on_hours": 70123})
        self.assertEqual((d2["status"], d2["health_status"], d2["temp_c"], d2["power_on_hours"]), ("crashed", "failing", 47, 3001))
        self.assertEqual(set(out["unavailable"]), set(nas.NOT_IN_SNMP))
        for reason in out["unavailable"].values():
            self.assertIn("non disponible via SNMP", reason)

    def test_volume_from_filesystem_not_from_storage_pool(self):
        # /volume1 : 10,5 To (base 1024) dont 67 % utilisés, sur 64 bits (Ko) ; le groupe de stockage dit autre chose
        total_kb, used_kb = int(10.5 * 1024 ** 3), int(10.5 * 1024 ** 3 * 0.67)
        agent = {**AGENT,
                 "1.3.6.1.4.1.2021.9.1.2.1": '"/"', "1.3.6.1.4.1.2021.9.1.11.1": "1000", "1.3.6.1.4.1.2021.9.1.12.1": "0",
                 "1.3.6.1.4.1.2021.9.1.2.2": '"/volume1"',
                 "1.3.6.1.4.1.2021.9.1.11.2": str(total_kb % 2 ** 32), "1.3.6.1.4.1.2021.9.1.12.2": str(total_kb // 2 ** 32),
                 "1.3.6.1.4.1.2021.9.1.15.2": str(used_kb % 2 ** 32), "1.3.6.1.4.1.2021.9.1.16.2": str(used_kb // 2 ** 32)}
        c, _ = client(agent)
        out = nas.map_nas(c.read())
        self.assertEqual(len(out["volumes"]), 1)
        vol = out["volumes"][0]
        self.assertEqual((vol["name"], vol["source"], vol["total_bytes"]), ("Volume 1", "ucd_dsk", total_kb * 1024))
        self.assertAlmostEqual(vol["used_bytes"] / vol["total_bytes"], 0.67, places=3)
        self.assertEqual(nas.tib(vol["total_bytes"]), "10,5 To")

    def test_negative_hr_storage_is_read_unsigned_and_no_pool_fallback(self):
        agent = {**AGENT, "1.3.6.1.2.1.25.2.3.1.5.31": str(2685546875 - 2 ** 32)}
        out = nas.map_nas(client(agent)[0].read())
        self.assertEqual(out["volumes"][0]["total_bytes"], 2685546875 * 4096)
        no_vol = {k: v for k, v in AGENT.items() if not k.startswith("1.3.6.1.2.1.25.2.3.1.3.31")}
        out = nas.map_nas(client(no_vol)[0].read())
        self.assertEqual(out["volumes"], [])
        self.assertIn("volumes", out["unavailable"])

    def test_old_dsm_without_health_or_smart(self):
        agent = {k: v for k, v in AGENT.items() if not k.startswith((f"{S}.2.1.1.13", f"{S}.5."))}
        c, _ = client(agent)
        out = nas.map_nas(c.read())
        self.assertIsNone(out["disks"][0]["health_status"])
        self.assertIn("disk_health", out["unavailable"])
        self.assertIn("smart", out["unavailable"])

    def test_unreachable_or_refused(self):
        for err, expected in [("Timeout: No Response from nas.example.", "délai dépassé"),
                              ("snmpget: Authentication failure (incorrect password, community or key)", "authentification"),
                              ("snmpget: Unknown user name", "utilisateur SNMP inconnu"),
                              ("snmpget: Decryption error", "chiffrement")]:
            c, _ = client(fail=err)
            with self.assertRaises(nas.NasError) as e:
                c.read()
            self.assertIn(expected, str(e.exception))

    def test_every_30_minutes_and_disabled_without_host(self):
        c, _ = client()
        self.assertTrue(c.due())
        c.read()
        self.assertFalse(c.due())
        self.assertTrue(c.due(now=c.last_read + nas.READ_EVERY_S))
        self.assertIsNone(main.make_nas_client({"nas_host": ""}))


if __name__ == "__main__":
    unittest.main()
