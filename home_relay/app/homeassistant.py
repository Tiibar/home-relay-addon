"""Lecture de Home Assistant par l'API du Supervisor (homeassistant_api: true).

Aucun jeton longue durée : le Supervisor fournit SUPERVISOR_TOKEN à l'add-on.
Uniquement des lectures (GET /api/config, GET /api/states). Rien n'est
commandé : pas d'appel de service, pas d'écriture.
"""

import json
import os
import urllib.error
import urllib.request

from privacy import clean_text

API = "http://supervisor/core/api"
TIMEOUT = 20


class HaError(Exception):
    pass


def _get(path: str):
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        raise HaError("SUPERVISOR_TOKEN absent (homeassistant_api doit être activé)")
    req = urllib.request.Request(f"{API}{path}", method="GET", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise HaError(f"HTTP {e.code} sur {path}") from None
    except urllib.error.URLError as e:
        raise HaError(f"Home Assistant injoignable ({e.reason})") from None


def read():
    return _get("/config"), _get("/states")


def _num(v, lo, hi):
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    return round(n, 2) if lo <= n <= hi else None


def _name(s):
    return clean_text((s.get("attributes") or {}).get("friendly_name")) or None


def map_states(config: dict, states: list, climate_entities=None, alarm_entities=None):
    """Transforme les états en un résumé (fonction pure, testée)."""
    climate_entities = [e for e in (climate_entities or []) if e]
    alarm_entities = [e for e in (alarm_entities or []) if e]
    by_id = {s.get("entity_id"): s for s in states or [] if s.get("entity_id")}

    batteries, unavailable, updates = [], [], []
    for eid, s in by_id.items():
        attrs = s.get("attributes") or {}
        state = s.get("state")
        domain = eid.split(".", 1)[0]
        if state == "unavailable":
            unavailable.append({"entity_id": eid, "name": _name(s)})
            continue
        if domain == "sensor" and attrs.get("device_class") == "battery" and attrs.get("unit_of_measurement") == "%":
            level = _num(state, 0, 100)
            if level is not None:
                batteries.append({"entity_id": eid, "name": _name(s), "level": level})
        if domain == "update" and state == "on":
            updates.append({
                "name": clean_text(attrs.get("title")) or _name(s) or eid,
                "installed": clean_text(attrs.get("installed_version"), 40),
                "latest": clean_text(attrs.get("latest_version"), 40),
            })

    # Chauffage (Tado via HomeKit) : entités choisies, sinon toutes les climate.*
    climate = []
    ids = climate_entities or sorted(e for e in by_id if e.startswith("climate."))
    for eid in ids:
        s = by_id.get(eid)
        if not s:
            continue
        a = s.get("attributes") or {}
        if eid.startswith("climate."):
            temp, hum, target = a.get("current_temperature"), a.get("current_humidity"), a.get("temperature")
        else:
            dc = a.get("device_class")
            temp = s.get("state") if dc == "temperature" else None
            hum = s.get("state") if dc == "humidity" else None
            target = None
        climate.append({
            "name": _name(s) or eid,
            "temperature": _num(temp, -50, 80),
            "humidity": _num(hum, 0, 100),
            "target": _num(target, -50, 80),
        })

    # Alarme (lecture seule) : entités choisies, sinon les alarm_control_panel.* actives
    alarm = []
    ids = alarm_entities or sorted(e for e in by_id if e.startswith("alarm_control_panel."))
    for eid in ids:
        s = by_id.get(eid)
        if s:
            alarm.append({"name": _name(s) or eid, "state": clean_text(s.get("state"), 60)})

    return {
        "version": clean_text((config or {}).get("version"), 40),
        "updates": updates[:100],
        "batteries": sorted(batteries, key=lambda b: b["level"])[:500],
        "unavailable": unavailable[:1000],
        "climate": climate[:100],
        "alarm": alarm[:200],
    }
