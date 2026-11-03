"""Lecture de Home Assistant par l'API du Supervisor (homeassistant_api: true).

Aucun jeton longue durée : le Supervisor fournit SUPERVISOR_TOKEN à l'add-on.
Sur les images de base récentes (s6-overlay v3), /init ne transmet pas
l'environnement du conteneur au programme principal : le jeton est alors lu
dans /run/s6/container_environment/SUPERVISOR_TOKEN (mécanisme officiel,
celui qu'utilise « with-contenv » / bashio).
Uniquement des lectures : GET /api/config, GET /api/states, et par WebSocket
les seules commandes de lecture des registres (appareils, entités, pièces ;
voir hass_ws.READ_ONLY). Rien n'est commandé : pas d'appel de service, pas
d'écriture.
"""

import json
import os
import urllib.error
import urllib.request

import hass_ws
from privacy import clean_text

API = "http://supervisor/core/api"
S6_ENV_DIR = "/run/s6/container_environment"
TIMEOUT = 20


class HaError(Exception):
    pass


def supervisor_token(env=None, s6_dir: str = S6_ENV_DIR):
    """Jeton du Supervisor : environnement, sinon fichiers d'environnement s6
    (SUPERVISOR_TOKEN, ou l'ancien nom HASSIO_TOKEN)."""
    env = os.environ if env is None else env
    for name in ("SUPERVISOR_TOKEN", "HASSIO_TOKEN"):
        if env.get(name):
            return env[name].strip()
    for name in ("SUPERVISOR_TOKEN", "HASSIO_TOKEN"):
        try:
            with open(os.path.join(s6_dir, name), encoding="utf-8") as f:
                token = f.read().strip()
            if token:
                return token
        except OSError:
            continue
    return None


def _get(path: str):
    token = supervisor_token()
    if not token:
        raise HaError("jeton du Supervisor introuvable (homeassistant_api: true ; environnement et /run/s6/container_environment vides)")
    req = urllib.request.Request(f"{API}{path}", method="GET", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise HaError(f"HTTP {e.code} sur {path}") from None
    except urllib.error.URLError as e:
        raise HaError(f"Home Assistant injoignable ({e.reason})") from None


def read():
    """Configuration, états et registres (appareils, entités, pièces).
    Si les registres sont illisibles, les états restent utilisables."""
    config, states = _get("/config"), _get("/states")
    registry, registry_error = None, None
    try:
        registry = hass_ws.read_registries(supervisor_token())
    except (hass_ws.WsError, OSError, ValueError) as e:
        registry_error = str(e)[:180] or e.__class__.__name__
    return {"config": config, "states": states, "registry": registry, "registry_error": registry_error}


def _num(v, lo, hi):
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    return round(n, 2) if lo <= n <= hi else None


def _name(s):
    return clean_text((s.get("attributes") or {}).get("friendly_name")) or None


# Entités qui ne sont pas des appareils physiques : ignorées pour « hors ligne »
NON_PHYSICAL = {
    "update", "button", "select", "scene", "number", "event", "automation", "script", "group",
    "input_boolean", "input_number", "input_select", "input_text", "input_datetime", "input_button",
    "zone", "person", "sun", "tts", "stt", "conversation", "wake_word", "notify", "image", "text",
    "time", "date", "datetime", "todo", "calendar", "schedule", "counter", "timer", "weather",
    "assist_satellite", "ai_task", "tag",
}


def is_group(state: dict, reg: dict | None) -> bool:
    """Groupe (lumières ou interrupteurs regroupés, pièce Hue…) : pas un appareil."""
    attrs = state.get("attributes") or {}
    if reg and reg.get("platform") == "group":
        return True
    return bool(attrs.get("is_hue_group")) or isinstance(attrs.get("entity_id"), list)


class Registry:
    """Index des registres de Home Assistant (appareils, entités, pièces)."""

    def __init__(self, registry: dict | None):
        registry = registry or {}
        self.entities = {e.get("entity_id"): e for e in registry.get("entities") or [] if e.get("entity_id")}
        self.devices = {d.get("id"): d for d in registry.get("devices") or [] if d.get("id")}
        self.areas = {a.get("area_id"): clean_text(a.get("name"), 60) for a in registry.get("areas") or []}
        self.available = bool(registry.get("entities")) and bool(registry.get("devices"))

    def device_of(self, entity_id: str):
        reg = self.entities.get(entity_id) or {}
        dev = self.devices.get(reg.get("device_id")) if reg.get("device_id") else None
        return reg, dev

    def area_of(self, reg: dict, dev: dict | None):
        return self.areas.get(reg.get("area_id")) or (self.areas.get(dev.get("area_id")) if dev else None)

    @staticmethod
    def device_name(dev: dict | None):
        if not dev:
            return None
        return clean_text(dev.get("name_by_user")) or clean_text(dev.get("name"))


def _is_hue(dev: dict | None, reg: dict) -> bool:
    maker = str((dev or {}).get("manufacturer") or "").lower()
    return reg.get("platform") == "hue" or "signify" in maker or "philips" in maker


def map_states(config: dict, states: list, climate_entities=None, alarm_entities=None, registry=None):
    """Transforme les états (et les registres) en un résumé (fonction pure, testée).

    * appareils indisponibles regroupés PAR APPAREIL : « hors ligne » si toutes
      ses entités principales sont indisponibles, « en partie » sinon ; les
      lumières Hue indisponibles sont classées à part (« éteintes à
      l'interrupteur », normal) ; entités non physiques et groupes ignorés ;
    * piles PAR APPAREIL : capteur device_class battery en %, attribut
      battery_level, ou binary_sensor device_class battery (pile faible oui/non).
    """
    climate_entities = [e for e in (climate_entities or []) if e]
    alarm_entities = [e for e in (alarm_entities or []) if e]
    by_id = {s.get("entity_id"): s for s in states or [] if s.get("entity_id")}
    reg_index = Registry(registry)

    updates = []
    devices: dict[str, dict] = {}       # clé appareil -> suivi disponibilité
    batteries: dict[str, dict] = {}     # clé appareil -> pile
    unavailable_entities = []           # sans registres seulement (repli)

    for eid, s in by_id.items():
        attrs = s.get("attributes") or {}
        state = s.get("state")
        domain = eid.split(".", 1)[0]
        reg, dev = reg_index.device_of(eid)
        if reg.get("disabled_by") or (dev or {}).get("disabled_by"):
            continue
        if dev and dev.get("entry_type") == "service":   # service (météo, intégration…), pas un appareil
            dev = None
        key = dev.get("id") if dev else f"entity:{eid}"
        label = Registry.device_name(dev) or _name(s) or eid
        area = reg_index.area_of(reg, dev)

        if domain == "update" and state == "on":
            updates.append({
                "name": clean_text(attrs.get("title")) or _name(s) or eid,
                "installed": clean_text(attrs.get("installed_version"), 40),
                "latest": clean_text(attrs.get("latest_version"), 40),
            })

        # ---- piles (quel que soit l'état des autres entités) ----
        level, low = None, None
        if domain == "sensor" and attrs.get("device_class") == "battery" and attrs.get("unit_of_measurement") == "%":
            level = _num(state, 0, 100)
        elif domain == "binary_sensor" and attrs.get("device_class") == "battery" and state in ("on", "off"):
            low = state == "on"
        if level is None and attrs.get("battery_level") is not None:
            level = _num(attrs.get("battery_level"), 0, 100)
        if level is not None or low is not None:
            b = batteries.setdefault(key, {"name": label, "area": area, "level": None, "low": None})
            if level is not None:
                b["level"] = level if b["level"] is None else min(b["level"], level)
            if low is not None:
                b["low"] = bool(b["low"]) or low

        # ---- disponibilité : appareils physiques seulement ----
        if domain in NON_PHYSICAL or is_group(s, reg):
            continue
        if not reg_index.available:
            if state == "unavailable":
                unavailable_entities.append({"entity_id": eid, "name": _name(s)})
            continue
        if not dev:   # entité sans appareil (modèle, aide…) : pas un appareil physique
            continue
        primary = not reg.get("entity_category")   # « diagnostic » / « config » ne comptent pas
        d = devices.setdefault(key, {
            "name": label, "area": area,
            "manufacturer": clean_text(dev.get("manufacturer"), 60), "model": clean_text(dev.get("model"), 60),
            "total": 0, "unavailable": 0, "hue_light": False,
        })
        if domain == "light" and _is_hue(dev, reg):
            d["hue_light"] = True
        if primary:
            d["total"] += 1
            if state == "unavailable":
                d["unavailable"] += 1

    unavailable_devices = []
    for d in devices.values():
        if not d["total"] or not d["unavailable"]:
            continue
        status = "hue_off" if d["hue_light"] and d["unavailable"] == d["total"] else \
                 "offline" if d["unavailable"] == d["total"] else "partial"
        unavailable_devices.append({k: d[k] for k in ("name", "area", "manufacturer", "model", "unavailable", "total")}
                                   | {"status": status})
    order = {"offline": 0, "partial": 1, "hue_off": 2}
    unavailable_devices.sort(key=lambda d: (order[d["status"]], d["area"] or "~", d["name"]))

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
        reg, dev = reg_index.device_of(eid)
        climate.append({
            "name": Registry.device_name(dev) or _name(s) or eid,
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

    def battery_order(b):
        lvl = b["level"] if b["level"] is not None else (0 if b["low"] else 101)
        return (lvl, b["name"])

    return {
        "version": clean_text((config or {}).get("version"), 40),
        "updates": updates[:100],
        "batteries": sorted(batteries.values(), key=battery_order)[:500],
        "unavailable_devices": unavailable_devices[:500],
        "unavailable": unavailable_entities[:1000],
        "climate": climate[:100],
        "alarm": alarm[:200],
    }
