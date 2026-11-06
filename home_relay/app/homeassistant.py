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
import re
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


SOMFY = re.compile(r"somfy", re.I)
ALARM_STATE_HINT = re.compile(r"securit|alarm|state|[ée]tat|mode|level|niveau|status", re.I)
ALARM_DETECTOR_CLASSES = {"door", "window", "opening", "motion", "occupancy", "tamper", "smoke", "safety", "presence"}


def alarm_entities_for(by_id: dict, reg_index: "Registry", chosen=None) -> list:
    """Entités dont on lit l'état de l'alarme (lecture seule, jamais commandées) :
    1. celles choisies dans la configuration ;
    2. sinon les alarm_control_panel.* actives ;
    3. sinon, si le panneau a été désactivé volontairement, les entités qui
       restent de l'appareil Somfy (SomfyProtect2MQTT, en MQTT) : état ou
       niveau de sécurité (sensor / select / binary_sensor) et détecteurs.
    Liste vide = état non suivi (choix volontaire, pas une panne)."""
    if chosen:
        return list(chosen)
    panels = sorted(e for e in by_id if e.startswith("alarm_control_panel."))
    if panels:
        return panels
    found = []
    for eid, s in by_id.items():
        domain = eid.split(".", 1)[0]
        if domain not in ("sensor", "binary_sensor", "select"):
            continue
        reg, dev = reg_index.device_of(eid)
        if reg.get("disabled_by") or (dev or {}).get("disabled_by"):
            continue
        dev = dev or {}
        origin = " ".join(str(x or "") for x in (eid, dev.get("manufacturer"), dev.get("model"), dev.get("name"),
                                                  reg.get("platform"), _name(s)))
        if not SOMFY.search(origin):
            continue
        label = f"{eid} {_name(s) or ''}"
        dclass = str((s.get("attributes") or {}).get("device_class") or "")
        if ALARM_STATE_HINT.search(label) or (domain == "binary_sensor" and dclass in ALARM_DETECTOR_CLASSES):
            found.append(eid)
    return sorted(found)


def map_states(config: dict, states: list, climate_entities=None, alarm_entities=None, registry=None, weather_entity=None):
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
    # Téléphones et tablettes de l'application Home Assistant (Companion App,
    # intégration « mobile_app ») : pas des appareils de la maison, exclus du Parc.
    mobile_devices = {e.get("device_id") for e in reg_index.entities.values()
                      if e.get("platform") == "mobile_app" and e.get("device_id")}

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

        if reg.get("platform") == "mobile_app" or (dev and dev.get("id") in mobile_devices):
            continue

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
            # numéro de série (HomeKit, ex. vanne Tado) : pour reconnaître l'appareil dans l'app du fabricant
            "serial": clean_text(dev.get("serial_number"), 40),
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
        unavailable_devices.append({k: d[k] for k in ("name", "area", "manufacturer", "model", "serial", "unavailable", "total")}
                                   | {"status": status})
    order = {"offline": 0, "partial": 1, "hue_off": 2}
    unavailable_devices.sort(key=lambda d: (order[d["status"]], d["area"] or "~", d["name"]))

    # Chauffage (Tado via HomeKit) : entités choisies, sinon toutes les climate.*
    # Par thermostat : consigne, température et humidité mesurées (au besoin
    # lues sur les capteurs du même appareil), mode et état de chauffe, pièce.
    siblings: dict[str, list[str]] = {}
    for eid, reg in reg_index.entities.items():
        if reg.get("device_id"):
            siblings.setdefault(reg["device_id"], []).append(eid)

    def sibling_value(dev, device_class, lo, hi):
        for other in siblings.get((dev or {}).get("id"), []):
            o = by_id.get(other) or {}
            if other.startswith("sensor.") and (o.get("attributes") or {}).get("device_class") == device_class:
                v = _num(o.get("state"), lo, hi)
                if v is not None:
                    return v
        return None

    climate = []
    ids = climate_entities or sorted(e for e in by_id if e.startswith("climate."))
    for eid in ids:
        s = by_id.get(eid)
        if not s:
            continue
        a = s.get("attributes") or {}
        reg, dev = reg_index.device_of(eid)
        if eid.startswith("climate."):
            temp = _num(a.get("current_temperature"), -50, 80)
            hum = _num(a.get("current_humidity"), 0, 100)
            target = _num(a.get("temperature"), -50, 80)
            mode = clean_text(s.get("state"), 20) if s.get("state") not in ("unavailable", "unknown") else None
            action = clean_text(a.get("hvac_action"), 20)
        else:
            dc = a.get("device_class")
            temp = _num(s.get("state"), -50, 80) if dc == "temperature" else None
            hum = _num(s.get("state"), 0, 100) if dc == "humidity" else None
            target, mode, action = None, None, None
        if temp is None:
            temp = sibling_value(dev, "temperature", -50, 80)
        if hum is None:
            hum = sibling_value(dev, "humidity", 0, 100)
        climate.append({
            "entity_id": eid,
            "kind": "zone",
            "name": Registry.device_name(dev) or _name(s) or eid,
            "area": reg_index.area_of(reg, dev),
            "temperature": temp,
            "humidity": hum,
            "target": target,
            "hvac_mode": mode,
            "hvac_action": action,
        })

    # Température extérieure : entité météo choisie, sinon la première weather.*
    wid = weather_entity or next((e for e in sorted(by_id) if e.startswith("weather.")), None)
    w = by_id.get(wid) if wid else None
    if w and w.get("state") not in ("unavailable", "unknown"):
        wa = w.get("attributes") or {}
        t = _num(wa.get("temperature"), -50, 60) if wid.startswith("weather.") else _num(w.get("state"), -50, 60)
        if t is not None:
            climate.append({
                "entity_id": wid, "kind": "outdoor", "name": "Extérieur", "area": None,
                "temperature": t, "humidity": _num(wa.get("humidity"), 0, 100) if wid.startswith("weather.") else None,
                "target": None, "hvac_mode": None, "hvac_action": None,
            })

    # Alarme (lecture seule) : voir alarm_entities()
    alarm, alarm_tracking = [], "non_suivi"
    for eid in alarm_entities_for(by_id, reg_index, alarm_entities):
        s = by_id.get(eid)
        if s:
            alarm.append({"name": _name(s) or eid, "state": clean_text(s.get("state"), 60)})
    if alarm:
        alarm_tracking = "suivi"

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
        "alarm_tracking": alarm_tracking,
    }


# ---------------------------------------------------------------------------
# Reolink (module ≥ 1.2.6) : sonnette sur batterie et Home Hub Mini, via
# l'intégration Reolink de Home Assistant. LECTURE SEULE des états déjà lus
# (aucune requête en plus, aucune commande) : batterie %, signal Wi-Fi, en ligne,
# dernière sonnerie / dernière détection. Jamais d'image, de flux, d'adresse ni
# d'identifiant ; les entités de commande (sirène, lumière, réglages, boutons)
# sont ignorées même si elles n'ont pas été désactivées dans Home Assistant.
# ---------------------------------------------------------------------------

REOLINK_SENSORS = {
    # clés de l'intégration Reolink (translation_key) ou fin de l'entity_id réel : jamais inventés,
    # seules les entités de la plateforme « reolink » du registre sont examinées
    "battery": re.compile(r"(^|_)battery(_percent|_level)?$"),
    "wifi": re.compile(r"(^|_)wi_?fi_signal$"),
    "ring": re.compile(r"(^|_)visitor$|(^|_)doorbell$|(^|_)ring$"),
    "motion": re.compile(r"(^|_)motion$"),
    "person": re.compile(r"(^|_)person$"),
}
REOLINK_READ_DOMAINS = {"sensor", "binary_sensor"}


def _reolink_kind(entity_id: str, reg: dict):
    domain, _, obj = entity_id.partition(".")
    if domain not in REOLINK_READ_DOMAINS:
        return None  # commandes (switch, light, siren, button, number, select…) : jamais lues
    keys = [str(reg.get("translation_key") or ""), obj]
    for kind, rx in REOLINK_SENSORS.items():
        if any(rx.search(k) for k in keys if k):
            if kind == "battery" and domain != "sensor":
                return None
            return kind
    return None


def _is_reolink_device(dev: dict) -> bool:
    return "reolink" in str(dev.get("manufacturer") or "").lower() or any(
        isinstance(i, (list, tuple)) and i and i[0] == "reolink" for i in dev.get("identifiers") or [])


def map_reolink(states: list, registry=None):
    """Sonnette et hub Reolink : quelques valeurs, rien d'autre (fonction pure, testée).

    « En ligne » = au moins une entité ACTIVE de l'appareil n'est pas « unavailable ».
    Le hub n'a volontairement aucune entité active (06/11/2026) : la sonnette passe par lui,
    donc s'il n'a pas d'entité active, il est « en ligne » quand la sonnette l'est
    (`derived`: true) et inconnu sinon.
    """
    reg_index = Registry(registry)
    by_id = {s.get("entity_id"): s for s in states or [] if s.get("entity_id")}
    devices: dict = {}
    for dev_id, dev in reg_index.devices.items():
        if _is_reolink_device(dev):
            devices[dev_id] = {"dev": dev, "states": [], "values": {}}
    for eid, reg in reg_index.entities.items():
        if reg.get("platform") != "reolink":
            continue
        dev_id = reg.get("device_id") or eid
        d = devices.setdefault(dev_id, {"dev": reg_index.devices.get(reg.get("device_id")) or {}, "states": [], "values": {}})
        if reg.get("disabled_by"):
            continue
        s = by_id.get(eid)
        if s is not None:
            d["states"].append(s.get("state"))
            kind = _reolink_kind(eid, reg)
            if kind:
                d["values"][kind] = s
    # aucune entité Reolink ACTIVE (intégration supprimée ou désactivée, 06/11/2026) : rien à envoyer,
    # la source est « absente » (l'app affiche « non suivie volontairement »), jamais des valeurs vides
    if not devices or not any(d["states"] for d in devices.values()):
        return None

    def online(d):
        live = [st for st in d["states"] if st is not None]
        return (any(st != "unavailable" for st in live)) if live else None

    def when(s):
        return _iso_ts(s.get("last_changed")) if s else None

    out = {"doorbell": None, "hub": None}
    hub_dev = None
    for dev_id, d in devices.items():
        dev, vals = d["dev"], d["values"]
        model = f"{dev.get('model') or ''} {dev.get('name') or ''} {dev.get('name_by_user') or ''}"
        if re.search(r"\bhub\b|home hub|\bnvr\b", model, re.I) and "ring" not in vals and "battery" not in vals:
            hub_dev = (dev_id, d)
            continue
        if "ring" in vals or "battery" in vals or re.search(r"doorbell|sonn?ette", model, re.I):
            bat, wifi = vals.get("battery"), vals.get("wifi")
            out["doorbell"] = {
                "name": Registry.device_name(dev),
                "online": online(d),
                "battery_pct": _num(bat.get("state"), 0, 100) if bat else None,
                "wifi_signal": _num(wifi.get("state"), -150, 100) if wifi else None,
                "wifi_unit": clean_text((wifi.get("attributes") or {}).get("unit_of_measurement"), 10) if wifi else None,
                "ring_state": clean_text(vals["ring"].get("state"), 20) if vals.get("ring") else None,
                "last_ring_at": when(vals.get("ring")),
                "last_motion_at": max([t for t in (when(vals.get("motion")), when(vals.get("person"))) if t], default=None),
                "_via": dev.get("via_device_id"),
            }
    if hub_dev:
        dev_id, d = hub_dev
        own = online(d)
        if own is not None:
            out["hub"] = {"name": Registry.device_name(d["dev"]), "online": own, "derived": False}
        else:
            bell = out["doorbell"]
            via_ok = bell is not None and (bell.get("_via") in (None, dev_id))
            out["hub"] = {"name": Registry.device_name(d["dev"]), "online": True if (via_ok and bell and bell["online"]) else None, "derived": True}
    if out["doorbell"]:
        out["doorbell"].pop("_via", None)
    if not out["doorbell"] and not out["hub"]:
        return None
    return out


def _iso_ts(v):
    s = str(v or "")
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", s)
    if not m:
        return None
    # last_changed de Home Assistant est en UTC (« +00:00 ») : on le garde à la seconde
    return m.group(1) + "Z" if s.endswith("+00:00") or s.endswith("Z") else None
