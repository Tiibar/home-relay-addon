"""Home Relay : relais en lecture seule UniFi + Home Assistant -> Supabase.

Toutes les N minutes :
  1. lit la passerelle UniFi locale (GET) et Home Assistant (GET) ;
  2. construit un instantané sans adresse IP, sans adresse MAC en clair
     (HMAC-SHA256 avec le secret), sans site visité ni DNS ;
  3. l'envoie à la fonction Supabase (file d'attente si échec).

Ne commande rien, n'écrit rien ailleurs que dans /data (sa file d'attente).
"""

import json
import logging
import os
import sys
import time
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import homeassistant
import unifi
from sender import Queue, make_sender

VERSION = "1.0.5"
OPTIONS = "/data/options.json"
QUEUE = "/data/queue.json"

log = logging.getLogger("home_relay")


def load_options(path: str = OPTIONS) -> dict:
    with open(path, encoding="utf-8") as f:
        opts = json.load(f)
    missing = [k for k in ("unifi_url", "unifi_username", "unifi_password", "supabase_function_url", "shared_secret") if not opts.get(k)]
    if missing:
        raise SystemExit(f"Configuration incomplète : {', '.join(missing)}")
    if len(opts["shared_secret"]) < 32:
        raise SystemExit("Le secret partagé doit faire au moins 32 caractères (40 conseillés).")
    if not str(opts["supabase_function_url"]).startswith("https://"):
        raise SystemExit("L'URL de la fonction Supabase doit commencer par https://")
    return opts


def short(e: Exception) -> str:
    return str(e)[:180] or e.__class__.__name__


def collect(opts: dict, client: "unifi.UnifiClient") -> dict:
    secret = opts["shared_secret"]
    sources: dict[str, str] = {}
    raw: dict = {}

    def read(name, fn):
        try:
            raw[name] = fn()
            sources[name] = "ok"
        except unifi.ThreatsUnavailable as e:  # désactivée proprement, pas une panne
            raw[name] = None
            sources[name] = f"désactivée : {short(e)}"
        except Exception as e:  # une source en panne n'empêche pas les autres
            raw[name] = None
            sources[name] = f"erreur : {short(e)}"

    read("unifi_devices", client.devices)
    read("unifi_clients", client.clients_now)
    read("unifi_clients_24h", client.clients_24h)
    read("unifi_networks", client.networks)
    read("unifi_health", client.health)
    read("unifi_threats", client.threats)
    if raw.get("unifi_threats") is not None:
        raw["unifi_threats"], endpoint = raw["unifi_threats"]
        sources["unifi_threats"] = f"ok ({endpoint})"
    read("home_assistant", homeassistant.read)

    devices = raw.get("unifi_devices") or []
    unifi_part = None
    if devices or raw.get("unifi_clients") is not None:
        wan, speedtest = unifi.map_wan(raw.get("unifi_health"), devices)
        unifi_part = {
            "devices": unifi.map_devices(devices, secret),
            "clients": unifi.map_clients(raw.get("unifi_clients"), raw.get("unifi_clients_24h"),
                                         raw.get("unifi_networks"), devices, secret)[:1000],
            "threats": unifi.map_threats(raw.get("unifi_threats"), secret),
            "wan": wan,
            "speedtest": speedtest,
        }

    ha_part = None
    if raw.get("home_assistant"):
        h = raw["home_assistant"]
        sources["home_assistant_registry"] = "ok" if h["registry"] else f"erreur : {h['registry_error']}"
        ha_part = homeassistant.map_states(h["config"], h["states"], opts.get("climate_entities"),
                                           opts.get("alarm_entities"), h["registry"])

    return {
        "v": 1,
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "addon_version": VERSION,
        "sources": sources,
        "unifi": unifi_part,
        "ha": ha_part,
    }


def local_timezone(env=None, s6_dir: str = homeassistant.S6_ENV_DIR, default: str = "Europe/Brussels") -> str:
    """Fuseau de Home Assistant : TZ (environnement, sinon fichiers s6, où le
    Supervisor le place), sinon Europe/Brussels."""
    env = os.environ if env is None else env
    if env.get("TZ"):
        return env["TZ"].strip()
    try:
        with open(os.path.join(s6_dir, "TZ"), encoding="utf-8") as f:
            tz = f.read().strip()
        if tz:
            return tz
    except OSError:
        pass
    return default


class LocalFormatter(logging.Formatter):
    """Horodatage du journal à l'heure locale (et non en UTC)."""

    def __init__(self, tz_name: str):
        super().__init__("%(asctime)s %(levelname)s %(message)s")
        try:
            self.tz = ZoneInfo(tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            self.tz = ZoneInfo("Europe/Brussels")

    def formatTime(self, record, datefmt=None):
        return datetime.fromtimestamp(record.created, self.tz).strftime(datefmt or "%Y-%m-%d %H:%M:%S")


def setup_logging(tz_name: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(LocalFormatter(tz_name))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)


def main():
    tz_name = local_timezone()
    setup_logging(tz_name)
    opts = load_options()
    interval = max(1, int(opts.get("interval_minutes") or 5)) * 60
    client = unifi.UnifiClient(opts["unifi_url"], opts["unifi_username"], opts["unifi_password"],
                               opts.get("unifi_site") or "default", bool(opts.get("unifi_verify_ssl")))
    queue = Queue(QUEUE)
    send = make_sender(opts["supabase_function_url"], opts["shared_secret"])
    log.info("Home Relay %s démarré : lecture seule, envoi toutes les %d min (heure : %s).", VERSION, interval // 60, tz_name)

    while True:
        started = time.monotonic()
        try:
            payload = collect(opts, client)
            failed = {k: v for k, v in payload["sources"].items() if not v.startswith("ok")}
            n_clients = len((payload.get("unifi") or {}).get("clients") or [])
            log.info("Lu : %d clients, %d équipements UniFi%s.", n_clients,
                     len((payload.get("unifi") or {}).get("devices") or []),
                     ", Home Assistant" if payload.get("ha") else "")
            for k, v in failed.items():
                if v.startswith("désactivée"):
                    detail = f" ({client.threats_reason})" if k == "unifi_threats" and client.threats_reason else ""
                    log.info("Source %s %s%s", k, v, detail)
                else:
                    log.warning("Source %s : %s", k, v)
            dropped = queue.push(payload)
            if dropped:
                log.warning("File d'attente pleine : %d ancien(s) envoi(s) abandonné(s).", dropped)
            sent, error = queue.flush(send)
            if error:
                log.warning("Envoi : %s (%d en attente).", error, len(queue.items))
            else:
                log.info("Envoyé à Supabase (%d envoi(s)).", sent)
        except Exception as e:
            log.error("Cycle en erreur : %s", short(e))
        time.sleep(max(5, interval - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
