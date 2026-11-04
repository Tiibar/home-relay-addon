"""Home Relay : relais en lecture seule UniFi + Home Assistant + NAS Synology -> Supabase.

Toutes les N minutes :
  1. lit la passerelle UniFi locale (GET) et Home Assistant (GET), et toutes
     les 30 min le NAS Synology (API Web de DSM, liste blanche de lectures) ;
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
import nas
import unifi
from sender import Queue, make_sender

VERSION = "1.1.0"
OPTIONS = "/data/options.json"
QUEUE = "/data/queue.json"

log = logging.getLogger("home_relay")


def load_options(path: str = OPTIONS) -> dict:
    with open(path, encoding="utf-8") as f:
        opts = json.load(f)
    missing = [k for k in ("unifi_url", "unifi_username", "unifi_password", "supabase_function_url", "shared_secret") if not opts.get(k)]
    if missing:
        raise SystemExit(f"Configuration incomplète : {', '.join(missing)}")
    if opts.get("nas_url") and not str(opts["nas_url"]).startswith("https://"):
        raise SystemExit("L'adresse du NAS doit commencer par https:// (port HTTPS de DSM : 3041 à la maison, voir Portail de connexion).")
    if opts.get("nas_url") and not (opts.get("nas_username") and opts.get("nas_password")):
        raise SystemExit("NAS : utilisateur et mot de passe obligatoires quand l'adresse du NAS est renseignée.")
    if len(opts["shared_secret"]) < 32:
        raise SystemExit("Le secret partagé doit faire au moins 32 caractères (40 conseillés).")
    if not str(opts["supabase_function_url"]).startswith("https://"):
        raise SystemExit("L'URL de la fonction Supabase doit commencer par https://")
    return opts


def short(e: Exception) -> str:
    return str(e)[:180] or e.__class__.__name__


def make_nas_client(opts: dict):
    """Client NAS, ou None si l'adresse du NAS n'est pas renseignée (lecture désactivée)."""
    if not opts.get("nas_url"):
        return None
    return nas.NasClient(opts["nas_url"], opts["nas_username"], opts["nas_password"], bool(opts.get("nas_verify_ssl")))


def collect(opts: dict, client: "unifi.UnifiClient", nas_client=None) -> dict:
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
    read("unifi_client_events", lambda: client.log_events("CLIENT_DEVICES", unifi.CLIENT_EVENTS_BACKFILL_DAYS))
    read("unifi_wan_events", lambda: client.log_events("INTERNET_AND_WAN", unifi.WAN_EVENTS_BACKFILL_DAYS))
    read("home_assistant", homeassistant.read)

    nas_part = None
    if nas_client is None:
        sources["nas"] = "désactivée : adresse du NAS non renseignée"
    elif nas_client.due():
        read("nas", nas_client.read)
        if raw.get("nas") is not None:
            nas_part = nas.map_nas(raw["nas"])
            missing = nas_part["unavailable"]
            sources["nas"] = f"ok ({len(missing)} information(s) non disponible(s))" if missing else "ok"

    devices = raw.get("unifi_devices") or []
    unifi_part = None
    if devices or raw.get("unifi_clients") is not None:
        wan, speedtest = unifi.map_wan(raw.get("unifi_health"), devices)
        unifi_part = {
            "devices": unifi.map_devices(devices, secret),
            "clients": unifi.map_clients(raw.get("unifi_clients"), raw.get("unifi_clients_24h"),
                                         raw.get("unifi_networks"), devices, secret)[:1000],
            "threats": unifi.map_threats(raw.get("unifi_threats"), secret, *unifi.client_lookup(raw.get("unifi_clients"))),
            "client_events": unifi.map_client_events(raw.get("unifi_client_events"), secret),
            "wan_events": unifi.map_wan_events(raw.get("unifi_wan_events"), secret),
            "wan": wan,
            "speedtest": speedtest,
        }

    ha_part = None
    if raw.get("home_assistant"):
        h = raw["home_assistant"]
        sources["home_assistant_registry"] = "ok" if h["registry"] else f"erreur : {h['registry_error']}"
        ha_part = homeassistant.map_states(h["config"], h["states"], opts.get("climate_entities"),
                                           opts.get("alarm_entities"), h["registry"], opts.get("weather_entity") or None)
        if ha_part.get("alarm_tracking") == "non_suivi":
            sources["alarme"] = "désactivée : état non suivi volontairement (lecture seule)"

    return {
        "v": 1,
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "addon_version": VERSION,
        "sources": sources,
        "unifi": unifi_part,
        "ha": ha_part,
        **({"nas": nas_part} if nas_part is not None else {}),
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
    nas_client = make_nas_client(opts)
    log.info("Home Relay %s démarré : lecture seule, envoi toutes les %d min (heure : %s).", VERSION, interval // 60, tz_name)

    while True:
        started = time.monotonic()
        try:
            payload = collect(opts, client, nas_client)
            if payload.get("nas"):
                for k, v in payload["nas"]["unavailable"].items():
                    log.info("NAS : %s non disponible : %s", k, v)
                if nas_client and not nas_client.keys_logged:
                    # une fois : les champs reçus de DSM (noms seulement, jamais les valeurs), pour ajuster le module
                    log.info("NAS : champs reçus de DSM : %s", json.dumps(nas_client.response_keys, ensure_ascii=False)[:2000])
                    nas_client.keys_logged = True
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
