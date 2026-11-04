"""Lecture du NAS Synology (API Web officielle de DSM), en LECTURE SEULE.

Chaque appel passe par une LISTE BLANCHE stricte de couples (API, méthode)
(`ALLOWED_CALLS`, vérifiée dans `_call` avant tout envoi) : uniquement des
méthodes qui lisent (`query`, `login`, `info`, `get`, `list`, `load_info`,
`get_health_info`, `get_smart_info`, `check`). Tout autre appel (`set`,
`create`, `delete`, `start`, `stop`, `run`, `install`, `upgrade`…) est refusé
par le module lui-même, avant d'être envoyé (`ForbiddenCall`).

  * SYNO.API.Info / query            : chemins et versions des API (sans session)
  * SYNO.API.Auth / login            : ouverture de la session (seule requête
                                       POST, pour que le mot de passe ne soit
                                       jamais dans une adresse) ; pas de logout :
                                       la session est gardée, reconnexion si elle
                                       expire (évite une ligne de journal DSM
                                       toutes les 30 min)
  * SYNO.Core.System / info          : modèle, version DSM, température, état
  * SYNO.Core.System.Utilization/get : processeur, mémoire
  * SYNO.Storage.CGI.Storage / load_info : volumes, groupes de stockage (RAID),
                                       disques (modèle, taille, température, état)
  * SYNO.Storage.CGI.Smart / get_health_info, get_smart_info : dernier test
                                       SMART, santé IronWolf, heures de fonctionnement
  * SYNO.Core.Upgrade.Server / check : demande au NAS s'il existe une version de
                                       DSM plus récente (ne télécharge et
                                       n'installe rien)
  * SYNO.Core.Package / list         : paquets installés et leur version
  * SYNO.Core.Package.Server / list  : dernières versions disponibles des paquets

Garde-fou principal : le compte NAS « home-relay » n'est PAS administrateur
(groupe « users », aucune application autorisée hormis DSM). Une information
que ce compte ne peut pas lire est envoyée « non disponible », avec le code
d'erreur de DSM (105 = permission refusée).

Jamais envoyé : numéros de série, adresses IP ou MAC, noms d'utilisateur,
noms des dossiers partagés, contenu des fichiers.
"""

import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from privacy import clean_text

TIMEOUT = 25
READ_EVERY_S = 30 * 60          # le NAS change lentement : une lecture toutes les 30 min
SESSION = "HomeRelay"

ALLOWED_CALLS = {
    ("SYNO.API.Info", "query"),
    ("SYNO.API.Auth", "login"),
    ("SYNO.Core.System", "info"),
    ("SYNO.Core.System.Utilization", "get"),
    ("SYNO.Storage.CGI.Storage", "load_info"),
    ("SYNO.Storage.CGI.Smart", "get_health_info"),
    ("SYNO.Storage.CGI.Smart", "get_smart_info"),
    ("SYNO.Core.Upgrade.Server", "check"),
    ("SYNO.Core.Package", "list"),
    ("SYNO.Core.Package.Server", "list"),
}
# Seule requête POST : la connexion (mot de passe dans le corps, pas dans l'adresse)
POST_CALLS = {("SYNO.API.Auth", "login")}
# Mots qui désignent une modification : refusés même s'ils apparaissaient un jour dans la liste
WRITE_WORDS = re.compile(r"set|create|delete|remove|start|stop|run|install|uninstall|upgrade|update|reboot|shutdown|"
                         r"format|repair|enable|disable|apply|save|edit|add|cancel|test", re.I)
# Paramètres autorisés : jamais de paramètre libre vers DSM
ALLOWED_PARAMS = {"api", "version", "method", "query", "account", "passwd", "session", "format", "_sid",
                  "device", "additional", "blforcereload", "updateSprite", "type"}

# Codes d'erreur DSM (documentation officielle de l'API Web)
DSM_ERRORS = {
    100: "erreur inconnue", 101: "paramètre invalide", 102: "API absente de ce DSM", 103: "méthode absente de ce DSM",
    104: "version non prise en charge", 105: "permission refusée pour ce compte", 106: "session expirée",
    107: "session interrompue (connexion en double)", 119: "session inconnue",
}
AUTH_ERRORS = {
    400: "identifiant ou mot de passe refusé", 401: "compte désactivé", 402: "permission refusée",
    403: "double authentification demandée : à retirer pour ce compte de service", 404: "double authentification refusée",
    406: "double authentification imposée : à retirer pour ce compte de service", 407: "adresse bloquée (blocage automatique de DSM)",
    408: "mot de passe expiré", 409: "mot de passe expiré", 410: "mot de passe à changer",
}
SESSION_LOST = {106, 107, 119}


class NasError(Exception):
    pass


class ForbiddenCall(NasError):
    """Appel hors de la liste blanche : refusé avant tout envoi."""


class DsmError(NasError):
    def __init__(self, api: str, code: int):
        self.api, self.code = api, code
        super().__init__(f"{api} : {DSM_ERRORS.get(code, 'erreur')} (code DSM {code})")


def reason(e: Exception) -> str:
    """Raison lisible d'une information non disponible (jamais d'adresse)."""
    if isinstance(e, DsmError):
        if e.code == 105:
            return "accès refusé au compte du module (code DSM 105) : réservé aux administrateurs sur ce DSM"
        return f"{DSM_ERRORS.get(e.code, 'erreur')} (code DSM {e.code})"
    return clean_text(str(e), 160) or e.__class__.__name__


def check_call(api: str, method: str, http_method: str, params: dict) -> None:
    """Lève ForbiddenCall si l'appel n'est pas une lecture de la liste blanche."""
    if (api, method) not in ALLOWED_CALLS:
        raise ForbiddenCall(f"appel refusé par la liste blanche : {api} / {method}")
    if method not in ("query", "login", "check") and WRITE_WORDS.search(method.replace("load_info", "").replace("get_", "")):
        raise ForbiddenCall(f"méthode d'écriture refusée : {method}")
    if http_method == "POST" and (api, method) not in POST_CALLS:
        raise ForbiddenCall(f"requête POST refusée : {api} / {method}")
    if http_method not in ("GET", "POST"):
        raise ForbiddenCall(f"requête {http_method} refusée")
    extra = set(params) - ALLOWED_PARAMS
    if extra:
        raise ForbiddenCall(f"paramètre refusé : {', '.join(sorted(extra))}")


class NasClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        self.base = base_url.rstrip("/")
        self.username = username
        self.password = password
        ctx = ssl.create_default_context()
        if not verify_ssl:  # certificat auto-signé du NAS, réseau local
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        self.sid = None
        self.apis: dict = {}
        self.last_read = 0.0
        self.keys_logged = False
        self.response_keys: dict[str, list[str]] = {}

    # -- transport (liste blanche) ------------------------------------------
    def _send(self, http_method: str, path: str, params: dict):
        data = None
        url = f"{self.base}/webapi/{path}"
        if http_method == "POST":
            data = urllib.parse.urlencode(params).encode()
        else:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, data=data, method=http_method, headers={"Accept": "application/json"})
        try:
            with self.opener.open(req, timeout=TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8") or "null")
        except urllib.error.HTTPError as e:
            raise NasError(f"HTTP {e.code}") from None
        except urllib.error.URLError as e:
            raise NasError(f"NAS injoignable ({clean_text(e.reason, 80) or 'réseau'})") from None
        except (TimeoutError, OSError):
            raise NasError("NAS injoignable (délai dépassé)") from None

    def _call(self, api: str, method: str, version: int, params: dict | None = None, http_method: str = "GET"):
        """Seul point de sortie vers le NAS : liste blanche d'abord."""
        p = {"api": api, "version": str(version), "method": method, **(params or {})}
        check_call(api, method, http_method, p)
        path = "query.cgi" if api == "SYNO.API.Info" else self.apis.get(api, {}).get("path", "entry.cgi")
        res = self._send(http_method, path, p)
        if not isinstance(res, dict):
            raise NasError(f"{api} : réponse inattendue")
        if not res.get("success"):
            code = int((res.get("error") or {}).get("code") or 100)
            raise DsmError(api, code)
        return res.get("data") or {}

    def _version(self, api: str, preferred: int) -> int:
        info = self.apis.get(api)
        if not info:
            return preferred
        return max(int(info.get("minVersion", 1)), min(preferred, int(info.get("maxVersion", preferred))))

    # -- session -------------------------------------------------------------
    def discover(self):
        if not self.apis:
            data = self._call("SYNO.API.Info", "query", 1, {"query": ",".join(sorted({a for a, _ in ALLOWED_CALLS}))})
            self.apis = data if isinstance(data, dict) else {}

    def login(self):
        self.discover()
        try:
            data = self._call("SYNO.API.Auth", "login", self._version("SYNO.API.Auth", 6),
                              {"account": self.username, "passwd": self.password, "session": SESSION, "format": "sid"},
                              http_method="POST")
        except DsmError as e:
            raise NasError(f"connexion au NAS refusée : {AUTH_ERRORS.get(e.code, DSM_ERRORS.get(e.code, 'erreur'))} (code DSM {e.code})") from None
        self.sid = data.get("sid")
        if not self.sid:
            raise NasError("connexion au NAS : pas de session reçue")

    def get(self, api: str, method: str, preferred: int, params: dict | None = None):
        """Lecture authentifiée ; reconnecte une fois si la session a expiré."""
        check_call(api, method, "GET", {"api": api, "version": "1", "method": method, **(params or {}), "_sid": ""})
        if not self.sid:
            self.login()
        for attempt in (1, 2):
            try:
                data = self._call(api, method, self._version(api, preferred), {**(params or {}), "_sid": self.sid})
                if isinstance(data, dict):
                    self.response_keys[f"{api}/{method}"] = sorted(data)[:40]
                return data
            except DsmError as e:
                if e.code in SESSION_LOST and attempt == 1:
                    self.sid = None
                    self.login()
                    continue
                raise
        raise NasError(f"{api} : session refusée")

    def due(self, now: float | None = None) -> bool:
        return (now if now is not None else time.monotonic()) - self.last_read >= READ_EVERY_S or not self.last_read

    # -- lecture complète ------------------------------------------------------
    def read(self) -> dict:
        """Toutes les lectures ; chacune peut échouer sans empêcher les autres.
        Prochaine lecture dans 30 min même en cas d'échec (une connexion refusée
        n'est pas répétée toutes les 5 min : pas de blocage automatique par DSM)."""
        self.last_read = time.monotonic()
        self.discover()
        if not self.sid:
            self.login()
        raw: dict = {}
        errors: dict[str, str] = {}

        def one(key, fn):
            try:
                raw[key] = fn()
            except ForbiddenCall:
                raise
            except NasError as e:
                raw[key] = None
                errors[key] = reason(e)

        one("system", lambda: self.get("SYNO.Core.System", "info", 3))
        one("utilization", lambda: self.get("SYNO.Core.System.Utilization", "get", 1))
        one("storage", lambda: self.get("SYNO.Storage.CGI.Storage", "load_info", 1))
        one("dsm_update", lambda: self.get("SYNO.Core.Upgrade.Server", "check", 1))
        one("packages", lambda: self.get("SYNO.Core.Package", "list", 2, {"additional": json.dumps(["status"])}))
        one("package_updates", lambda: self.get("SYNO.Core.Package.Server", "list", 2, {"blforcereload": "false"}))

        smart: dict = {}
        disks = ((raw.get("storage") or {}).get("disks") or []) if isinstance(raw.get("storage"), dict) else []
        for d in disks[:12]:
            dev = d.get("device") or (f"/dev/{d['id']}" if d.get("id") else None)
            if not dev or not re.fullmatch(r"/dev/[a-z0-9]{2,12}", str(dev)):
                continue
            entry: dict = {}
            for key, method in (("health", "get_health_info"), ("info", "get_smart_info")):
                try:
                    entry[key] = self.get("SYNO.Storage.CGI.Smart", method, 1, {"device": dev})
                except NasError as e:
                    entry[key] = None
                    errors.setdefault("smart", reason(e))
            smart[str(d.get("id") or dev)] = entry
        raw["smart"] = smart
        return {"raw": raw, "errors": errors}


# ---------------------------------------------------------------------------
# Mise en forme (sans numéro de série ni adresse)
# ---------------------------------------------------------------------------

def _num(v):
    if v is None or v == "" or isinstance(v, bool):
        return None
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if x == x and abs(x) != float("inf") else None


def _pick(d: dict, *keys):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, ""):
            return d[k]
    return None


def _iso(v):
    """Date DSM (horodatage en secondes, ou texte « 2026/11/01 02:00:00 ») -> ISO, sinon None."""
    n = _num(v)
    if n and n > 1e9:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(n / 1000 if n > 1e12 else n))
    if isinstance(v, str):
        m = re.match(r"^(\d{4})[/-](\d{2})[/-](\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?", v)
        if m:
            y, mo, d, h, mi, s = (int(x or 0) for x in m.groups())
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.mktime((y, mo, d, h, mi, s, 0, 0, -1))))
    return None


def _uptime_h(v):
    if isinstance(v, str) and re.fullmatch(r"\d+:\d{2}:\d{2}", v):
        h, m, s = (int(x) for x in v.split(":"))
        return round(h + m / 60, 1)
    n = _num(v)
    return round(n / 3600, 1) if n is not None else None


def _status(v):
    return clean_text(v, 30) if isinstance(v, str) else None


def _vtuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def _slot(d: dict, i: int) -> str:
    n = _pick(d, "num_id", "slot_id")
    if n is not None and _num(n) is not None:
        return f"Disque {int(_num(n))}"
    m = re.search(r"(\d+)$", str(d.get("id") or ""))
    return f"Disque {m.group(1)}" if m else f"Disque {i + 1}"


def _power_on_hours(info) -> float | None:
    rows = (info or {}).get("smartInfo") or (info or {}).get("smart_info") or []
    for r in rows if isinstance(rows, list) else []:
        if str(r.get("id")) == "9" or "power_on" in str(r.get("name", "")).lower():
            raw = re.match(r"\d+", str(_pick(r, "raw", "raw_value", "rawValue") or ""))
            return int(raw.group(0)) if raw else None
    return None


def _health(health) -> dict:
    h = (health or {}).get("healthInfo") or health or {}
    ov = h.get("overview") or h
    last = _pick(h, "last_test", "smart_test") or {}
    return {
        "test_result": _status(_pick(last, "result", "status") or _pick(ov, "smart_test_result", "last_test_result", "smart_test")),
        "test_type": _status(_pick(last, "type") or _pick(ov, "smart_test_type", "last_test_type")),
        "test_at": _iso(_pick(last, "time", "date") or _pick(ov, "smart_test_time", "last_test_time")),
        "ihm_status": _status(_pick(ov, "ihm", "ihm_status", "ihm_health")),
        "smart_status": _status(_pick(ov, "smart", "smart_status")),
    }


def map_nas(result: dict) -> dict:
    raw, errors = result.get("raw") or {}, dict(result.get("errors") or {})
    sysinfo = raw.get("system") if isinstance(raw.get("system"), dict) else {}
    util = raw.get("utilization") if isinstance(raw.get("utilization"), dict) else {}
    storage = raw.get("storage") if isinstance(raw.get("storage"), dict) else {}
    smart = raw.get("smart") or {}

    cpu = util.get("cpu") or {}
    cpu_pct = None
    if cpu:
        parts = [_num(cpu.get(k)) for k in ("user_load", "system_load", "other_load")]
        cpu_pct = min(100.0, sum(p for p in parts if p is not None)) if any(p is not None for p in parts) else None
    ram_pct = _num((util.get("memory") or {}).get("real_usage"))

    volumes = []
    for i, v in enumerate(storage.get("volumes") or []):
        m = re.search(r"(\d+)$", str(v.get("vol_path") or v.get("id") or ""))
        size = v.get("size") or {}
        volumes.append({"name": f"Volume {m.group(1) if m else i + 1}", "status": _status(v.get("status")),
                        "used_bytes": _num(size.get("used")), "total_bytes": _num(size.get("total"))})

    pools = []
    for i, p in enumerate(storage.get("storagePools") or storage.get("storage_pools") or []):
        m = re.search(r"(\d+)$", str(p.get("num_id") or p.get("id") or ""))
        scrub = p.get("scrubbing") if isinstance(p.get("scrubbing"), dict) else {}
        pools.append({
            "name": f"Groupe de stockage {m.group(1) if m else i + 1}", "status": _status(p.get("status")),
            "raid": _status(_pick(p, "device_type", "raidType", "raid_type")),
            "scrub_status": _status(_pick(scrub, "status") or _pick(p, "scrubbingStatus", "scrubbing_status")),
            "scrub_last_at": _iso(_pick(scrub, "last_done_time", "last_time") or _pick(p, "last_scrubbing_time", "last_done_time")),
        })

    disks = []
    for i, d in enumerate((storage.get("disks") or [])[:40]):
        s = smart.get(str(d.get("id") or "")) or {}
        h = _health(s.get("health"))
        disks.append({
            "slot": _slot(d, i), "model": clean_text(d.get("model"), 60), "vendor": clean_text(d.get("vendor"), 40),
            "size_bytes": _num(d.get("size_total")), "temp_c": _num(d.get("temp")),
            "status": _status(_pick(d, "overview_status", "status")),
            "smart_status": h["smart_status"] or _status(d.get("smart_status")),
            "power_on_hours": _power_on_hours(s.get("info")),
            "test_type": h["test_type"], "test_result": h["test_result"], "test_at": h["test_at"], "ihm_status": h["ihm_status"],
        })
    if disks and all(x["power_on_hours"] is None for x in disks):
        errors.setdefault("smart", "heures de fonctionnement absentes de la réponse de DSM")
    if disks and all(x["test_result"] is None for x in disks):
        errors.setdefault("smart", "résultat des tests SMART absent de la réponse de DSM")
    if pools and all(p["scrub_last_at"] is None for p in pools):
        errors.setdefault("scrubbing", "date du dernier nettoyage des données absente de la réponse de DSM")

    upd = raw.get("dsm_update") if isinstance(raw.get("dsm_update"), dict) else None
    dsm_update = None
    if upd is not None:
        u = upd.get("update") if isinstance(upd.get("update"), dict) else upd
        avail = u.get("available")
        dsm_update = {"available": avail if isinstance(avail, bool) else None, "version": clean_text(_pick(u, "version", "update_version"), 60)}

    installed = raw.get("packages") if isinstance(raw.get("packages"), dict) else None
    server = raw.get("package_updates") if isinstance(raw.get("package_updates"), dict) else None
    packages, n_installed = [], None
    if installed is not None:
        inst = installed.get("packages") or []
        n_installed = len(inst)
        latest = {}
        for p in (server or {}).get("packages") or []:
            if p.get("id") and p.get("version"):
                latest[p["id"]] = str(p["version"])
        for p in inst:
            cur, new = str(p.get("version") or ""), latest.get(p.get("id"))
            if new and _vtuple(new) > _vtuple(cur):
                packages.append({"name": clean_text(_pick(p, "name", "id"), 60) or "paquet",
                                 "installed": clean_text(cur, 40), "latest": clean_text(new, 40)})

    temp = _num(_pick(sysinfo, "sys_temp", "temperature"))
    warn = _pick(sysinfo, "sys_tempwarn", "temperature_warn")
    return {
        "model": clean_text(sysinfo.get("model"), 40),
        "dsm_version": clean_text(_pick(sysinfo, "firmware_ver", "version_string"), 60),
        "dsm_update": dsm_update,
        "system_status": _status(_pick(sysinfo, "sys_status", "status")),
        "temperature_c": temp,
        "temperature_warning": warn if isinstance(warn, bool) else None,
        "cpu_pct": cpu_pct,
        "ram_pct": ram_pct,
        "uptime_h": _uptime_h(_pick(sysinfo, "up_time", "uptime")),
        "volumes": volumes,
        "pools": pools,
        "disks": disks,
        "packages": packages[:200],
        "packages_installed": n_installed,
        "unavailable": {k: v for k, v in errors.items()},
    }
