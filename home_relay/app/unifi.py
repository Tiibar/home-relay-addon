"""Lecture de la passerelle UniFi locale (API classique « UniFi Network »).

Uniquement des lectures (GET). Toute requête non-GET passe par une LISTE
BLANCHE stricte (`ALLOWED_NON_GET`, vérifiée dans `_request`) qui n'en
autorise que deux, aucune ne modifiant rien :
  * POST /api/auth/login : ouverture de la session ;
  * POST /proxy/network/v2/api/site/<site>/system-log/all : RECHERCHE dans le
    journal (catégorie SECURITY, menaces IPS), la requête qu'utilise
    l'interface de UniFi Network 10 ; le corps ne peut contenir que les champs
    de recherche (`SYSTEM_LOG_FIELDS`).
Garde-fou principal : le compte local « home-relay » est en View Only (lecture
seule) : même une requête erronée ne pourrait rien modifier.

Pourquoi l'API classique et pas l'API officielle « Integrations » : l'API
officielle (clé API) ne donne ni les compteurs d'octets par client, ni la
satisfaction Wi-Fi, ni l'occupation des canaux, ni les menaces IPS, ni la santé
WAN. Voir DOCS.md, section « Ce que le module lit ».
"""

import http.cookiejar
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from privacy import clean_text, hashed_id, redact

TIMEOUT = 20


class UnifiError(Exception):
    pass


class ThreatsUnavailable(Exception):
    """Source désactivée proprement (pas une panne)."""


class ForbiddenRequest(UnifiError):
    """Requête non-GET hors de la liste blanche : refusée avant tout envoi."""


LOGIN_PATH = "/api/auth/login"
SYSTEM_LOG_PATH = "/proxy/network/v2/api/site/{site}/system-log/all"
# Seules requêtes non-GET possibles : (méthode, chemin exact, champs autorisés du corps)
ALLOWED_NON_GET = {
    ("POST", LOGIN_PATH): {"username", "password", "rememberMe"},
    ("POST", SYSTEM_LOG_PATH): {"timestampFrom", "timestampTo", "pageSize", "pageNumber", "categories"},
}
SYSTEM_LOG_FIELDS = ALLOWED_NON_GET[("POST", SYSTEM_LOG_PATH)]
SYSTEM_LOG_PAGE = 100
SYSTEM_LOG_MAX_PAGES = 5
THREATS_UNAVAILABLE = "menaces non disponibles sur cette passerelle"


class UnifiClient:
    def __init__(self, base_url: str, username: str, password: str, site: str = "default", verify_ssl: bool = False):
        self.base = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.site = site or "default"
        ctx = ssl.create_default_context()
        if not verify_ssl:  # certificat auto-signé de la passerelle, réseau local
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
        )
        self.logged_in = False
        self.threats_endpoint = None
        self.threats_disabled_until = 0.0
        self.threats_reason = ""
        self.threats_since_ms = 0
        self.csrf = None

    # -- transport (liste blanche) ------------------------------------------
    def _allowed(self, method: str, path: str, body) -> None:
        """Lève ForbiddenRequest si la requête n'est pas un GET autorisé par la liste blanche."""
        if method == "GET":
            if body is not None:
                raise ForbiddenRequest("GET avec corps refusé")
            return
        site_path = SYSTEM_LOG_PATH.format(site=urllib.parse.quote(self.site))
        template = {LOGIN_PATH: LOGIN_PATH, site_path: SYSTEM_LOG_PATH}.get(path)
        fields = ALLOWED_NON_GET.get((method, template)) if template else None
        if fields is None:
            raise ForbiddenRequest(f"requête {method} refusée par la liste blanche : {path}")
        if not isinstance(body, dict) or not set(body) <= fields:
            raise ForbiddenRequest(f"corps de requête refusé pour {path}")

    def _request(self, method: str, path: str, params: dict | None = None, body: dict | None = None):
        """Seul point de sortie vers la passerelle : liste blanche d'abord."""
        self._allowed(method, path, body)
        return self._send(method, path, params, body)

    def _send(self, method: str, path: str, params: dict | None, body: dict | None):
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            csrf = getattr(self, "csrf", None)
            if csrf and path != LOGIN_PATH:
                headers["X-CSRF-Token"] = csrf
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with self.opener.open(req, timeout=TIMEOUT) as r:
            token = r.headers.get("X-Updated-CSRF-Token") or r.headers.get("X-CSRF-Token")
            if token:
                self.csrf = token
            raw = r.read().decode("utf-8")
        return json.loads(raw or "null")

    # -- session -------------------------------------------------------------
    def login(self):
        try:
            self._request("POST", LOGIN_PATH, body={"username": self.username, "password": self.password, "rememberMe": False})
        except urllib.error.HTTPError as e:
            raise UnifiError(f"connexion refusée (HTTP {e.code}) : vérifier l'identifiant et le mot de passe") from None
        except urllib.error.URLError as e:
            raise UnifiError(f"passerelle injoignable ({e.reason})") from None
        self.logged_in = True

    def _authed(self, method: str, path: str, params=None, body=None):
        """Requête authentifiée ; reconnecte une fois si la session a expiré."""
        self._allowed(method, path, body)   # refus avant même la connexion
        if not self.logged_in:
            self.login()
        for attempt in (1, 2):
            try:
                return self._request(method, path, params, body)
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 1:
                    self.login()
                    continue
                raise UnifiError(f"HTTP {e.code} sur {path}") from None
            except urllib.error.URLError as e:
                raise UnifiError(f"passerelle injoignable ({e.reason})") from None
        raise UnifiError(f"accès refusé sur {path}")

    def get(self, path: str, params: dict | None = None):
        """GET authentifié."""
        data = self._authed("GET", path, params)
        return data.get("data", data) if isinstance(data, dict) and "data" in data else data

    def search_system_log(self, since_ms: int, until_ms: int, page: int = 0, categories=("SECURITY",)):
        """La seule recherche POST autorisée : journal système, catégorie SECURITY."""
        body = {"timestampFrom": int(since_ms), "timestampTo": int(until_ms),
                "pageSize": SYSTEM_LOG_PAGE, "pageNumber": int(page)}
        if categories:
            body["categories"] = list(categories)
        return self._authed("POST", SYSTEM_LOG_PATH.format(site=urllib.parse.quote(self.site)), body=body)

    # -- lectures ------------------------------------------------------------
    def net(self, suffix: str) -> str:
        return f"/proxy/network/api/s/{urllib.parse.quote(self.site)}/{suffix}"

    def devices(self):
        return self.get(self.net("stat/device")) or []

    def clients_now(self):
        return self.get(self.net("stat/sta")) or []

    def networks(self):
        return self.get(self.net("rest/networkconf")) or []

    def health(self):
        return self.get(self.net("stat/health")) or []

    def clients_24h(self):
        """Clients vus sur 24 h : API v2 de l'interface, sinon stat/alluser."""
        try:
            data = self.get(
                f"/proxy/network/v2/api/site/{urllib.parse.quote(self.site)}/clients/history",
                {"onlyNonBlocked": "true", "includeUnifiDevices": "false", "withinHours": 24},
            )
            if isinstance(data, list):
                return data
        except UnifiError:
            pass
        rows = self.get(self.net("stat/alluser")) or []
        since = time.time() - 86400
        return [r for r in rows if _epoch(r.get("last_seen")) and _epoch(r.get("last_seen")) >= since]

    def threats_from_system_log(self):
        """Menaces de la catégorie SECURITY depuis la dernière lecture (24 h la
        première fois), par pages de 100 (5 pages au plus)."""
        now_ms = int(time.time() * 1000)
        since = self.threats_since_ms or now_ms - 86400_000
        rows, categories = [], ("SECURITY",)
        for page in range(SYSTEM_LOG_MAX_PAGES):
            try:
                data = self.search_system_log(since, now_ms, page, categories)
            except UnifiError as e:
                # certaines versions refusent le filtre de catégorie : on filtre ici
                if page == 0 and categories and "HTTP 400" in str(e):
                    categories = ()
                    data = self.search_system_log(since, now_ms, page, categories)
                else:
                    raise
            found = threat_rows(data, "system-log")
            if found is None:
                raise UnifiError("format inconnu")
            rows += found
            items = data.get("data") if isinstance(data, dict) else data
            total = data.get("total_element_count") if isinstance(data, dict) else None
            if not items or len(items) < SYSTEM_LOG_PAGE or (total is not None and (page + 1) * SYSTEM_LOG_PAGE >= total):
                break
        self.threats_since_ms = now_ms
        return rows

    def threats(self):
        """Menaces IPS : journal système (UniFi Network 9 et 10), sinon les
        anciennes lectures GET (versions plus anciennes). Si rien ne répond,
        la source est désactivée (nouvel essai 24 h plus tard).
        Renvoie (lignes, nom de la source)."""
        now = time.time()
        if self.threats_disabled_until and now < self.threats_disabled_until:
            raise ThreatsUnavailable(THREATS_UNAVAILABLE)
        tried = []
        try:
            rows = self.threats_from_system_log()
            self.threats_endpoint = "system-log"
            return rows, "system-log"
        except UnifiError as e:
            tried.append(f"system-log {str(e).split(' sur ')[0]}")
        for name, path, params in (
            ("stat/ips/event", self.net("stat/ips/event"), {"_limit": 200}),
            ("stat/alarm", self.net("stat/alarm"), {"archived": "false"}),
        ):
            try:
                data = self.get(path, params)
            except UnifiError as e:
                tried.append(f"{name} {str(e).split(' sur ')[0]}")
                continue
            rows = threat_rows(data, name)
            if rows is None:
                tried.append(f"{name} format inconnu")
                continue
            self.threats_endpoint = name
            return rows, name
        self.threats_endpoint = None
        self.threats_disabled_until = now + 86400
        self.threats_reason = "essayé : " + ", ".join(tried)   # détail pour le journal du module seulement
        raise ThreatsUnavailable(THREATS_UNAVAILABLE)


# ---------------------------------------------------------------------------
# Transformation (fonctions pures, testées) : on ne garde que des champs choisis
# ---------------------------------------------------------------------------

IPS_KEY = ("IPS", "THREAT", "INTRUSION")


def threat_rows(data, endpoint: str):
    """Extrait la liste des menaces d'une réponse ; None si la forme est inconnue."""
    if isinstance(data, dict):
        for key in ("data", "items", "threats", "events"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            return None
    if not isinstance(data, list):
        return None
    rows = [r for r in data if isinstance(r, dict)]
    if endpoint == "system-log":   # catégorie SECURITY (filtrée ici aussi, au cas où)
        rows = [r for r in rows if str(r.get("category", "")).upper() == "SECURITY"
                or any(k in str(r.get("key", "")).upper() for k in IPS_KEY)]
    elif endpoint in ("stat/alarm", "stat/event"):  # journaux généraux : garder l'IPS
        rows = [r for r in rows if any(k in str(r.get("key", "")).upper() for k in IPS_KEY)
                or r.get("inner_alert_signature")]
    return rows


def _epoch(v):
    """Secondes depuis 1970 (accepte des millisecondes)."""
    if v is None:
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    return v / 1000 if v > 1e12 else v


def _iso(epoch):
    e = _epoch(epoch)
    if e is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e))


def _int(v, lo=None, hi=None):
    try:
        n = int(round(float(v)))
    except (TypeError, ValueError):
        return None
    if lo is not None and n < lo or hi is not None and n > hi:
        return None
    return n


def _num(v, lo=None, hi=None):
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    if lo is not None and n < lo or hi is not None and n > hi:
        return None
    return round(n, 2)


def _signal(v):
    n = _int(v)
    return n if n is not None and -120 <= n < 0 else None


KIND = {"ugw": "gateway", "udm": "gateway", "uxg": "gateway", "usw": "switch", "uap": "ap"}
BAND = {"ng": "2.4g", "na": "5g", "6e": "6g"}


def channel_width(device, radio):
    """Largeur du canal d'une radio : champ `ht` de radio_table (« 80 », « VHT80 », « HE160 »…)."""
    for rt in device.get("radio_table") or []:
        if rt.get("radio") == radio:
            m = re.search(r"(\d{2,3})", str(rt.get("ht") or ""))
            if m and int(m.group(1)) in (20, 40, 80, 160, 320):
                return int(m.group(1))
    return None


def device_names(devices) -> dict:
    """MAC (minuscules) -> nom, pour nommer les bornes et switchs (reste en local)."""
    out = {}
    for d in devices or []:
        mac = str(d.get("mac", "")).lower()
        if mac:
            out[mac] = clean_text(d.get("name")) or clean_text(d.get("model")) or "Équipement UniFi"
    return out


def map_devices(devices, secret: str):
    names = device_names(devices)
    out = []
    for d in devices or []:
        if not d.get("mac"):
            continue
        state = d.get("state")
        up = d.get("uplink") or {}
        uplink = None
        if up:
            wireless = str(up.get("type", "")).startswith("wireless")
            rate = up.get("tx_rate")
            uplink = {
                "type": "wireless" if wireless else "wired",
                "parent": clean_text(up.get("uplink_device_name")) or names.get(str(up.get("uplink_mac", "")).lower()),
                "signal_dbm": _signal(up.get("signal")) if wireless else None,
                # sans fil : tx_rate en kb/s ; câble : speed en Mb/s
                "rate_mbps": _num(rate / 1000, 0, 100000) if wireless and isinstance(rate, (int, float)) else _num(up.get("speed"), 0, 100000),
                # numéro du port du switch parent (liaison par câble)
                "port": None if wireless else _int(up.get("uplink_remote_port") or up.get("port_idx"), 0, 128),
            }
        out.append({
            "id": hashed_id(d["mac"], secret),
            "name": clean_text(d.get("name")),
            "model": clean_text(d.get("model"), 60),
            "kind": KIND.get(d.get("type"), "other"),
            "state": "online" if state == 1 else "offline" if state == 0 else f"state_{state}",
            "firmware": str(d.get("version"))[:60] if d.get("version") else None,
            "upgradable": bool(d.get("upgradable")) if d.get("upgradable") is not None else None,
            "uptime_s": _int(d.get("uptime"), 0),
            "clients": _int(d.get("num_sta"), 0),
            "satisfaction": _int(d.get("satisfaction"), -1, 100),
            "radios": [
                {
                    "band": BAND.get(r.get("radio"), clean_text(r.get("radio"), 10)),
                    "channel": _int(r.get("channel"), 0, 300),
                    "utilization_pct": _num(r.get("cu_total"), 0, 100),
                    "satisfaction": _int(r.get("satisfaction"), -1, 100),
                    "clients": _int(r.get("num_sta"), 0),
                    # largeur du canal (MHz), lue dans la configuration radio de la borne
                    "width_mhz": channel_width(d, r.get("radio")),
                }
                for r in (d.get("radio_table_stats") or [])[:8]
            ],
            "uplink": uplink,
        })
    return out


def _network_name(c, networks_by_id):
    name = clean_text(c.get("network")) or clean_text(c.get("network_name")) or networks_by_id.get(c.get("network_id"))
    vlan = _int(c.get("vlan"), 0, 4094)
    if name and vlan:
        return f"{name} (VLAN {vlan})"
    return name


def _client_name(c):
    return clean_text(c.get("name")) or clean_text(c.get("display_name")) or clean_text(c.get("hostname"))


def map_clients(now_rows, history_rows, networks, devices, secret: str, now: float | None = None):
    """Clients connectés (avec compteurs) + clients vus sur 24 h (sans compteurs)."""
    now = now or time.time()
    names = device_names(devices)
    networks_by_id = {n.get("_id"): clean_text(n.get("name"), 60) for n in networks or [] if n.get("_id")}
    out, seen = [], set()

    for c in now_rows or []:
        mac = c.get("mac")
        if not mac:
            continue
        wired = bool(c.get("is_wired"))
        if wired:
            sw = names.get(str(c.get("sw_mac", "")).lower())
            port = _int(c.get("sw_port"), 0)
            uplink = f"{sw or 'Switch'} · port {port}" if port is not None else sw
            tx, rx = c.get("wired-tx_bytes", c.get("tx_bytes")), c.get("wired-rx_bytes", c.get("rx_bytes"))
        else:
            uplink = names.get(str(c.get("ap_mac", "")).lower())
            tx, rx = c.get("tx_bytes"), c.get("rx_bytes")
        uptime = _int(c.get("uptime"), 0)
        cid = hashed_id(mac, secret)
        seen.add(cid)
        out.append({
            "id": cid,
            "name": _client_name(c),
            "vendor": clean_text(c.get("oui"), 60),
            "wired": wired,
            "network": _network_name(c, networks_by_id),
            "uplink": uplink,
            "signal_dbm": None if wired else _signal(c.get("signal")),
            "online": True,
            "last_seen": _iso(c.get("last_seen")) or _iso(now),
            "tx_bytes": _int(tx, 0),
            "rx_bytes": _int(rx, 0),
            "connected_since": _iso(now - uptime) if uptime is not None else None,
        })

    for c in history_rows or []:
        mac = c.get("mac")
        if not mac:
            continue
        cid = hashed_id(mac, secret)
        if cid in seen:
            continue
        seen.add(cid)
        last_uplink = clean_text(c.get("last_uplink_name"))
        out.append({
            "id": cid,
            "name": _client_name(c),
            "vendor": clean_text(c.get("oui"), 60),
            "wired": bool(c.get("is_wired")) if c.get("is_wired") is not None else None,
            "network": _network_name(c, networks_by_id),
            "uplink": last_uplink,
            "signal_dbm": None,
            "online": False,
            "last_seen": _iso(c.get("last_seen")) or _iso(now),
            "tx_bytes": None,
            "rx_bytes": None,
            "connected_since": None,
        })
    return out


def _render(template, params):
    """« {CLIENT} bloqué vers {DST_IP} » -> texte, paramètres remplacés par leur nom."""
    if not isinstance(template, str):
        return None
    params = params if isinstance(params, dict) else {}

    def one(m):
        p = params.get(m.group(1))
        if isinstance(p, dict):
            return str(p.get("name") or p.get("id") or "[adresse]")
        return str(p) if p is not None else "…"
    return re.sub(r"\{([A-Z0-9_]+)\}", one, template)


def _direction(t):
    """« entrant » / « sortant » si la passerelle l'indique, sinon None."""
    params = t.get("parameters") if isinstance(t.get("parameters"), dict) else {}
    d = params.get("DIRECTION")
    raw = (d.get("name") or d.get("id")) if isinstance(d, dict) else d
    text = " ".join(str(x) for x in (t.get("direction"), raw, t.get("key"), t.get("inner_alert_direction")) if x).upper()
    if any(w in text for w in ("INBOUND", "INCOMING", "INGRESS", "WAN_IN")):
        return "entrant"
    if any(w in text for w in ("OUTBOUND", "OUTGOING", "EGRESS", "WAN_OUT")):
        return "sortant"
    return None


def _blocked(t):
    text = f"{t.get('key', '')} {t.get('inner_alert_action', '')} {t.get('action', '')}".upper()
    if "BLOCK" in text or "DROP" in text or "DENIED" in text:
        return True
    if "ALLOW" in text or "DETECT" in text or "ALERT" in text:
        return False
    return None


def map_threats(rows, secret: str):
    """Titre, gravité, catégorie, date, direction, bloqué ou non. Toute adresse
    IP ou MAC est remplacée par « [adresse] » avant l'envoi."""
    out = []
    for t in rows or []:
        key = t.get("_id") or t.get("id") or f"{t.get('timestamp') or t.get('time')}-{t.get('inner_alert_signature_id') or t.get('signature')}"
        title = redact(t.get("inner_alert_signature") or t.get("signature") or t.get("title_raw") or t.get("title")
                       or _render(t.get("message_raw"), t.get("parameters"))
                       or t.get("message") or t.get("msg"), 200)
        at = _iso(t.get("timestamp") or t.get("time") or t.get("datetime_ms"))
        if at is None and isinstance(t.get("datetime"), str):
            at = t["datetime"][:19] + "Z" if len(t["datetime"]) >= 19 else None
        if not title or not at:
            continue
        blocked = _blocked(t)
        out.append({
            "id": hashed_id(str(key), secret, is_mac=False),
            "at": at,
            "title": title,
            "severity": clean_text(t.get("inner_alert_severity") or t.get("severity") or t.get("risk"), 30),
            "category": clean_text(t.get("inner_alert_category") or t.get("catname") or t.get("subcategory")
                                   or t.get("category"), 80),
            "action": clean_text(t.get("inner_alert_action") or t.get("action"), 30)
                      or ("blocked" if blocked else "detected" if blocked is False else None),
            "direction": _direction(t),
            "blocked": blocked,
        })
    return out[:500]


def map_wan(health_rows, devices):
    """Santé WAN et speedtest, sans adresse IP ni serveur DNS."""
    sub = {h.get("subsystem"): h for h in health_rows or []}
    wan, www = sub.get("wan") or {}, sub.get("www") or {}
    wan_out = {
        "status": clean_text(wan.get("status"), 20),
        "www_status": clean_text(www.get("status"), 20),
        "isp": clean_text(wan.get("isp_name") or wan.get("isp_organization"), 60),
        "latency_ms": _num(www.get("latency"), 0),
        "uptime_s": _int(www.get("uptime"), 0),
        "drops": _int(www.get("drops"), 0),
        "rx_bytes_rate": _num(wan.get("rx_bytes-r"), 0),
        "tx_bytes_rate": _num(wan.get("tx_bytes-r"), 0),
    }
    speed = None
    if www.get("speedtest_lastrun"):
        speed = {
            "at": _iso(www.get("speedtest_lastrun")),
            "status": clean_text(www.get("speedtest_status"), 20),
            "down_mbps": _num(www.get("xput_down"), 0),
            "up_mbps": _num(www.get("xput_up"), 0),
            "ping_ms": _num(www.get("speedtest_ping"), 0),
        }
    else:
        for d in devices or []:
            st = d.get("speedtest-status") or {}
            if KIND.get(d.get("type")) == "gateway" and st.get("rundate"):
                speed = {
                    "at": _iso(st.get("rundate")),
                    "status": None,
                    "down_mbps": _num(st.get("xput_download"), 0),
                    "up_mbps": _num(st.get("xput_upload"), 0),
                    "ping_ms": _num(st.get("latency"), 0),
                }
                break
    return {k: v for k, v in wan_out.items() if v is not None} or None, speed
