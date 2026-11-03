"""Lecture de la passerelle UniFi locale (API classique « UniFi Network »).

Uniquement des lectures (GET). Seule exception : la connexion
(POST /api/auth/login), qui ouvre une session avec le compte local en lecture
seule ; elle ne modifie rien.

Pourquoi l'API classique et pas l'API officielle « Integrations » : l'API
officielle (clé API) ne donne ni les compteurs d'octets par client, ni la
satisfaction Wi-Fi, ni l'occupation des canaux, ni les menaces IPS, ni la santé
WAN. Voir DOCS.md, section « Ce que le module lit ».
"""

import http.cookiejar
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from privacy import clean_text, hashed_id

TIMEOUT = 20


class UnifiError(Exception):
    pass


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

    # -- session -------------------------------------------------------------
    def login(self):
        body = json.dumps({"username": self.username, "password": self.password, "rememberMe": False}).encode()
        req = urllib.request.Request(
            f"{self.base}/api/auth/login", data=body, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with self.opener.open(req, timeout=TIMEOUT) as r:
                r.read()
        except urllib.error.HTTPError as e:
            raise UnifiError(f"connexion refusée (HTTP {e.code}) : vérifier l'identifiant et le mot de passe") from None
        except urllib.error.URLError as e:
            raise UnifiError(f"passerelle injoignable ({e.reason})") from None
        self.logged_in = True

    def get(self, path: str, params: dict | None = None):
        """GET authentifié ; reconnecte une fois si la session a expiré."""
        if not self.logged_in:
            self.login()
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        for attempt in (1, 2):
            req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
            try:
                with self.opener.open(req, timeout=TIMEOUT) as r:
                    data = json.loads(r.read().decode("utf-8") or "null")
                    return data.get("data", data) if isinstance(data, dict) and "data" in data else data
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 1:
                    self.login()
                    continue
                raise UnifiError(f"HTTP {e.code} sur {path}") from None
            except urllib.error.URLError as e:
                raise UnifiError(f"passerelle injoignable ({e.reason})") from None
        raise UnifiError(f"accès refusé sur {path}")

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

    def threats(self):
        """Menaces IPS : stat/ips/event, sinon les alarmes IPS de stat/alarm."""
        try:
            rows = self.get(self.net("stat/ips/event"), {"_limit": 200})
            if isinstance(rows, list):
                return rows
        except UnifiError:
            pass
        rows = self.get(self.net("stat/alarm"), {"archived": "false"}) or []
        return [r for r in rows if "IPS" in str(r.get("key", "")).upper()]


# ---------------------------------------------------------------------------
# Transformation (fonctions pures, testées) : on ne garde que des champs choisis
# ---------------------------------------------------------------------------

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


def map_threats(rows, secret: str):
    out = []
    for t in rows or []:
        key = t.get("_id") or f"{t.get('timestamp') or t.get('time')}-{t.get('inner_alert_signature_id') or t.get('signature')}"
        title = clean_text(t.get("inner_alert_signature") or t.get("signature") or t.get("msg"), 200)
        at = _iso(t.get("timestamp") or t.get("time"))
        if not title or not at:
            continue
        out.append({
            "id": hashed_id(str(key), secret, is_mac=False),
            "at": at,
            "title": title,
            "severity": clean_text(t.get("inner_alert_severity") or t.get("severity"), 30),
            "category": clean_text(t.get("inner_alert_category") or t.get("catname") or t.get("category"), 80),
            "action": clean_text(t.get("inner_alert_action") or t.get("action"), 30),
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
