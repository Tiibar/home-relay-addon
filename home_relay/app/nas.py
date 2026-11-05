"""Lecture du NAS Synology par SNMPv3, en LECTURE SEULE (aucun compte DSM).

Le module appelle les outils standard net-snmp (`snmpget`, `snmpwalk`) :
  * seulement ces deux commandes (GET, et GETNEXT pour parcourir une table) ;
    `snmpset` et toute autre commande sont refusés dans le code avant tout
    lancement (`ForbiddenRequest`), et `snmpset` est retiré de l'image ;
  * seulement les OID de la liste blanche (`ALLOWED_OIDS` : valeurs exactes,
    `ALLOWED_TABLES` : colonnes de tables) ; toute autre demande est refusée
    avant l'envoi, et toute réponse hors liste blanche est ignorée ;
  * SNMPv3 « authPriv » (authentification SHA, chiffrement AES) avec
    l'utilisateur SNMP du NAS ; les deux mots de passe ne passent jamais sur
    la ligne de commande : ils sont écrits dans un fichier de configuration
    temporaire (droits 600), lu par net-snmp (`SNMPCONFPATH`).

Jamais lu ni envoyé : le numéro de série (SYNOLOGY-SYSTEM-MIB serialNumber,
absent de la liste blanche), les adresses, les comptes, les dossiers.

Ce que SNMP ne fournit pas (historique des tests SMART, nettoyage des données,
mises à jour des paquets) est envoyé « non disponible via SNMP ».
"""

import os
import re
import shutil
import subprocess
import tempfile
import time

from privacy import clean_text

READ_EVERY_S = 30 * 60          # le NAS change lentement : une lecture toutes les 30 min
# NAS injoignable (il redémarre, par ex. après une coupure de courant) : nouvel essai au cycle
# suivant, sans attendre 30 min. Mot de passe ou utilisateur refusé : 30 min.
RETRY_UNREACHABLE_S = 5 * 60
TIMEOUT_S = 5                    # par requête SNMP (net-snmp -t)
RETRIES = 1
PROCESS_TIMEOUT_S = 60

SYN = "1.3.6.1.4.1.6574"
# Valeurs uniques (GET)
ALLOWED_OIDS = {
    f"{SYN}.1.1.0": "system_status",     # SYNOLOGY-SYSTEM-MIB systemStatus (1 normal, 2 failed)
    f"{SYN}.1.2.0": "temperature",       # temperature (°C)
    f"{SYN}.1.5.1.0": "model",           # modelName
    f"{SYN}.1.5.3.0": "version",         # version (DSM)
    f"{SYN}.1.5.4.0": "upgrade",         # upgradeAvailable
    "1.3.6.1.2.1.25.1.1.0": "uptime",    # HOST-RESOURCES-MIB hrSystemUptime (centièmes de seconde)
    "1.3.6.1.4.1.2021.4.5.0": "mem_total",    # UCD-SNMP-MIB memTotalReal (Ko)
    "1.3.6.1.4.1.2021.4.6.0": "mem_avail",    # memAvailReal
    "1.3.6.1.4.1.2021.4.14.0": "mem_buffer",  # memBuffer
    "1.3.6.1.4.1.2021.4.15.0": "mem_cached",  # memCached
}
# Colonnes de tables (parcourues par GETNEXT, sans sortir de la colonne)
ALLOWED_TABLES = {
    f"{SYN}.2.1.1.2": "disk_id",          # SYNOLOGY-DISK-MIB diskID (« Disk 1 »)
    f"{SYN}.2.1.1.3": "disk_model",       # diskModel
    f"{SYN}.2.1.1.5": "disk_status",      # diskStatus
    f"{SYN}.2.1.1.6": "disk_temp",        # diskTemperature
    f"{SYN}.2.1.1.13": "disk_health",     # diskHealthStatus (DSM 7.1 et plus)
    f"{SYN}.3.1.1.2": "raid_name",        # SYNOLOGY-RAID-MIB raidName
    f"{SYN}.3.1.1.3": "raid_status",      # raidStatus
    f"{SYN}.3.1.1.4": "raid_free",        # raidFreeSize (octets)
    f"{SYN}.3.1.1.5": "raid_total",       # raidTotalSize (octets)
    f"{SYN}.5.1.1.2": "smart_dev",        # SYNOLOGY-SMART-MIB diskSMARTInfoDevName
    f"{SYN}.5.1.1.4": "smart_attr",       # diskSMARTAttrId
    f"{SYN}.5.1.1.8": "smart_raw",        # diskSMARTAttrRaw
    "1.3.6.1.2.1.25.3.3.1.2": "cpu_load",     # HOST-RESOURCES-MIB hrProcessorLoad (%)
    "1.3.6.1.2.1.25.2.3.1.3": "store_descr",  # hrStorageDescr (« /volume1 »)
    "1.3.6.1.2.1.25.2.3.1.4": "store_units",  # hrStorageAllocationUnits
    "1.3.6.1.2.1.25.2.3.1.5": "store_size",   # hrStorageSize
    "1.3.6.1.2.1.25.2.3.1.6": "store_used",   # hrStorageUsed
    # UCD-SNMP-MIB dskTable : utilisation réelle du système de fichiers (/volumeN), en Ko, sur 64 bits
    "1.3.6.1.4.1.2021.9.1.2": "dsk_path",       # dskPath
    "1.3.6.1.4.1.2021.9.1.11": "dsk_total_lo",  # dskTotalLow
    "1.3.6.1.4.1.2021.9.1.12": "dsk_total_hi",  # dskTotalHigh
    "1.3.6.1.4.1.2021.9.1.15": "dsk_used_lo",   # dskUsedLow
    "1.3.6.1.4.1.2021.9.1.16": "dsk_used_hi",   # dskUsedHigh
}
ALLOWED_COMMANDS = {"snmpget", "snmpwalk"}
# Ce que SNMP ne donne pas : affiché tel quel, jamais deviné
NOT_IN_SNMP = {
    "smart_tests": "non disponible via SNMP (historique et résultat des tests SMART)",
    "scrubbing": "non disponible via SNMP (date du dernier nettoyage des données)",
    "package_updates": "non disponible via SNMP (mises à jour des paquets)",
}

DISK_STATUS = {1: "normal", 2: "initialized", 3: "not_initialized", 4: "system_partition_failed", 5: "crashed"}
DISK_HEALTH = {1: "normal", 2: "warning", 3: "critical", 4: "failing"}
RAID_STATUS = {1: "normal", 2: "repairing", 3: "migrating", 4: "expanding", 5: "deleting", 6: "creating",
               7: "syncing", 8: "parity_checking", 9: "assembling", 10: "canceling", 11: "degrade", 12: "crashed",
               13: "data_scrubbing", 14: "deploying", 15: "undeploying", 16: "mount_cache", 17: "unmount_cache",
               18: "expanding", 19: "converting", 20: "migrating", 21: "unknown"}
UPGRADE = {1: True, 2: False}    # 3 connexion en cours, 4 hors ligne, 5 autre : inconnu


class NasError(Exception):
    pass


class ForbiddenRequest(NasError):
    """Commande ou OID hors liste blanche : refusé avant tout lancement."""


def _norm(oid: str) -> str:
    return oid.strip().lstrip(".")


def check_request(command: str, oids: list[str]) -> None:
    """Lève ForbiddenRequest si la requête n'est pas une lecture de la liste blanche."""
    if command not in ALLOWED_COMMANDS:
        raise ForbiddenRequest(f"commande SNMP refusée : {command}")
    if not oids:
        raise ForbiddenRequest("aucun OID demandé")
    for oid in oids:
        o = _norm(oid)
        if not re.fullmatch(r"\d+(?:\.\d+)+", o):
            raise ForbiddenRequest(f"OID invalide : {oid}")
        if command == "snmpget" and o not in ALLOWED_OIDS:
            raise ForbiddenRequest(f"OID refusé par la liste blanche : {o}")
        if command == "snmpwalk" and o not in ALLOWED_TABLES:
            raise ForbiddenRequest(f"table refusée par la liste blanche : {o}")


def allowed_answer(oid: str) -> bool:
    o = _norm(oid)
    return o in ALLOWED_OIDS or any(o.startswith(t + ".") for t in ALLOWED_TABLES)


_LINE = re.compile(r"^\.?(\d+(?:\.\d+)+)\s+=\s+(.*)$")


def parse_output(text: str) -> dict[str, str]:
    """Sortie net-snmp (-On -OQ -Oe -Ot) -> {oid: valeur} ; valeurs absentes ignorées."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        oid, val = m.group(1), m.group(2).strip()
        if not allowed_answer(oid) or val.startswith(("No Such", "No more variables")):
            continue
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1].replace('\\"', '"')
        out[oid] = val
    return out


def snmp_reason(stderr: str) -> str:
    s = (stderr or "").lower()
    if "timeout" in s:
        return "NAS injoignable en SNMP (délai dépassé : pare-feu UDP 161, adresse ou service SNMP)"
    if "authentication failure" in s or "wrong digest" in s:
        return "SNMP refusé : mot de passe d'authentification incorrect"
    if "decryption error" in s:
        return "SNMP refusé : mot de passe de chiffrement incorrect"
    if "unknown user name" in s:
        return "SNMP refusé : utilisateur SNMP inconnu du NAS"
    if "unsupported security level" in s:
        return "SNMP refusé : niveau de sécurité (SHA + AES attendus)"
    return clean_text((stderr or "").strip().splitlines()[-1] if (stderr or "").strip() else "erreur SNMP", 160) or "erreur SNMP"


class NasClient:
    def __init__(self, host: str, user: str, auth_password: str, priv_password: str, runner=None):
        if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host or ""):
            raise NasError("adresse du NAS invalide (nom ou adresse, sans https:// ni port)")
        for label, value in (("utilisateur SNMP", user), ("mot de passe SNMP", auth_password), ("mot de passe SNMP", priv_password)):
            if not value or any(c in value for c in '"\\\n\r'):
                raise NasError(f"{label} vide ou avec un caractère refusé (guillemet, barre oblique inverse, retour à la ligne)")
        if len(auth_password) < 8 or len(priv_password) < 8:
            raise NasError("mots de passe SNMP : 8 caractères au moins (exigence de SNMPv3)")
        self.host = host
        self.user = user
        self.auth_password = auth_password
        self.priv_password = priv_password
        self.runner = runner or self._run
        self.last_read = 0.0
        self.conf_dir = None

    # -- transport (liste blanche) ------------------------------------------
    def _conf(self) -> str:
        """Fichier snmp.conf temporaire (600) : les mots de passe ne passent jamais en argument."""
        if self.conf_dir and os.path.isdir(self.conf_dir):
            return self.conf_dir
        d = tempfile.mkdtemp(prefix="home-relay-snmp-")
        os.chmod(d, 0o700)
        path = os.path.join(d, "snmp.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("defVersion 3\ndefSecurityLevel authPriv\ndefAuthType SHA\ndefPrivType AES\n")
            f.write(f'defSecurityName "{self.user}"\ndefAuthPassphrase "{self.auth_password}"\ndefPrivPassphrase "{self.priv_password}"\n')
        self.conf_dir = d
        return d

    def _run(self, command: str, oids: list[str]) -> tuple[int, str, str]:
        exe = shutil.which(command)
        if not exe:
            raise NasError(f"outil {command} absent de l'image du module")
        conf = self._conf()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "SNMPCONFPATH": conf, "SNMP_PERSISTENT_DIR": conf, "MIBS": ""}
        args = [exe, "-On", "-OQ", "-Oe", "-Ot", "-t", str(TIMEOUT_S), "-r", str(RETRIES), self.host, *oids]
        p = subprocess.run(args, capture_output=True, text=True, timeout=PROCESS_TIMEOUT_S, env=env, check=False)
        return p.returncode, p.stdout, p.stderr

    def request(self, command: str, oids: list[str]) -> dict[str, str]:
        """Seul point de sortie vers le NAS : liste blanche d'abord."""
        check_request(command, oids)
        try:
            code, out, err = self.runner(command, [_norm(o) for o in oids])
        except subprocess.TimeoutExpired:
            raise NasError("NAS injoignable en SNMP (délai dépassé)") from None
        values = parse_output(out)
        if code != 0 and not values:
            raise NasError(snmp_reason(err))
        return values

    def due(self, now: float | None = None) -> bool:
        return (now if now is not None else time.monotonic()) - self.last_read >= READ_EVERY_S or not self.last_read

    # -- lecture complète ------------------------------------------------------
    def read(self) -> dict:
        """Une requête GET pour les valeurs uniques, puis une marche par colonne.
        Prochaine lecture dans 30 min ; si le NAS est injoignable (il redémarre), dans 5 min."""
        self.last_read = time.monotonic()
        try:
            values = self.request("snmpget", list(ALLOWED_OIDS))   # erreur ici = NAS injoignable : la source échoue
        except NasError as e:
            if "injoignable" in str(e):
                self.last_read -= READ_EVERY_S - RETRY_UNREACHABLE_S
            raise
        errors: dict[str, str] = {}
        for table in ALLOWED_TABLES:
            try:
                values.update(self.request("snmpwalk", [table]))
            except NasError as e:
                errors.setdefault(ALLOWED_TABLES[table], str(e))
        return {"values": values, "errors": errors}


# ---------------------------------------------------------------------------
# Mise en forme (sans numéro de série ni adresse)
# ---------------------------------------------------------------------------

def _int(v):
    m = re.match(r"\s*(-?\d+)", str(v)) if v is not None else None
    return int(m.group(1)) if m else None


def _u32(v):
    """Entier SNMP 32 bits relu en non signé (un hrStorage trop grand revient négatif)."""
    n = _int(v)
    return n + 2 ** 32 if n is not None and n < 0 else n


def _u64(lo, hi):
    lo, hi = _u32(lo), _u32(hi)
    return None if lo is None else (hi or 0) * 2 ** 32 + lo


def _col(values: dict, name: str) -> dict[str, str]:
    """{index: valeur} d'une colonne de table."""
    base = next(k for k, v in ALLOWED_TABLES.items() if v == name)
    return {oid[len(base) + 1:]: v for oid, v in values.items() if oid.startswith(base + ".")}


def _scalar(values: dict, name: str):
    oid = next(k for k, v in ALLOWED_OIDS.items() if v == name)
    return values.get(oid)


def _slot(disk_id: str | None, index: str, n: int) -> str:
    m = re.search(r"(\d+)\s*$", disk_id or "")
    return f"Disque {m.group(1)}" if m else f"Disque {n}"


def _smart_hours(values: dict) -> dict[int, int]:
    """Heures de fonctionnement (attribut SMART 9) par numéro de disque (« sata1 » -> 1, « sda » -> 1)."""
    devs, attrs, raws = _col(values, "smart_dev"), _col(values, "smart_attr"), _col(values, "smart_raw")
    out: dict[int, int] = {}
    for idx, attr in attrs.items():
        if _int(attr) != 9:
            continue
        dev = (devs.get(idx) or "").strip().lower()
        m = re.search(r"(\d+)$", dev)
        n = int(m.group(1)) if m else (ord(dev[-1]) - ord("a") + 1 if re.fullmatch(r"sd[a-z]", dev) else None)
        raw = _int(raws.get(idx))
        if n and raw is not None:
            out[n] = raw
    return out


def tib(b) -> str:
    """Octets -> « 10,5 To » en base 1024, comme l'affiche DSM (journal seulement)."""
    return "?" if b is None else f"{b / 1024 ** 4:.1f} To".replace(".", ",")


def map_nas(result: dict) -> dict:
    v, errors = result.get("values") or {}, dict(result.get("errors") or {})
    unavailable: dict[str, str] = {}

    status = _int(_scalar(v, "system_status"))
    upgrade = _int(_scalar(v, "upgrade"))
    uptime = _int(_scalar(v, "uptime"))

    # Mémoire : UCD-SNMP-MIB (sans les tampons ni le cache, comme DSM)
    total, avail, buf, cached = (_int(_scalar(v, k)) for k in ("mem_total", "mem_avail", "mem_buffer", "mem_cached"))
    ram_pct = None
    if total:
        used = total - (avail or 0) - (buf or 0) - (cached or 0)
        ram_pct = round(max(0.0, min(100.0, 100 * used / total)), 1)
    loads = [x for x in (_int(x) for x in _col(v, "cpu_load").values()) if x is not None]
    cpu_pct = round(sum(loads) / len(loads), 1) if loads else None

    # Volumes : utilisation réelle du système de fichiers /volumeN (comme DSM).
    # 1) UCD-SNMP-MIB dskTable (64 bits, Ko) ; 2) à défaut HOST-RESOURCES-MIB hrStorage.
    # Jamais l'espace du groupe de stockage (RAID-MIB), qui n'est pas celui du volume.
    volumes = []
    paths = _col(v, "dsk_path")
    t_lo, t_hi, u_lo, u_hi = (_col(v, k) for k in ("dsk_total_lo", "dsk_total_hi", "dsk_used_lo", "dsk_used_hi"))
    for idx, p in sorted(paths.items(), key=lambda x: x[1]):
        m = re.fullmatch(r"/volume(\d+)", p.strip())
        total_kb, used_kb = _u64(t_lo.get(idx), t_hi.get(idx)), _u64(u_lo.get(idx), u_hi.get(idx))
        if m and total_kb:
            volumes.append({"name": f"Volume {m.group(1)}", "status": None, "source": "ucd_dsk",
                            "used_bytes": used_kb * 1024 if used_kb is not None else None, "total_bytes": total_kb * 1024})
    if not volumes:
        descr, units, size, used_ = (_col(v, k) for k in ("store_descr", "store_units", "store_size", "store_used"))
        for idx, d in sorted(descr.items(), key=lambda x: x[1]):
            m = re.fullmatch(r"/volume(\d+)", d.strip())
            u, s, us = _int(units.get(idx)), _u32(size.get(idx)), _u32(used_.get(idx))
            if m and u and s:
                volumes.append({"name": f"Volume {m.group(1)}", "status": None, "source": "hr_storage",
                                "used_bytes": us * u if us is not None else None, "total_bytes": s * u})

    # Groupes de stockage / RAID : SYNOLOGY-RAID-MIB
    names, rstat, rfree, rtotal = (_col(v, k) for k in ("raid_name", "raid_status", "raid_free", "raid_total"))
    pools = []
    for idx in sorted(names, key=lambda x: _int(x) or 0):
        name = clean_text(names[idx], 40) or f"Groupe {idx}"
        name = re.sub(r"^Storage Pool", "Groupe de stockage", name)
        pools.append({"name": name, "status": RAID_STATUS.get(_int(rstat.get(idx)), None),
                      "free_bytes": _int(rfree.get(idx)), "total_bytes": _int(rtotal.get(idx))})

    # Disques : SYNOLOGY-DISK-MIB (+ heures SMART)
    ids, models, dstat, temps, health = (_col(v, k) for k in ("disk_id", "disk_model", "disk_status", "disk_temp", "disk_health"))
    hours = _smart_hours(v)
    disks = []
    for n, idx in enumerate(sorted(ids or models, key=lambda x: _int(x) or 0), 1):
        slot = _slot(ids.get(idx), idx, n)
        num = _int(re.sub(r"\D", "", slot)) or n
        disks.append({
            "slot": slot, "model": clean_text(models.get(idx), 60),
            "temp_c": _int(temps.get(idx)), "status": DISK_STATUS.get(_int(dstat.get(idx))),
            "health_status": DISK_HEALTH.get(_int(health.get(idx))),
            "power_on_hours": hours.get(num),
        })

    if disks and all(d["health_status"] is None for d in disks):
        unavailable["disk_health"] = "état de santé des disques absent de la MIB de ce NAS"
    if disks and all(d["power_on_hours"] is None for d in disks):
        unavailable["smart"] = "heures de fonctionnement absentes (SYNOLOGY-SMART-MIB)"
    if not volumes:
        unavailable["volumes"] = "utilisation du volume absente (UCD-SNMP dskTable et HOST-RESOURCES hrStorage)"
    if ram_pct is None:
        unavailable["memory"] = "mémoire absente (UCD-SNMP-MIB)"
    for key, reason in errors.items():
        if key.startswith("disk_") and not disks:
            unavailable["storage"] = reason
        elif key.startswith("raid_") and not pools:
            unavailable["raid"] = reason
        elif key.startswith(("store_", "dsk_")) and not volumes:
            unavailable["volumes"] = reason
    unavailable.update(NOT_IN_SNMP)

    return {
        "model": clean_text(_scalar(v, "model"), 40),
        "dsm_version": clean_text(_scalar(v, "version"), 60),
        "dsm_update": {"available": UPGRADE.get(upgrade), "version": None} if upgrade is not None else None,
        "system_status": {1: "normal", 2: "failed"}.get(status),
        "temperature_c": _int(_scalar(v, "temperature")),
        "cpu_pct": cpu_pct,
        "ram_pct": ram_pct,
        "uptime_h": round(uptime / 360000, 1) if uptime is not None else None,
        "volumes": volumes,
        "pools": pools,
        "disks": disks[:40],
        "unavailable": unavailable,
    }
