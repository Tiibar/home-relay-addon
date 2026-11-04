#!/usr/bin/env python3
"""Contrôle de sécurité du dépôt public : aucun secret, clé, mot de passe,
adresse IP ou adresse MAC.

    python3 scripts/check_secrets.py            # fichiers suivis par git
    python3 scripts/check_secrets.py --history  # + toutes les lignes ajoutées dans l'historique

Code de sortie 1 (et liste des trouvailles, valeur masquée) si quelque chose
est détecté. Bibliothèque standard uniquement.

Seules exceptions, volontaires et documentées :
  * adresses IP de documentation (RFC 5737 : 192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) et 0.0.0.0 / 127.0.0.1 / :: (adresse non spécifiée) ;
  * adresses MAC factices des tests : xx:00:00:00:00:yy et aa:bb:cc:dd:ee:ff.
"""

import ipaddress
import re
import subprocess
import sys

RULES = [
    ("clé privée", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jeton JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")),
    ("clé Anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}")),
    ("clé OpenAI / générique sk-", re.compile(r"\bsk-[A-Za-z0-9]{32,}")),
    ("jeton GitHub", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("clé Supabase", re.compile(r"\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{10,}")),
    ("URL de projet Supabase", re.compile(r"\b[a-z0-9]{20}\.supabase\.co\b")),
    ("clé AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("clé Google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jeton Slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("identifiants dans une URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@\"']+:[^\s/@\"']+@")),
    ("mot de passe / secret en clair", re.compile(
        r"(?i)(?<![a-z0-9])[a-z0-9_-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[a-z0-9_-]*"
        r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']")),
]

IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)")
IPV6 = re.compile(r"(?<![\w:])[0-9a-fA-F:]*:[0-9a-fA-F:]*:[0-9a-fA-F:]*(?![\w:])")
MAC = re.compile(r"(?<![\w:-])[0-9a-fA-F]{2}(?:([:-])[0-9a-fA-F]{2})(?:\1[0-9a-fA-F]{2}){4}(?![\w:-])")

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
# « :: » = adresse non spécifiée (comme 0.0.0.0) ; apparaît aussi dans les expressions régulières « (?::…) »
ALLOWED_IPS = {"0.0.0.0", "127.0.0.1", "::1", "::"}
FAKE_MAC = re.compile(r"^(?:[0-9a-f]{2}[:-]00[:-]00[:-]00[:-]00[:-][0-9a-f]{2}|aa[:-]bb[:-]cc[:-]dd[:-]ee[:-]ff)$", re.I)

SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2")


def _ip_allowed(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return True  # pas une vraie adresse (ex. numéro de version 999.1.2.3)
    return text in ALLOWED_IPS or any(ip in n for n in DOC_NETS)


def scan_line(line: str):
    """Liste des (type, extrait masqué) trouvés dans une ligne."""
    found = []
    if "check-secrets: allow" in line:  # jamais utilisé pour un vrai secret
        return found
    for label, rx in RULES:
        for m in rx.finditer(line):
            found.append((label, m.group(0)))
    for m in IPV4.finditer(line):
        if not _ip_allowed(m.group(0)):
            found.append(("adresse IP", m.group(0)))
    for m in IPV6.finditer(line):
        cand = m.group(0)
        try:  # seulement une vraie adresse IPv6 (pas une heure « 12:30:00 »)
            ipaddress.IPv6Address(cand)
        except ValueError:
            continue
        if not MAC.fullmatch(cand) and not _ip_allowed(cand):
            found.append(("adresse IPv6", cand))
    for m in MAC.finditer(line):
        if not FAKE_MAC.match(m.group(0)):
            found.append(("adresse MAC", m.group(0)))
    return found


def mask(value: str) -> str:
    return value[:4] + "…" if len(value) > 6 else "…"


def tracked_files():
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p for p in out.decode().split("\0") if p and not p.lower().endswith(SKIP_SUFFIXES)]


def scan_files(paths):
    hits = []
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for n, line in enumerate(f, 1):
                    for label, value in scan_line(line):
                        hits.append(f"{path}:{n} : {label} ({mask(value)})")
        except (IsADirectoryError, FileNotFoundError):
            continue
    return hits


def scan_history():
    """Toutes les lignes ajoutées dans tout l'historique (un secret retiré
    ensuite reste visible dans un dépôt public)."""
    out = subprocess.run(["git", "log", "--all", "-p", "--no-color", "--format=commit %H"],
                         capture_output=True, check=True).stdout.decode("utf-8", "replace")
    hits, commit, path = [], "?", "?"
    for line in out.splitlines():
        if line.startswith("commit "):
            commit = line[7:15]
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("+") and not line.startswith("+++"):
            if path.lower().endswith(SKIP_SUFFIXES):
                continue
            for label, value in scan_line(line[1:]):
                hits.append(f"{commit} {path} : {label} ({mask(value)})")
    return sorted(set(hits))


def main(argv):
    hits = scan_files(tracked_files())
    if "--history" in argv:
        hits += scan_history()
    if hits:
        print("Contrôle de sécurité : éléments interdits dans ce dépôt public :")
        for h in hits:
            print("  -", h)
        print("Retirer la valeur (configuration de l'add-on, Dashlane) ; si elle a déjà été poussée, la considérer comme exposée et la changer.")
        return 1
    print("Contrôle de sécurité : rien de sensible trouvé.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
