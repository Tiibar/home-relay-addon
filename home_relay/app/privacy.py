"""Vie privée : les adresses MAC ne quittent jamais la maison en clair.

Identifiant stable d'un appareil = HMAC-SHA256(MAC normalisée, secret partagé),
tronqué à 32 caractères hexadécimaux (128 bits).
"""

import hashlib
import hmac
import re

_MAC_SEP = re.compile(r"[^0-9a-f]")


def normalize_mac(mac: str) -> str:
    """'AA-BB-CC-DD-EE-FF' / 'aabb.ccdd.eeff' -> 'aa:bb:cc:dd:ee:ff'."""
    hexa = _MAC_SEP.sub("", (mac or "").lower())
    if len(hexa) != 12:
        raise ValueError("adresse MAC invalide")
    return ":".join(hexa[i:i + 2] for i in range(0, 12, 2))


def hashed_id(value: str, secret: str, *, is_mac: bool = True) -> str:
    """Identifiant opaque et stable (32 caractères hexadécimaux)."""
    if not secret:
        raise ValueError("secret manquant")
    msg = normalize_mac(value) if is_mac else str(value)
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC = re.compile(r"\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b", re.I)
_IPV6 = re.compile(r"(?<![\w:.])[0-9a-f:]*:[0-9a-f:]*:[0-9a-f:.]*(?![\w:])", re.I)


def _has_ipv6(s: str) -> bool:
    import ipaddress
    for m in _IPV6.finditer(s):
        try:
            ipaddress.IPv6Address(m.group(0))
            return True
        except ValueError:
            continue
    return False


def _sub_ipv6(s: str) -> str:
    import ipaddress

    def one(m):
        try:
            ipaddress.IPv6Address(m.group(0))
            return "[adresse]"
        except ValueError:
            return m.group(0)
    return _IPV6.sub(one, s)


def clean_text(value, max_len: int = 120):
    """Texte court ; None s'il est vide ou contient une adresse IP ou MAC."""
    if value is None:
        return None
    s = str(value).strip()[:max_len]
    if not s or _IPV4.search(s) or _MAC.search(s) or _has_ipv6(s):
        return None
    return s


def redact(value, max_len: int = 120):
    """Texte court où toute adresse IP ou MAC est remplacée par « [adresse] »."""
    if value is None:
        return None
    s = _sub_ipv6(_MAC.sub("[adresse]", _IPV4.sub("[adresse]", str(value)))).strip()[:max_len]
    return s or None
