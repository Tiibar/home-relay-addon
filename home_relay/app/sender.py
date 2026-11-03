"""Envoi HTTPS vers Supabase, avec file d'attente.

Si l'envoi échoue (Internet coupé, Supabase indisponible), l'instantané reste
dans la file (mémoire + /data/queue.json, qui survit à un redémarrage) et
part au cycle suivant, dans l'ordre. Les volumes ne sont pas perdus : les
compteurs d'octets sont cumulés, Supabase calcule la différence avec le
dernier compteur reçu, même plusieurs heures plus tard.
"""

import json
import os
import ssl
import urllib.error
import urllib.request

MAX_QUEUE = 288  # 24 h à raison d'un envoi toutes les 5 min
TIMEOUT = 30


class Queue:
    def __init__(self, path: str | None = None, max_items: int = MAX_QUEUE):
        self.path = path
        self.max_items = max_items
        self.items: list[dict] = []
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    self.items = data[-max_items:]
            except (OSError, ValueError):
                self.items = []

    def push(self, payload: dict):
        self.items.append(payload)
        dropped = max(0, len(self.items) - self.max_items)
        if dropped:
            self.items = self.items[dropped:]
        self.save()
        return dropped

    def save(self):
        if not self.path:
            return
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.items, f)
        os.replace(tmp, self.path)

    def flush(self, send) -> tuple[int, str | None]:
        """Envoie dans l'ordre. `send(payload)` renvoie "ok", "drop" ou "retry".
        S'arrête au premier "retry" (on réessaiera au cycle suivant)."""
        sent, error = 0, None
        while self.items:
            result, detail = send(self.items[0])
            if result == "retry":
                error = detail
                break
            self.items.pop(0)
            if result == "ok":
                sent += 1
            else:
                error = detail
        self.save()
        return sent, error


def make_sender(url: str, secret: str):
    ctx = ssl.create_default_context()  # Supabase : certificat toujours vérifié

    def send(payload: dict):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json", "x-relay-secret": secret},
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
                r.read()
            return "ok", None
        except urllib.error.HTTPError as e:
            detail = e.read()[:300].decode("utf-8", "replace")
            # 400 / 413 : cet envoi ne passera jamais, on l'abandonne (sinon il bloque la file)
            if e.code in (400, 413):
                return "drop", f"envoi refusé (HTTP {e.code}) : {detail}"
            if e.code == 401:
                return "retry", "secret refusé (HTTP 401) : vérifier le secret partagé ici et dans Supabase"
            return "retry", f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return "retry", f"Supabase injoignable ({getattr(e, 'reason', e)})"

    return send
