# Home Relay — dépôt d'add-ons Home Assistant

Add-on **en lecture seule** qui relaie l'état de la passerelle UniFi locale, de
Home Assistant et (facultatif) du NAS Synology vers le tableau de bord de la maison (fonction Supabase).
Il ne commande rien.

## Installation

1. Home Assistant → **Settings** → **Add-ons** → **Add-on store**.
2. Menu **⋮** (en haut à droite) → **Repositories** → coller
   `https://github.com/Tiibar/home-relay-addon` → **Add** → **Close**.
3. Ouvrir **Home Relay** → **Install**, puis l'onglet **Configuration**.

Documentation complète (options, vie privée, données lues, limites) :
[`home_relay/DOCS.md`](home_relay/DOCS.md).

## Règles de ce dépôt public

- Aucun secret, aucune adresse IP ou MAC, aucune URL de projet en dur : tout
  passe par la configuration de l'add-on (contrôlé par la CI).
- Uniquement des lectures (GET), sauf deux requêtes en liste blanche stricte :
  la connexion, et la recherche des menaces dans le journal (compte View Only).
- NAS Synology : SNMPv3 (SHA + AES) en lecture seule, sans compte DSM ;
  `snmpget` / `snmpwalk` seulement (jamais `snmpset`), liste blanche d'OID.
- Adresses MAC hachées (HMAC-SHA256) avant envoi ; aucune adresse IP envoyée ;
  jamais de sites visités ni de DNS.

## Sécurité du dépôt

- **Contrôle automatique** (`.github/workflows/security.yml`,
  `scripts/check_secrets.py`) à chaque push et pull request : fichiers **et**
  historique complet. Il échoue s'il trouve une clé (Anthropic, GitHub,
  Supabase, AWS, Google, Slack, JWT, clé privée), un mot de passe ou secret en
  clair, des identifiants dans une URL, une adresse IP (v4/v6) ou une adresse
  MAC. Seules exceptions : adresses de documentation (RFC 5737, `2001:db8::/32`), adresses non spécifiées (`0.0.0.0`, `::`)
  et fausses MAC des tests (`xx:00:00:00:00:yy`, `aa:bb:cc:dd:ee:ff`). Dans l'historique seulement, une
  exception acceptée le 06/11/2026 (`HISTORY_EXCEPTIONS`) : l'adresse locale privée de la sonnette dans le commit
  `d951e39` (corrigée par `2774071`) — limitée à ce commit, ce fichier et cette valeur (empreinte SHA-256), sans
  réécriture de l'historique.
- **Secret scanning + push protection** de GitHub : refusent le push lui-même
  quand il contient une clé d'un fournisseur connu.
- Un workflow GitHub s'exécute **après** le push : pour qu'il bloque, la
  branche `main` doit être protégée (règle « Require status checks to pass »,
  check « Aucun secret ni adresse ») ; les changements passent alors par une
  pull request.

## Tests

```bash
python3 -m unittest discover -s tests -v
```
