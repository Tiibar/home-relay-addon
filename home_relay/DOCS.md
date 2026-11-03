# Home Relay

Relais **en lecture seule** : toutes les 5 minutes, il lit la passerelle UniFi
locale et Home Assistant, puis envoie un résumé au tableau de bord de la maison
(fonction Supabase `ingest-home`). **Il ne commande rien** : aucun
redémarrage, aucun changement de configuration, aucun appel de service Home
Assistant.

## Configuration

| Option | Rôle |
|---|---|
| `unifi_url` | Adresse locale de la passerelle UniFi, en `https://` (sans `/` final). |
| `unifi_username` / `unifi_password` | Compte UniFi **local**, rôle **View Only** pour UniFi Network. |
| `unifi_site` | Site UniFi (`default` en général). |
| `unifi_verify_ssl` | Désactivé par défaut : la passerelle a un certificat auto-signé (réseau local uniquement). |
| `supabase_function_url` | `https://<projet>.supabase.co/functions/v1/ingest-home` |
| `shared_secret` | Secret partagé (40 caractères), identique au secret `RELAY_SHARED_SECRET` de Supabase. |
| `interval_minutes` | Intervalle entre deux envois (5 par défaut). |
| `climate_entities` | Facultatif. Entités lues pour la température et l'humidité. Vide = toutes les `climate.*`. |
| `alarm_entities` | Facultatif. Entités dont l'**état** est lu (lecture seule). Vide = les `alarm_control_panel.*` activées. |

Aucune valeur n'est écrite dans ce dépôt public : tout passe par cette
configuration, stockée par Home Assistant.

## Vie privée

- **Adresses MAC** : jamais envoyées en clair. Identifiant stable =
  HMAC-SHA256(MAC, secret partagé), tronqué à 32 caractères. Changer le secret
  change tous les identifiants (l'historique repart de zéro).
  Comme Supabase connaît aussi le secret, il s'agit d'un pseudonyme et non d'un
  anonymat complet.
- **Adresses IP** : jamais envoyées (ni celles des appareils, ni l'adresse
  Internet de la maison, ni les serveurs DNS). Tout texte qui ressemble à une
  adresse IP ou MAC est effacé avant l'envoi, et une seconde fois à l'arrivée.
- **Sites visités / DNS** : jamais lus (le module n'interroge pas l'analyse de
  trafic par application ni les journaux DNS).

## Ce que le module lit

API UniFi utilisée : l'API **classique** de UniFi Network (sous
`/proxy/network/…`), avec le compte local en lecture seule. L'API officielle
« Integrations » (clé API) ne fournit pas les compteurs d'octets par client, la
satisfaction Wi-Fi, l'occupation des canaux, les menaces IPS ni la santé WAN.

Seule requête qui n'est pas un GET : la connexion (`POST /api/auth/login`), qui
ouvre la session ; elle ne modifie rien.

| Donnée | Requête (GET) | Champs gardés |
|---|---|---|
| Passerelle, switch, bornes | `stat/device` | nom, modèle, type, état, firmware, mise à jour dispo, uptime, nombre de clients, satisfaction ; par radio : bande, canal, occupation du canal (`cu_total`), satisfaction, clients ; lien montant : câble/sans fil (mesh), équipement parent, signal, débit |
| Clients connectés | `stat/sta` | nom, réseau (VLAN), borne ou port du switch, signal, compteurs tx/rx en octets, durée de connexion |
| Clients vus sur 24 h | `v2/api/site/<site>/clients/history?withinHours=24`, sinon `stat/alluser` filtré sur 24 h | nom, réseau, dernière borne, dernière apparition |
| Noms des réseaux | `rest/networkconf` | nom du réseau (pour les clients qui n'ont que l'identifiant du réseau) |
| Santé WAN, speedtest | `stat/health` (sinon `speedtest-status` de la passerelle) | état, fournisseur, latence, uptime, coupures ; date, débits et ping du dernier speedtest |
| Menaces IPS | essayées dans l'ordre, en GET : `v2/api/site/<site>/system-log/threat`, `stat/ips/event`, `stat/alarm`, `stat/event` (alertes IPS seulement) ; la première qui répond est retenue | titre (signature, adresses masquées), gravité, catégorie, action (bloquée/détectée), date |

Home Assistant (API du Supervisor, `homeassistant_api: true`, sans jeton
longue durée) : `GET /api/config` (version) et `GET /api/states` :

- piles : capteurs `device_class: battery` en % ;
- entités indisponibles (état `unavailable`) ;
- chauffage : température, humidité et consigne des entités choisies ;
- alarme : **état** des entités choisies (lecture seule) ;
- mises à jour en attente (entités `update.*` à `on`).

### Limites connues

- Ce module a été écrit d'après l'API classique documentée de UniFi Network,
  **sans accès à la passerelle de la maison** : chaque source est lue
  séparément et son résultat (`ok` ou le message d'erreur) est envoyé avec les
  données. Le journal du module et la section « Relais maison » de l'écran
  Réseau montrent ce qui a réellement été obtenu.
- **Menaces IPS** : sur UniFi Network 10, `stat/alarm` n'existe plus (HTTP 404)
  et l'interface lit le journal des menaces par une requête **POST**
  (`system-log`), que ce module s'interdit. Si aucune des requêtes GET ne
  répond, la source passe à « **désactivée** » (pas une erreur), avec la liste
  des essais ; un nouvel essai a lieu 24 h plus tard (ou au redémarrage du
  module). Les « traffic-flows » ne sont **pas** utilisés : ce sont les
  connexions, donc les sites visités.
- **Jeton Home Assistant** : fourni par le Supervisor (`homeassistant_api:
  true`). Sur les images de base récentes (s6-overlay v3), il est lu dans
  `/run/s6/container_environment/` quand il n'est pas dans l'environnement.
- **Sens des compteurs** : les compteurs `tx_bytes` / `rx_bytes` sont
  transmis tels que UniFi les donne ; l'app affiche leur **somme** (volume).
- Les compteurs d'un client sans fil repartent de zéro à chaque reconnexion ;
  Supabase le détecte (compteur qui baisse, ou connexion plus récente que la
  mesure précédente).

## File d'attente

Si l'envoi échoue, l'instantané reste dans `/data/queue.json` (24 h au plus)
et part au cycle suivant, dans l'ordre. Les compteurs étant cumulés, le volume
d'une période sans envoi est rattrapé au premier envoi réussi.

## Journal

Onglet **Log** du module : une ligne par cycle (« Lu : N clients… », « Envoyé à
Supabase »), et un avertissement par source en erreur.
