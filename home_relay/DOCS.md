# Home Relay

Relais **en lecture seule** : toutes les 5 minutes, il lit la passerelle UniFi
locale et Home Assistant (et toutes les 30 minutes le NAS Synology), puis envoie un résumé au tableau de bord de la maison
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
| `nas_url` | Facultatif. Adresse locale du NAS Synology, `https://<adresse du NAS>:5001` (sans `/` final). Vide = NAS non lu. |
| `nas_username` / `nas_password` | Compte NAS **dédié, non administrateur** (ex. `home-relay`), voir « NAS Synology ». |
| `nas_verify_ssl` | Désactivé par défaut : le NAS a un certificat auto-signé (réseau local uniquement). |
| `alarm_entities` | Facultatif. Entités dont l'**état** est lu (lecture seule). Vide = les `alarm_control_panel.*` activées, sinon les entités Somfy restantes (voir plus bas). |

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

### Exception : deux requêtes qui ne sont pas des GET

Le client HTTP du module refuse toute requête non-GET qui n'est pas dans une
**liste blanche** (`ALLOWED_NON_GET` dans `unifi.py`, testée) :

1. `POST /api/auth/login` : ouvre la session ;
2. `POST /proxy/network/v2/api/site/<site>/system-log/all` : **recherche**
   dans le journal système, avec uniquement les champs `timestampFrom`,
   `timestampTo`, `pageSize`, `pageNumber`, `categories`, et seulement les
   catégories `SECURITY` (menaces IPS), `CLIENT_DEVICES` (connexions,
   déconnexions, passages d'une borne à l'autre) et `INTERNET_AND_WAN`
   (alertes de latence, de perte de paquets, de lien Internet) ; toute autre
   catégorie est refusée avant l'envoi (`SYSTEM_LOG_CATEGORIES`). C'est la
   requête qu'utilise l'interface de UniFi Network 10 pour afficher son
   journal : elle lit, elle ne modifie rien.

**Garde-fou principal** : le compte local « home-relay » est en **View Only**
(lecture seule) pour UniFi Network. Même une requête erronée ne pourrait rien
modifier sur la passerelle.

| Donnée | Requête (GET) | Champs gardés |
|---|---|---|
| Passerelle, switch, bornes | `stat/device` | nom, modèle, type, état, firmware, mise à jour dispo, uptime, nombre de clients, satisfaction ; par radio : bande, canal, occupation du canal (`cu_total`), satisfaction, clients ; lien montant : câble/sans fil (mesh), équipement parent, signal, débit |
| Clients connectés | `stat/sta` | nom, réseau (VLAN), borne ou port du switch, signal, compteurs tx/rx en octets, durée de connexion |
| Clients vus sur 24 h | `v2/api/site/<site>/clients/history?withinHours=24`, sinon `stat/alluser` filtré sur 24 h | nom, réseau, dernière borne, dernière apparition |
| Noms des réseaux | `rest/networkconf` | nom du réseau (pour les clients qui n'ont que l'identifiant du réseau) |
| Santé WAN, speedtest | `stat/health` (sinon `speedtest-status` de la passerelle) | état, fournisseur, latence, uptime, coupures ; date, débits et ping du dernier speedtest |
| Menaces IPS | **POST** `v2/api/site/<site>/system-log/all` (recherche, catégorie `SECURITY` ; voir « Exception ») ; sur les versions anciennes, `stat/ips/event` puis `stat/alarm` en GET | titre, gravité, catégorie, date, direction (entrant/sortant si indiquée), bloquée ou non, origine (Internet, ou appareil de la maison avec son nom s'il est connu) et cible (nom de l'appareil visé) ; adresses IP/MAC remplacées par « [adresse] ». Au démarrage puis une fois par jour : relecture des 30 derniers jours (les doublons sont écartés par Supabase) |
| Événements Wi-Fi des appareils | **POST** `system-log/all`, catégorie `CLIENT_DEVICES` (7 derniers jours au démarrage, puis depuis la dernière lecture ; 1500 par envoi au plus) | type (connexion, déconnexion, passage d'une borne à l'autre), date, appareil (identifiant haché + nom), bornes de départ et d'arrivée, durée de connexion. **Jamais** le nom du Wi-Fi ni d'adresse |
| Alertes Internet | **POST** `system-log/all`, catégorie `INTERNET_AND_WAN` (30 derniers jours au démarrage) | type (latence élevée, perte de paquets, lien Internet), date, titre sans adresse |

Home Assistant (API du Supervisor, `homeassistant_api: true`, sans jeton
longue durée) : `GET /api/config` (version), `GET /api/states`, et par
WebSocket les trois commandes de **lecture** des registres
(`config/device_registry/list`, `config/entity_registry/list`,
`config/area_registry/list` ; aucune autre commande n'est possible,
voir `hass_ws.READ_ONLY`) :

- piles **par appareil** : capteur `device_class: battery` en %, attribut
  `battery_level` (capteurs Hue), `binary_sensor` `device_class: battery`
  (pile faible oui/non, par ex. HomeKit) ; liste complète triée par niveau ;
- appareils indisponibles **par appareil** (nom + pièce) : « hors ligne » si
  toutes ses entités principales sont indisponibles, « en partie » sinon ;
  les lumières Hue indisponibles sont classées à part (éteintes à
  l'interrupteur). Ignorés : entités non physiques (`update`, `button`,
  `select`, `scene`, `number`…), groupes, entités de diagnostic ou de
  configuration, services (météo…). Sans registres (erreur affichée), repli
  sur la liste des entités indisponibles ;
- chauffage : température, humidité et consigne des entités choisies ;
- alarme : **état** seulement (lecture seule, rien n'est commandé) : entités
  choisies (`alarm_entities`), sinon les `alarm_control_panel.*` activées,
  sinon — si le panneau a été désactivé volontairement dans Home Assistant —
  les entités qui restent de l'appareil Somfy (SomfyProtect2MQTT : niveau de
  sécurité, état, détecteurs). Si rien n'est trouvé, la source `alarme`
  indique « désactivée : état non suivi volontairement (lecture seule) » :
  c'est un choix, pas une panne ;
- mises à jour en attente (entités `update.*` à `on`).
- exclus : les téléphones et tablettes de l'application Home Assistant
  (Companion App, intégration `mobile_app`), qui ne sont pas des appareils de
  la maison.

### NAS Synology (module ≥ 1.1.0)

Toutes les 30 minutes, par l'**API Web officielle de DSM** (`/webapi/…`),
avec un compte NAS dédié **non administrateur**. Le client du module n'autorise
que les couples (API, méthode) de **lecture** de la liste blanche
`nas.ALLOWED_CALLS` (testée) ; tout autre appel, tout mot d'écriture dans le
nom de la méthode (`set`, `create`, `delete`, `start`, `install`…) et tout
paramètre inconnu sont refusés **avant l'envoi**. Seule requête POST : la
connexion (le mot de passe est dans le corps, jamais dans l'adresse). La
session est gardée (pas une connexion toutes les 30 min) ; une connexion
refusée n'est retentée que 30 min plus tard (pas de blocage automatique).

| Donnée | API / méthode | Champs gardés |
|---|---|---|
| Chemins des API | `SYNO.API.Info` / `query` (sans session) | chemin, versions |
| Session | `SYNO.API.Auth` / `login` (POST) | identifiant de session (jamais envoyé) |
| Système | `SYNO.Core.System` / `info` | modèle, version de DSM, température, alerte de température, état, durée de fonctionnement |
| Charge | `SYNO.Core.System.Utilization` / `get` | processeur (%), mémoire (%) |
| Stockage | `SYNO.Storage.CGI.Storage` / `load_info` | volumes (état, utilisé, total), groupes de stockage (état, type de RAID, nettoyage des données), disques (emplacement, modèle, fabricant, taille, température, état) |
| SMART | `SYNO.Storage.CGI.Smart` / `get_health_info`, `get_smart_info` | dernier test (type, résultat, date), santé IronWolf, heures de fonctionnement (attribut 9) |
| Mise à jour de DSM | `SYNO.Core.Upgrade.Server` / `check` | disponible ou non, version (demande au NAS s'il existe une version plus récente : rien n'est téléchargé ni installé) |
| Paquets | `SYNO.Core.Package` / `list`, `SYNO.Core.Package.Server` / `list` | nom et version des paquets qui ont une mise à jour, nombre de paquets installés |

**Jamais envoyé** : numéros de série, adresses IP ou MAC, noms d'utilisateur,
noms des dossiers partagés, contenu des fichiers.

**Information non disponible** : si DSM refuse une lecture au compte du module
(souvent `code DSM 105` : permission refusée, ces API étant réservées aux
administrateurs sur DSM 7.1), elle est envoyée « non disponible » avec la
raison, et le journal du module l'écrit à chaque lecture
(`NAS : storage non disponible : …`). À la première lecture, le journal liste
aussi les **noms** des champs reçus de DSM (jamais leurs valeurs), pour ajuster
le module si un champ porte un autre nom sur ce NAS.

Format des réponses établi d'après la documentation de l'API Web de Synology
et des projets communautaires, **sans accès au NAS de la maison** : les champs
manquants sont signalés « non disponible » plutôt que devinés.

### Limites connues

- Ce module a été écrit d'après l'API classique documentée de UniFi Network,
  **sans accès à la passerelle de la maison** : chaque source est lue
  séparément et son résultat (`ok` ou le message d'erreur) est envoyé avec les
  données. Le journal du module et la section « Relais maison » de l'écran
  Réseau montrent ce qui a réellement été obtenu.
- **Menaces IPS** : `stat/alarm` et `stat/ips/event` n'existent plus sur UniFi
  Network 10 ; le journal système (exception ci-dessus) les remplace. Format
  établi d'après des projets communautaires, pas d'après une documentation
  officielle d'Ubiquiti. Si la recherche ne répond pas, la source passe à
  « désactivée : menaces non disponibles sur cette passerelle » (le détail est
  dans le journal du module) et un nouvel essai a lieu 24 h plus tard. Les
  « traffic-flows » ne sont **pas** utilisés : ce sont les connexions, donc les
  sites visités.
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
