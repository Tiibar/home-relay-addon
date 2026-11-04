# Home Relay

Relais **en lecture seule** : toutes les 5 minutes, il lit la passerelle UniFi
locale et Home Assistant (et toutes les 30 minutes le NAS Synology, en SNMPv3), puis envoie un résumé au tableau de bord de la maison
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
| `nas_host` | Facultatif. Adresse locale du NAS Synology (adresse ou nom, sans `https://` ni port). Lu en **SNMPv3** (UDP 161). Vide = NAS non lu. |
| `nas_snmp_user` | Utilisateur **SNMPv3** créé sur le NAS (aucun compte DSM). |
| `nas_snmp_auth_password` / `nas_snmp_priv_password` | Mots de passe SNMPv3 : authentification (SHA) et chiffrement (AES), 8 caractères au moins, sans guillemet. |
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

### NAS Synology (module ≥ 1.2.0) : SNMPv3, lecture seule

Toutes les 30 minutes, par **SNMPv3** (UDP 161), **sans aucun compte DSM** :
niveau « authPriv », authentification **SHA**, chiffrement **AES**. Sur le NAS :
Panneau de configuration → Terminal & SNMP → SNMP : SNMPv1/v2c désactivés,
SNMPv3 activé avec un utilisateur dédié.

Garde-fous (`nas.py`, testés) :

- seules commandes possibles : `snmpget` (GET) et `snmpwalk` (GETNEXT, pour
  parcourir une colonne de table) ; `snmpset` et toute autre commande sont
  refusés dans le code avant tout lancement, et **retirés de l'image** ;
- seuls les OID de la liste blanche (`ALLOWED_OIDS`, `ALLOWED_TABLES`) sont
  demandés ; toute autre demande est refusée avant l'envoi, et toute réponse
  hors liste blanche est ignorée ;
- les deux mots de passe ne passent jamais sur la ligne de commande : ils sont
  dans un fichier temporaire (droits 600) lu par net-snmp.

| Donnée | MIB / OID | Gardé |
|---|---|---|
| Système | SYNOLOGY-SYSTEM-MIB (`1.3.6.1.4.1.6574.1`) : `systemStatus`, `temperature`, `modelName`, `version`, `upgradeAvailable` | état global, température, modèle, version de DSM, mise à jour disponible (oui / non) |
| Disques | SYNOLOGY-DISK-MIB (`…6574.2`) : `diskID`, `diskModel`, `diskStatus`, `diskTemperature`, `diskHealthStatus` | emplacement, modèle, état, température, état de santé (DSM 7.1 et plus) |
| RAID | SYNOLOGY-RAID-MIB (`…6574.3`) : `raidName`, `raidStatus`, `raidFreeSize`, `raidTotalSize` | nom, état (l'espace du groupe de stockage n'est **pas** celui du volume : il n'est pas affiché comme tel) |
| Volumes | UCD-SNMP-MIB `dskTable` (`1.3.6.1.4.1.2021.9.1`) : `dskPath`, `dskTotalLow/High`, `dskUsedLow/High` (64 bits, Ko) ; à défaut HOST-RESOURCES-MIB `hrStorage` | utilisé / total du système de fichiers `/volumeN`, comme DSM |
| SMART | SYNOLOGY-SMART-MIB (`…6574.5`) : nom du disque, numéro et valeur brute des attributs | heures de fonctionnement (attribut 9) seulement |
| Charge | HOST-RESOURCES-MIB : `hrProcessorLoad`, `hrSystemUptime` ; UCD-SNMP-MIB : mémoire | processeur (%), durée de fonctionnement, mémoire (%) |

**Jamais lu ni envoyé** : numéro de série (`serialNumber` n'est pas dans la
liste blanche), adresses, comptes, dossiers.

**Non disponible via SNMP** (envoyé tel quel, jamais deviné) : historique et
résultat des tests SMART, date du dernier nettoyage des données, mises à jour
des paquets. Une table absente de ce NAS (ex. état de santé des disques sur un
DSM ancien) est aussi signalée « non disponible ».

**Pourquoi pas l'API Web de DSM** (module 1.1.0, abandonné) : elle exige un
compte DSM ; un compte non administrateur est refusé par l'API, et pouvait
pourtant se connecter à DSM par QuickConnect. SNMPv3 ne demande aucun compte
DSM et ne permet aucune écriture avec ce module.

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
