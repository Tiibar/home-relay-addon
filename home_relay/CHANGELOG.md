# Changelog

## 1.2.3

- NAS : s'il ne répond pas (il redémarre, par exemple après une coupure de
  courant, plus lentement que Home Assistant), nouvel essai au cycle suivant
  (5 min) au lieu de 30 min. Mot de passe ou utilisateur SNMP refusé : 30 min.
  Au démarrage du module, la lecture du NAS est immédiate.

## 1.2.2

- Chaque envoi indique l'heure de démarrage du module (`started_at`). Après
  une coupure de courant, l'application voit que le module a redémarré (avec
  les équipements UniFi), ce qui distingue une coupure de courant d'une panne
  d'Internet.

## 1.2.1

- NAS : l'espace du volume vient du **système de fichiers** `/volume1`
  (UCD-SNMP `dskTable`, 64 bits ; à défaut HOST-RESOURCES `hrStorage`, relu
  en non signé), comme DSM. L'espace libre / total du groupe de stockage
  (RAID-MIB) n'est plus utilisé pour le volume.
- Journal : une ligne par volume et par groupe de stockage avec les chiffres
  lus et leur source (en To, base 1024 comme DSM).

## 1.2.0

- **NAS Synology : SNMPv3** remplace l'API Web de DSM (plus aucun compte DSM).
  Lecture seule : `snmpget` et `snmpwalk` uniquement, `snmpset` refusé dans le
  code et retiré de l'image ; liste blanche d'OID (SYNOLOGY-SYSTEM, -DISK,
  -RAID, -SMART, HOST-RESOURCES, UCD-SNMP) ; jamais le numéro de série.
- Données : état global, température, version de DSM, mise à jour disponible,
  processeur, mémoire, volumes, RAID (état, espace), disques (modèle, état,
  température, état de santé, heures de fonctionnement).
- « Non disponible via SNMP » : tests SMART, nettoyage des données, mises à
  jour des paquets.
- Options : `nas_host`, `nas_snmp_user`, `nas_snmp_auth_password`,
  `nas_snmp_priv_password` (remplacent `nas_url`, `nas_username`,
  `nas_password`, `nas_verify_ssl`).

## 1.1.0

- **NAS Synology** (facultatif) : toutes les 30 min, lecture seule par l'API
  Web officielle de DSM, avec un compte NAS dédié **non administrateur** :
  état, version de DSM et mise à jour disponible, température, processeur et
  mémoire, volumes (utilisé / total), RAID, disques (modèle, taille,
  température, état, heures de fonctionnement, dernier test SMART, santé
  IronWolf), dernier nettoyage des données, paquets à mettre à jour.
- Liste blanche stricte de couples (API, méthode) de lecture (`nas.ALLOWED_CALLS`,
  testée) ; tout autre appel est refusé avant l'envoi. Seule requête POST : la
  connexion (mot de passe dans le corps, jamais dans l'adresse).
- Une information que le compte ne peut pas lire est envoyée « non
  disponible » avec le code d'erreur de DSM (105 = permission refusée) ; le
  journal du module la liste à chaque lecture.
- Nouvelles options : `nas_url`, `nas_username`, `nas_password`,
  `nas_verify_ssl` (désactivée par défaut). Adresse vide = NAS non lu.

## 1.0.11

- Parc : numéro de série des appareils hors ligne (registre de Home
  Assistant, ex. vannes Tado via HomeKit), pour reconnaître le bon appareil
  dans l'application du fabricant.

## 1.0.10

- Parc : les téléphones et tablettes de l'application Home Assistant
  (Companion App, intégration `mobile_app`) ne sont plus comptés parmi les
  appareils de la maison (piles, hors ligne).

## 1.0.9

- Menaces : **source** et **cible** distinguées (nom de l'appareil de la
  maison à l'origine, nom de l'appareil visé). Le paramètre « CLIENT » de
  UniFi est en général la cible : il n'est plus pris pour la source. La
  relecture des 30 jours au démarrage complète les menaces déjà envoyées.

## 1.0.8

- Menaces IPS : relecture des **30 derniers jours** au démarrage puis une
  fois par jour ; origine de chaque menace (Internet, ou appareil de la
  maison avec son nom s'il est connu, sans adresse).
- Même recherche dans le journal (lecture seule), étendue à deux catégories :
  `CLIENT_DEVICES` (connexions, déconnexions, passages d'une borne à l'autre,
  durées de connexion) et `INTERNET_AND_WAN` (alertes de latence élevée, de
  perte de paquets). Toute autre catégorie est refusée avant l'envoi. Jamais
  de nom de Wi-Fi, d'adresse ni de site visité.
- Alarme : si le panneau a été désactivé volontairement dans Home Assistant,
  lecture de l'état sur les entités Somfy restantes (SomfyProtect2MQTT) ;
  sinon « état non suivi volontairement (lecture seule) ».
- Réseau d'un appareil : quand UniFi ne remplit pas le champ `network`
  (Apple TV…), il est retrouvé par le dernier réseau de connexion, l'identifiant
  du réseau, le numéro de VLAN ou le nom du Wi-Fi.

## 1.0.7

- Bornes Wi-Fi : largeur du canal de chaque radio (20/40/80/160 MHz), pour
  repérer les chevauchements de canaux entre bornes.

## 1.0.6

- Chauffage : pour chaque thermostat (Tado via HomeKit), consigne,
  température et humidité mesurées (au besoin lues sur les capteurs du même
  appareil), mode (`hvac_mode`) et état de chauffe (`hvac_action`), pièce.
- Température extérieure : entité météo (option `weather_entity`, sinon la
  première `weather.*`).

## 1.0.5

- Journal à l'heure locale (fuseau de Home Assistant, Europe/Brussels par
  défaut) au lieu de l'UTC.
- Plan du réseau : numéro du port du switch pour les équipements reliés par
  câble ; fabricant de la carte réseau des clients (pour reconnaître les
  objets connectés).

## 1.0.4

- Menaces IPS sur UniFi Network 9/10 : **une** requête de recherche POST,
  `v2/api/site/<site>/system-log/all` (catégorie SECURITY), celle qu'utilise
  l'interface UniFi. Elle ne modifie rien ; le compte « home-relay » est en
  View Only.
- Liste blanche stricte dans le client HTTP : seules deux requêtes non-GET
  sont possibles (connexion et cette recherche, avec les seuls champs de
  recherche) ; toute autre est refusée avant l'envoi.
- Données des menaces : titre, gravité, catégorie, date, direction
  (entrant/sortant, si la passerelle l'indique), bloquée ou non ; adresses
  IP/MAC (v4 et v6) remplacées par « [adresse] ».
- Lecture depuis la dernière fois (24 h au premier passage), par pages de 100.
- Si rien ne répond : source « désactivée » avec un message court ; le détail
  reste dans le journal du module.

## 1.0.3

- Parc : appareils indisponibles regroupés **par appareil** (nom de l'appareil
  et pièce), grâce aux registres de Home Assistant lus par WebSocket
  (commandes de lecture uniquement). Une vanne Tado = 1 ligne.
- Ignorés : entités non physiques (update, button, select, scene, number…),
  groupes, entités de diagnostic/configuration, services (météo…).
- Lumières Hue indisponibles classées à part (« éteintes à l'interrupteur »).
- Piles par appareil : capteur `battery` en %, attribut `battery_level`
  (capteurs Hue), et `binary_sensor` `battery` (pile faible oui/non).
  Liste complète, triée par niveau.

## 1.0.2

- Home Assistant : le jeton du Supervisor est lu dans l'environnement, sinon
  dans `/run/s6/container_environment/` (images s6-overlay v3, où `/init` ne
  transmet pas l'environnement au programme). Corrige « SUPERVISOR_TOKEN
  absent ».
- Menaces IPS : plusieurs requêtes GET essayées dans l'ordre
  (`v2 system-log/threat`, `stat/ips/event`, `stat/alarm`, `stat/event`) ; la
  première qui répond est retenue. Si aucune ne répond, la source est
  **désactivée** proprement (message « désactivée », nouvel essai 24 h plus
  tard) au lieu d'être en erreur. Les adresses dans les titres sont masquées.

## 1.0.1

- Correction de l'installation : image de base Home Assistant avec Python
  (`build.yaml`, `{arch}-base-python:3.13-alpine3.23`) et valeur par défaut
  de `BUILD_FROM` dans le Dockerfile (erreur « base name ($BUILD_FROM) should
  not be blank »).

## 1.0.0

- Première version : lecture seule de la passerelle UniFi locale et de Home
  Assistant, envoi toutes les 5 min vers Supabase, file d'attente en cas
  d'échec, adresses MAC hachées (HMAC-SHA256), aucune adresse IP envoyée.
