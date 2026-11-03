# Changelog

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
