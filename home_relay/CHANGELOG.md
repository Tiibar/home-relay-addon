# Changelog

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
