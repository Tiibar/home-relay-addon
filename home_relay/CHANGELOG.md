# Changelog

## 1.0.1

- Correction de l'installation : image de base Home Assistant avec Python
  (`build.yaml`, `{arch}-base-python:3.13-alpine3.23`) et valeur par défaut
  de `BUILD_FROM` dans le Dockerfile (erreur « base name ($BUILD_FROM) should
  not be blank »).

## 1.0.0

- Première version : lecture seule de la passerelle UniFi locale et de Home
  Assistant, envoi toutes les 5 min vers Supabase, file d'attente en cas
  d'échec, adresses MAC hachées (HMAC-SHA256), aucune adresse IP envoyée.
