# Image de base : fournie par le Supervisor depuis build.yaml ; valeur par
# défaut valide pour un build sans Supervisor (Home Assistant Green = aarch64).
ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base-python:3.13-alpine3.23
FROM ${BUILD_FROM}

# Python est déjà dans l'image de base ; aucune dépendance externe
# (bibliothèque standard uniquement).
COPY app/ /app/
WORKDIR /app
CMD [ "python3", "-u", "/app/main.py" ]
