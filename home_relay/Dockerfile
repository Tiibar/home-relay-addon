# Image de base : fournie par le Supervisor depuis build.yaml ; valeur par
# défaut valide pour un build sans Supervisor (Home Assistant Green = aarch64).
ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base-python:3.13-alpine3.23
FROM ${BUILD_FROM}

# Python est déjà dans l'image de base ; aucune dépendance Python externe
# (bibliothèque standard uniquement). tzdata : heure locale du journal.
# net-snmp-tools : snmpget / snmpwalk pour lire le NAS (SNMPv3, lecture seule) ;
# les commandes d'écriture (snmpset…) sont retirées de l'image.
RUN apk add --no-cache tzdata net-snmp-tools \
    && rm -f /usr/bin/snmpset /usr/bin/snmptrap /usr/bin/snmpinform /usr/bin/snmpusm /usr/bin/snmpvacm /usr/bin/snmpdelta \
    && command -v snmpget && command -v snmpwalk && ! command -v snmpset
COPY app/ /app/
WORKDIR /app
CMD [ "python3", "-u", "/app/main.py" ]
