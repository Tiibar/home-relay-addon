ARG BUILD_FROM
FROM $BUILD_FROM

# Python de la distribution, aucune dépendance externe (bibliothèque standard).
RUN apk add --no-cache python3

COPY app/ /app/
WORKDIR /app
CMD [ "python3", "-u", "/app/main.py" ]
