ARG TRAEFIKVERSION=latest

FROM traefik:$TRAEFIKVERSION

# provide the servername as a configurable option
# note that this is self signed so you should still add it to your
# trusted certificates every time you rebuild this images.
# For Chrome: click on the lock icon and export it
# then browse to chrome://settings/certificates and add it. Then restart

ARG FQDN=server.michelanders.nl

# add a self signed certificate
# note: it might be a good thing to remove the openssl package again to
# reduce the attack surface.

RUN apk add --no-cache openssl

WORKDIR /opt/traefik/certs

RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt -subj "/CN=$FQDN" -addext "subjectAltName = DNS:$FQDN"

RUN chmod 644 server.crt

RUN chmod 600 server.key

# add a tls certificate configuration that uses the self signed cert

COPY reverse-proxy/certs-traefik.yml .
