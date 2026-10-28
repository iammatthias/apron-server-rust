# The web client and the router in front of it and aprond, from the deploy/
# directory of the bundle tools/deploy/deploy.sh assembles.
FROM caddy:2.11.7-alpine AS router
LABEL systems.farfield.project=apron
COPY router.Caddyfile /etc/caddy/Caddyfile

FROM caddy:2.11.7-alpine AS web
LABEL systems.farfield.project=apron
COPY web.Caddyfile /etc/caddy/Caddyfile
COPY web /srv
