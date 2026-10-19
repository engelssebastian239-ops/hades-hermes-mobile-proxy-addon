FROM node:24.21.0-alpine3.23@sha256:9ec4a2e289874ed0d722e1772ec2de45d2801541db8612f3638b26f128c69ac2

ENV NODE_ENV=production \
    NODE_OPTIONS=--max-old-space-size=64

WORKDIR /opt/hades-hermes-mobile-proxy
COPY --chown=10001:10001 proxy.mjs runtime-preflight.mjs server.mjs package.json ./
USER 10001:10001
CMD ["node", "server.mjs"]
