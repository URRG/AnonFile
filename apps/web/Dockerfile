FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS source
WORKDIR /app
COPY package*.json ./
# Optional, build-only trust bundle for a managed TLS proxy.
RUN --mount=type=secret,id=package_ca \
    if [ -f /run/secrets/package_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/package_ca; fi \
    && npm ci --ignore-scripts
COPY . .
FROM source AS test
CMD ["npm", "test"]

FROM source AS build
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
WORKDIR /app
RUN --mount=type=secret,id=package_ca \
    if [ -f /run/secrets/package_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/package_ca; fi \
    && npm install --global serve@14.2.4
COPY --from=build /app/dist ./dist
USER node
EXPOSE 3000
CMD ["serve", "-s", "dist", "-l", "3000"]
