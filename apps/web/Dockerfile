FROM node:22-alpine AS source
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY . .
FROM source AS test
CMD ["npm", "test"]

FROM source AS build
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM node:22-alpine
WORKDIR /app
RUN npm install --global serve@14.2.4
COPY --from=build /app/dist ./dist
USER node
EXPOSE 3000
CMD ["serve", "-s", "dist", "-l", "3000"]
