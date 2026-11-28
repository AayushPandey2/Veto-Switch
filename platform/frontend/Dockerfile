FROM node:22-alpine AS build

WORKDIR /app
COPY platform/frontend/package.json ./package.json
RUN npm install --no-audit --no-fund
COPY platform/frontend/ ./
RUN npm run build

FROM nginx:alpine
COPY platform/frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
