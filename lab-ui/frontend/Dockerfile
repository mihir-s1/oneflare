FROM node:20-alpine AS builder
WORKDIR /app
# Copy only package.json (not the host lockfile) so npm resolves the correct
# Linux-native binaries (e.g. rollup) fresh; --include=dev ensures vite/build
# tooling installs regardless of NODE_ENV.
COPY package.json ./
RUN npm install --include=dev
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
