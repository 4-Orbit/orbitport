# Orbitport console (4Orbit policy playground). Development image: builds the
# client and runs the BFF with tsx. The BFF holds the operator PAT, read from
# ORBITPORT_CONSOLE_PAT_FILE, and never sends it to the browser.
FROM node:24-alpine

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npx vite build

ENV NODE_ENV=production
USER node
EXPOSE 4317
CMD ["node", "--import", "tsx", "server/main.ts"]
