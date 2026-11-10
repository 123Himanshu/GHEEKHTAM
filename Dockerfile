FROM node:20-alpine
WORKDIR /app
COPY enhanced ./enhanced
COPY server.js package.json ./
ENV PORT=8080
ENV HOST=0.0.0.0
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:${PORT}/healthz || exit 1
CMD ["node", "server.js"]
