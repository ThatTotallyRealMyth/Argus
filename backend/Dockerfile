FROM golang:1.24 AS builder

WORKDIR /app
ENV GOPROXY=https://proxy.golang.org,direct
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server && \
    CGO_ENABLED=0 go build -o /out/init-admin ./cmd/init-admin

FROM node:22-alpine AS web-builder
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates chromium dumb-init fonts-dejavu-core nmap python3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --system --home /app --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY --from=builder --chown=appuser:appuser /out/ ./
COPY --chown=appuser:appuser configs/ ./configs/
COPY --from=web-builder --chown=appuser:appuser /web/dist/ ./web/dist/

RUN cp configs/config.docker.yaml configs/config.yaml && \
    mkdir -p data/screenshots data/exports logs && \
    chown -R appuser:appuser data logs

USER appuser
EXPOSE 5003
ENTRYPOINT ["dumb-init","--"]
CMD ["./server"]
