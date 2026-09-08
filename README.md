└─$ ./scripts/production-up.sh                                  
[+] Running 24/24
 ✔ redis Pulled                                                                                                                                                                                                      7.1s 
   ✔ 897d797d2723 Pull complete                                                                                                                                                                                      1.2s 
   ✔ d85eda7b0b14 Pull complete                                                                                                                                                                                      1.2s 
   ✔ 9516b0cd89c9 Pull complete                                                                                                                                                                                      1.3s 
   ✔ de4b872bfdc3 Pull complete                                                                                                                                                                                      2.4s 
   ✔ 2c96e5a02ba0 Pull complete                                                                                                                                                                                      2.4s 
   ✔ 4f4fb700ef54 Pull complete                                                                                                                                                                                      2.4s 
   ✔ 41caa0265cb5 Pull complete                                                                                                                                                                                      2.9s 
 ✘ init-admin Error         pull access denied for moon-gazing-tower-backend, repository does not exist or may require 'docker login': denied: requested access to the resource is denied                            3.0s 
 ✔ db Pulled                                                                                                                                                                                                        16.8s 
   ✔ 6310eb16bf42 Pull complete                                                                                                                                                                                      4.7s 
   ✔ 639367129460 Pull complete                                                                                                                                                                                      4.7s 
   ✔ 248bdcd6e955 Pull complete                                                                                                                                                                                      4.9s 
   ✔ 8d2f3610bf84 Pull complete                                                                                                                                                                                      4.9s 
   ✔ 22bf49630d7e Pull complete                                                                                                                                                                                      5.2s 
   ✔ d523576e6b46 Pull complete                                                                                                                                                                                      5.2s 
   ✔ d522ad15b8c1 Pull complete                                                                                                                                                                                      5.3s 
   ✔ 876153b11224 Pull complete                                                                                                                                                                                      5.7s 
   ✔ 04913c3958ed Pull complete                                                                                                                                                                                     10.7s 
   ✔ a849d36c92a3 Pull complete                                                                                                                                                                                     10.8s 
   ✔ d6430d172c75 Pull complete                                                                                                                                                                                     11.7s 
   ✔ b86905d46631 Pull complete                                                                                                                                                                                     11.7s 
   ✔ 2659259e5615 Pull complete                                                                                                                                                                                     11.7s 
   ✔ 8f6bdf8e7ebe Pull complete                                                                                                                                                                                     12.7s 
[+] Building 129.3s (22/28)                                                                                                                                                                                                                             
 => [internal] load local bake definitions                                                                                                                                                                                                         0.0s
 => => reading from stdin 457B                                                                                                                                                                                                                     0.0s
 => [internal] load build definition from Dockerfile                                                                                                                                                                                               0.0s
 => => transferring dockerfile: 1.18kB                                                                                                                                                                                                             0.0s
 => [internal] load metadata for docker.io/library/node:22-alpine                                                                                                                                                                                  3.0s
 => [internal] load metadata for docker.io/library/debian:bookworm-slim                                                                                                                                                                            2.5s
 => [internal] load metadata for docker.io/library/golang:1.24                                                                                                                                                                                     3.0s
 => [internal] load .dockerignore                                                                                                                                                                                                                  0.0s
 => => transferring context: 211B                                                                                                                                                                                                                  0.0s
 => [builder 1/7] FROM docker.io/library/golang:1.24@sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804                                                                                                                      20.2s
 => => resolve docker.io/library/golang:1.24@sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804                                                                                                                               0.0s
 => => sha256:954d6059ca7bdbb9ceb566ca2239e01ef312165659d656753d7dbace7771a591 25.61MB / 25.61MB                                                                                                                                                   2.0s
 => => sha256:b5e2021c4c8bd1a46b34d9608a9381afdc333600ee1ef3c94306ecf7373e1956 67.79MB / 67.79MB                                                                                                                                                   4.6s
 => => sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804 9.70kB / 9.70kB                                                                                                                                                     0.0s
 => => sha256:00925efecb9c93b3208f48a9e8ae8b1d426be1fff78baf2fc9d394d198fe9fc8 3.05kB / 3.05kB                                                                                                                                                     0.0s
 => => sha256:ef235bf1a09a237b896b69935c8c8d917c9c6a78b538724911414afc0a96763c 49.29MB / 49.29MB                                                                                                                                                   1.3s
 => => sha256:46fdd02b6cbcd624a4087ea298e4c8505e5d400c4ee5181e4dd06e2297d647ae 2.32kB / 2.32kB                                                                                                                                                     0.0s
 => => sha256:b2b04fcbed4bf6e5373e2607d2705704ec5b220f1d1306e06ab8fe9471b2f86a 102.14MB / 102.14MB                                                                                                                                                 5.6s
 => => extracting sha256:ef235bf1a09a237b896b69935c8c8d917c9c6a78b538724911414afc0a96763c                                                                                                                                                          2.8s
 => => sha256:f7bdfd728ac2ad72d43b82689890dc698260d3a1049845f48fb3fb942df6c581 79.13MB / 79.13MB                                                                                                                                                   5.0s
 => => extracting sha256:954d6059ca7bdbb9ceb566ca2239e01ef312165659d656753d7dbace7771a591                                                                                                                                                          1.2s
 => => sha256:50a27cd32f8983e7e43777ec65195fb6594ea877f31993fd555513c261ffc054 126B / 126B                                                                                                                                                         5.1s
 => => sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1 32B / 32B                                                                                                                                                           5.5s
 => => extracting sha256:b5e2021c4c8bd1a46b34d9608a9381afdc333600ee1ef3c94306ecf7373e1956                                                                                                                                                          4.1s
 => => extracting sha256:b2b04fcbed4bf6e5373e2607d2705704ec5b220f1d1306e06ab8fe9471b2f86a                                                                                                                                                          4.1s
 => => extracting sha256:f7bdfd728ac2ad72d43b82689890dc698260d3a1049845f48fb3fb942df6c581                                                                                                                                                          6.3s
 => => extracting sha256:50a27cd32f8983e7e43777ec65195fb6594ea877f31993fd555513c261ffc054                                                                                                                                                          0.0s
 => => extracting sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1                                                                                                                                                          0.0s
 => [web-builder 1/6] FROM docker.io/library/node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32                                                                                                               10.0s
 => => resolve docker.io/library/node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32                                                                                                                            0.0s
 => => sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 6.41kB / 6.41kB                                                                                                                                                     0.0s
 => => sha256:76789712cd1ae89a1225eac9077010d68987a423588042dac30446f502f1858c 1.72kB / 1.72kB                                                                                                                                                     0.0s
 => => sha256:395425e54d98ebbd748d388685a0c2de151a30fa92fffc10ba30fa63f3db64d6 6.56kB / 6.56kB                                                                                                                                                     0.0s
 => => sha256:55afa1ecc21d2bb5e5045f32dafee56272ffd89860bac26f6c32123439af26a4 3.85MB / 3.85MB                                                                                                                                                     6.3s
 => => sha256:efbef6f9e333972a10ca323e700496a64e7ddcc3a6725e6afbbae52e690f4a4a 52.63MB / 52.63MB                                                                                                                                                   7.6s
 => => sha256:a2980c1fee17dfd6263234b253955e0e9d5f38d47c0e71c001139897134899d0 1.26MB / 1.26MB                                                                                                                                                     6.6s
 => => extracting sha256:55afa1ecc21d2bb5e5045f32dafee56272ffd89860bac26f6c32123439af26a4                                                                                                                                                          0.2s
 => => sha256:16da5a6403776464b5bf551ef294de57da242eac594527ea551a46e7f76ac2d6 445B / 445B                                                                                                                                                         6.8s
 => => extracting sha256:efbef6f9e333972a10ca323e700496a64e7ddcc3a6725e6afbbae52e690f4a4a                                                                                                                                                          2.2s
 => => extracting sha256:a2980c1fee17dfd6263234b253955e0e9d5f38d47c0e71c001139897134899d0                                                                                                                                                          0.1s
 => => extracting sha256:16da5a6403776464b5bf551ef294de57da242eac594527ea551a46e7f76ac2d6                                                                                                                                                          0.0s
 => [internal] load build context                                                                                                                                                                                                                  0.1s
 => => transferring context: 2.08MB                                                                                                                                                                                                                0.0s
 => [stage-2 1/8] FROM docker.io/library/debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171                                                                                                              8.3s
 => => resolve docker.io/library/debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171                                                                                                                      0.0s
 => => sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 5.65kB / 5.65kB                                                                                                                                                     0.0s
 => => sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867 1.02kB / 1.02kB                                                                                                                                                     0.0s
 => => sha256:160466e67bb85a4099d9d9c2356b4a6a64747b281a22c142efbd4539db1b8525 453B / 453B                                                                                                                                                         0.0s
 => => sha256:a8ac7f6c67abc236e4c745052c404112b8fab6fe8ac3a329d1ef3b867ad67c71 28.23MB / 28.23MB                                                                                                                                                   6.1s
 => => extracting sha256:a8ac7f6c67abc236e4c745052c404112b8fab6fe8ac3a329d1ef3b867ad67c71                                                                                                                                                          2.1s
 => [stage-2 2/8] RUN apt-get update && apt-get install -y --no-install-recommends     ca-certificates chromium dumb-init fonts-dejavu-core nmap python3 &&     rm -rf /var/lib/apt/lists/*                                                       30.7s
 => [web-builder 2/6] WORKDIR /web                                                                                                                                                                                                                 1.7s
 => [web-builder 3/6] COPY web/package.json web/package-lock.json ./                                                                                                                                                                               0.2s
 => [web-builder 4/6] RUN npm ci                                                                                                                                                                                                                   7.4s
 => [web-builder 5/6] COPY web/ ./                                                                                                                                                                                                                 0.1s
 => [web-builder 6/6] RUN npm run build                                                                                                                                                                                                            4.8s
 => [builder 2/7] RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev &&     rm -rf /var/lib/apt/lists/*                                                                                                                  4.9s
 => [builder 3/7] WORKDIR /app                                                                                                                                                                                                                     0.0s
 => [builder 4/7] COPY go.mod go.sum ./                                                                                                                                                                                                            0.0s
 => ERROR [builder 5/7] RUN go mod download                                                                                                                                                                                                      100.9s
 => [stage-2 3/8] RUN useradd --system --home /app --shell /usr/sbin/nologin appuser                                                                                                                                                               0.2s
 => [stage-2 4/8] WORKDIR /app                                                                                                                                                                                                                     0.0s
------
 > [builder 5/7] RUN go mod download:
99.92 go: github.com/chromedp/cdproto@v0.0.0-20231011050154-1d073bb38998: read "https://goproxy.cn/github.com/chromedp/cdproto/@v/v0.0.0-20231011050154-1d073bb38998.zip": stream error: stream ID 1549; INTERNAL_ERROR; received from peer
99.92 go: github.com/chromedp/chromedp@v0.9.3: read "https://goproxy.cn/github.com/chromedp/chromedp/@v/v0.9.3.zip": stream error: stream ID 1551; INTERNAL_ERROR; received from peer
99.92 go: github.com/lcvvvv/gonmap@v1.3.4: read "https://goproxy.cn/github.com/lcvvvv/gonmap/@v/v1.3.4.zip": stream error: stream ID 1563; INTERNAL_ERROR; received from peer
99.92 go: github.com/modelcontextprotocol/go-sdk@v0.5.0: read "https://goproxy.cn/github.com/modelcontextprotocol/go-sdk/@v/v0.5.0.zip": stream error: stream ID 1565; INTERNAL_ERROR; received from peer
99.92 go: github.com/projectdiscovery/naabu/v2@v2.3.5: read "https://goproxy.cn/github.com/projectdiscovery/naabu/v2/@v/v2.3.5.zip": stream error: stream ID 1567; INTERNAL_ERROR; received from peer
99.92 go: github.com/dlclark/regexp2@v1.11.5: read "https://goproxy.cn/github.com/dlclark/regexp2/@v/v1.11.5.zip": stream error: stream ID 1647; INTERNAL_ERROR; received from peer
99.92 go: github.com/miekg/dns@v1.1.68: read "https://goproxy.cn/github.com/miekg/dns/@v/v1.1.68.zip": stream error: stream ID 1749; INTERNAL_ERROR; received from peer
99.92 go: github.com/pelletier/go-toml/v2@v2.1.0: read "https://goproxy.cn/github.com/pelletier/go-toml/v2/@v/v2.1.0.zip": stream error: stream ID 1765; INTERNAL_ERROR; received from peer
99.92 go: github.com/projectdiscovery/cdncheck@v1.1.27: read "https://goproxy.cn/github.com/projectdiscovery/cdncheck/@v/v1.1.27.zip": stream error: stream ID 1777; INTERNAL_ERROR; received from peer
99.92 go: github.com/projectdiscovery/mapcidr@v1.1.34: read "https://goproxy.cn/github.com/projectdiscovery/mapcidr/@v/v1.1.34.zip": stream error: stream ID 1797; INTERNAL_ERROR; received from peer
99.92 go: github.com/projectdiscovery/uncover@v1.1.0: read "https://goproxy.cn/github.com/projectdiscovery/uncover/@v/v1.1.0.zip": stream error: stream ID 1807; INTERNAL_ERROR; received from peer
99.92 go: github.com/refraction-networking/utls@v1.7.0: read "https://goproxy.cn/github.com/refraction-networking/utls/@v/v1.7.0.zip": stream error: stream ID 1811; INTERNAL_ERROR; received from peer
99.92 go: github.com/shirou/gopsutil/v3@v3.23.7: read "https://goproxy.cn/github.com/shirou/gopsutil/v3/@v/v3.23.7.zip": stream error: stream ID 1823; INTERNAL_ERROR; received from peer
99.92 go: golang.org/x/exp@v0.0.0-20250106191152-7588d65b2ba8: read "https://goproxy.cn/golang.org/x/exp/@v/v0.0.0-20250106191152-7588d65b2ba8.zip": stream error: stream ID 1897; INTERNAL_ERROR; received from peer
------
Dockerfile:8
--------------------
   6 |     ENV GOPROXY=https://goproxy.cn,direct
   7 |     COPY go.mod go.sum ./
   8 | >>> RUN go mod download
   9 |     COPY . .
  10 |     RUN CGO_ENABLED=1 go build -o /out/server ./cmd/server && \
--------------------
failed to solve: process "/bin/sh -c go mod download" did not complete successfully: exit code: 1
                                                                                                                                                                                                                                                        
┌──(kali㉿kali)-[~/personalprojects/Argus]
└─$ 



# Argus

Argus is a web app and external pen testing framework for authorized security research and attack-surface operations. It brings scan orchestration, asset management, HTTP observations, fingerprint and proof-of-concept (PoC) libraries, proxy management, internet intelligence providers, and MCP tools into one web console.

The application uses a Go backend and a React/Vite frontend. PostgreSQL stores application data, while Redis stores runtime state and cache data. The Argus interface uses a dark security-operations design with route-level lazy loading.

> Use the scanning, PoC, proxy, and MCP features only against assets that you own or are explicitly authorized to test.

Some detection resources intentionally retain source-language strings. Chinese product signatures in `backend/configs/fingerprints/finger.yaml` and provider terms in `backend/configs/dicts/domain/big.txt` are matching data, not interface text; translating them would reduce detection coverage.

## Features

- **Scan orchestration:** Create, start, cancel, retry, delete, and export scan tasks with reusable policies and real-time progress.
- **Authorization guardrails:** Maintain per-project allow and exclude rules for exact domains, wildcard subdomains, IP addresses, and CIDR ranges. Default or explicit scopes apply to manual tasks, enterprise dispatches, scheduled tasks, continuous monitoring, manual PoC runs, and MCP operations. Every active network path is revalidated before use.
- **Durable execution queue:** Tasks are persisted before execution and atomically claimed by workers subject to a global concurrency limit. Queued work survives service restarts.
- **Asset inventory:** Normalize domains, IP addresses, ports, and sites across tasks. Preserve observations, relationship evidence, and semantic change timelines while aggregating findings and exposure risk. URL and HTTP records and asset groups are also supported.
- **Hunting leads:** Build a global priority queue from confirmed findings, takeover candidates, sensitive services, administrative interfaces, PoC matches, and attack-surface changes. Web and MCP validation share the source task's authorization scope and retain a structured audit trail. PoC hits are stored as deduplicated finding evidence and linked to asset risk and reports.
- **Evidence packages:** Review findings independently, copy individual evidence fields or a complete evidence package, and export a self-contained HTML security report.
- **Reconnaissance:** Domain discovery, port scanning, service and site detection, crawling, screenshots, fingerprinting, exposed-file checks, and PoC validation.
- **Library management:** Edit and import fingerprint DSL rules, Nuclei templates, and constrained Custom HTTP PoCs with categories, severities, and matching modes.
- **Proxy pool:** HTTP, HTTPS, and SOCKS5 proxies with authentication, bulk import, bulk validation, health checks, round-robin selection, and automatic rotation.
- **Internet intelligence:** Built-in configuration for FOFA, Hunter, 360 Quake, ZoomEye, Shodan, VirusTotal, and GitHub. Credentials can be saved, enabled, and tested individually; encrypted values are never returned to the browser.
- **Enterprise discovery:** Query sites, apps, mini programs, and quick apps through pluggable ICP_Query-compatible providers. Results can be synchronized into the global asset inventory or dispatched as scan tasks while preserving provenance.
- **Automation:** Asset monitoring, NVD CVE keyword monitoring, scheduled tasks, execution history, logs, and reusable notification channels.
- **MCP:** An optional Streamable HTTP MCP endpoint for task, asset, library, configuration, validation, and export operations.
- **Advanced search:** Field-qualified terms, parentheses, quoted phrases, `AND`, `OR`, `NOT`, and per-column filters.

## Technology stack

- Backend: Go 1.24, Gin, GORM, PostgreSQL, Redis
- Frontend: React 19, Vite, Tailwind CSS 4, Lucide, Motion
- Browser automation: Chromium, chromedp
- Protocols: REST, WebSocket, Streamable HTTP MCP

## Quick start

### Docker Compose

Prerequisites:

- Docker Engine 24+
- Docker Compose v2
- At least 2 GB of available memory; allow more for large scans or screenshot workloads

Clone the repository and create the environment file:

~~~bash
git clone https://github.com/ThatTotallyRealMyth/Argus.git
cd Argus
cp .env.example .env
~~~

Edit `.env` and replace at least these values:

~~~dotenv
DB_PASSWORD=a-random-database-password
REDIS_PASSWORD=a-random-redis-password
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=an-administrator-password-with-at-least-12-characters
~~~

Build and start the stack. The release script validates configuration first, backs up an existing database before automatic migrations, and waits for PostgreSQL, Redis, and the backend to become ready:

~~~bash
./scripts/production-up.sh
~~~

You can instead run `docker compose up -d --build` directly. When the UI and API share an origin, leave `CORS_ALLOWED_ORIGINS` empty. For a separately deployed frontend, provide an explicit origin allowlist; do not use `*`.

Service endpoints:

- Web console: http://localhost:5003
- Liveness check: http://localhost:5003/health
- Dependency readiness check: http://localhost:5003/ready
- PostgreSQL: localhost only at 127.0.0.1:15432
- Redis: localhost only at 127.0.0.1:16379

On first startup, the `prepare-storage` container gives the non-root application user access to the bind-mounted runtime directories and gives your host user access to the backup directory. Then `init-admin` creates the administrator account. JWT and encryption keys are generated in the Docker data volume. Do not delete `.storage/app/data`; doing so can make previously encrypted configuration unrecoverable.

Create a database backup manually:

~~~bash
./scripts/backup.sh
~~~

Backups are stored in `.storage/backups/`. The release script does not automatically delete historical backups.

Stop the stack:

~~~bash
docker compose down
~~~

The following commands permanently delete the local database, keys, logs, and other runtime data:

~~~bash
docker compose down -v
rm -rf .storage
~~~

### Enable MCP

The MCP endpoint is mounted only when MCP is enabled and a valid key is configured. For Docker, set a key of at least 32 characters in `.env`:

~~~dotenv
MCP_API_KEY=replace-with-a-random-key-of-at-least-32-characters
~~~

Restart the backend and confirm its status:

~~~bash
docker compose up -d backend
curl http://localhost:5003/health
~~~

When the health response contains `mcp_enabled: true`, MCP is available at `http://localhost:5003/mcp`. Requests must include:

~~~http
Authorization: Bearer <MCP_API_KEY>
~~~

For a direct local run without Docker:

~~~bash
cd backend
MCP_API_KEY='replace-with-a-random-key-of-at-least-32-characters' go run ./cmd/server
~~~

Set `MCP_ENABLED=false` to disable the endpoint temporarily. MCP currently focuses on the global asset inventory, clustered attack leads, the evidence workbench, triage state, and authorized PoC validation workflows.

## Local development

Local development requires PostgreSQL, Redis, Go 1.24+, Node.js 20+, and npm.

### Backend

~~~bash
cd backend
cp configs/config.docker.yaml configs/config.yaml
# Adjust database, Redis, server, and other settings for the local environment.
go run ./cmd/init-admin
go run ./cmd/server
~~~

The local file `backend/configs/config.yaml` is not committed. If the JWT or encryption key is empty, the service generates a random key in `data/.jwt-secret` or `data/.encryption-key` with `0600` permissions.

Reset an administrator password:

~~~bash
go run ./cmd/init-admin --reset-password admin
~~~

### Frontend

~~~bash
cd backend/web
npm install
npm run dev
~~~

Vite runs at http://localhost:5173 by default. The development API proxy is configured in [backend/web/vite.config.js](backend/web/vite.config.js).

~~~bash
npm run build
npm run preview -- --port 4173
~~~

## Search syntax

The task, asset, HTTP, fingerprint, and PoC lists support advanced search. Operator precedence is `NOT`, `AND`, then `OR`; whitespace is equivalent to `AND`. Use each page's help control to see its available fields.

~~~text
nginx && admin
nginx && !test
title:"admin portal" || product:tomcat
(status=200 || status=302) && !url:logout
~~~

Per-column filters are combined with the main expression before being sent to the backend. Invalid expressions return the error position, an example, and supported fields. Database queries are parameterized.

## Proxy-pool behavior

A proxy is included in the scan request pool only when enabled, successfully validated, and marked `healthy`.

~~~text
http://host:port
https://host:port
socks5://host:port
http://user:password@host:port
~~~

Bulk imports accept one URL per line, up to 1,000 lines. Validation errors report the line index and reason.

- Health checks run every 30 seconds by default.
- Automatic rotation advances the round-robin starting point every 30 seconds by default.
- Both features can be adjusted under **Settings → Scan engine**.
- Configuration changes affect newly started tasks only.
- Internet-intelligence credential checks also use enabled, healthy proxies.

## Custom HTTP PoCs

A Custom HTTP PoC uses YAML or JSON to describe same-origin HTTP requests. It cannot execute shell commands, Python, or arbitrary local programs. Supported matchers are `status`, `word`, `regex`, and `size`:

~~~yaml
requests:
  - method: GET
    path: /admin
    headers:
      X-Target-Host: "{{Host}}"
    timeout_seconds: 10
    matchers_condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: [management-console]
      - type: regex
        part: header
        regex: ['Server: .*Example']
~~~

Available placeholders are `{{BaseURL}}`, `{{Scheme}}`, `{{Host}}`, and `{{Hostname}}`. A template may contain at most 10 requests. Requests must remain same-origin; cross-host URLs and redirects are rejected. At most 2 MiB is read from one response.

## Continuous CVE monitoring

Create a CVE monitor under **Automation → Asset monitoring** and enter product keywords separated by commas or newlines. The platform fetches NVD changes using the `lastModified` window. The first run establishes a baseline; later runs distinguish new CVEs from revisions and send one combined alert through the selected webhook, DingTalk, or Feishu channel.

Each monitor accepts up to five unique keywords and stores up to 500 recent CVE summaries per run. Response size and alert-entry counts are capped. The UI's **Run** action and MCP `manage_platform_record(action=run)` share scheduler concurrency protection.

## GitHub exposure monitoring

After configuring and enabling a GitHub Personal Access Token on the internet-intelligence page, create a GitHub query under **Automation → Asset monitoring**. Each run retrieves up to 30 candidates and concurrently verifies up to 12 files. A finding is created only when file content confirms a credential pattern; a search hit alone is not recorded as a vulnerability.

Snapshots store only the repository, path, trusted `github.com` evidence URL, severity, and credential-category counts. They do not store raw tokens, private keys, or matched text. Change detection uses a redacted evidence fingerprint rather than result totals.

## Credential storage

API keys, tokens, webhook URLs and signing secrets, custom intelligence or ICP endpoints, and request headers are encrypted at rest. Settings responses return only a `configured` state; encrypted values are returned as empty strings. Leaving a saved field blank preserves its value. Saved credentials are decrypted by the backend only when contacting the provider and are not returned to the browser.

Bulk setting updates use one transaction. If encryption or persistence fails for any item, the whole update is rolled back. The backend determines which keys are sensitive; clients cannot force plaintext storage with `is_encrypted=false`.

## Finding evidence and reports

The **Findings** tab presents descriptions, payloads, proof, remediation guidance, and references in a separate evidence window. Fields can be copied individually or assembled into a submission package containing the target, severity, type, source, and proof.

**Export security report** generates a self-contained HTML report. User-controlled values are escaped with context-aware templates. Site links accept only credential-free HTTP or HTTPS URLs. Reports use a strict CSP, download as attachments, and are written with `0600` permissions. CSV exports neutralize formula prefixes to prevent spreadsheet formula injection.

Production responses include a CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, a no-referrer policy, and a permissions policy disabling camera, microphone, and geolocation. Inline styles remain allowed only for dynamic table column widths.

## Enterprise asset workflow

The enterprise workbench queries sites, apps, mini programs, and quick apps through an ICP_Query-compatible HTTP source. Configure it on the internet-intelligence page. Local endpoints are contacted directly; remote endpoints reuse the healthy proxy pool. PostgreSQL persists the queue. Each response is subject to a timeout, an 8 MiB body limit, and a 10,000-result limit.

Enterprise results containing domains support two distinct bulk actions:

- **Synchronize assets:** Write deduplicated canonical assets, optionally adding them to a group. This performs no network scan.
- **Dispatch scan:** Create a pending scan task for review and manual start on the Tasks page.

Synchronization uses a transaction and advisory lock. Repeated observations and group memberships are idempotent. `origin_type=enterprise_query`, original responses, semantic-state hashes, and change timelines preserve provenance. REST and MCP audit entries record only the operator, count, and group ID—not domains or credentials.

## Authorization scopes

Use **Policies → Authorization scopes** to define the mandatory boundary of an authorized assessment. At least one allow rule is required; exclude rules take precedence.

~~~text
example.com
*.example.com
203.0.113.10
203.0.113.0/24
2001:db8::/32
~~~

`*.example.com` matches subdomains only, not the apex domain. Add `example.com` separately when both are authorized. URL targets are checked by host or IP while retaining the original path. Scope rules define host or network boundaries, so rules containing paths, query strings, or fragments are rejected.

The first scope becomes the default. It applies to manual tasks without a `scope_id`, enterprise scan dispatches, scheduled tasks, network monitors, manual PoC runs, and MCP `create_scan_task` calls. The backend revalidates targets at creation, queueing, and worker claim. The worker then creates an immutable scope snapshot for the task. Existing installations remain in compatibility mode when no scopes are configured.

Guardrails also cover discovered subdomains, expanded CIDR or C-class addresses, port and service probes, redirects, crawled pages and JavaScript, exposed-file probes, screenshot navigation and subrequests, WIH, host-collision checks, takeover validation, and PoC targets. Out-of-scope redirects stop before the next request. A domain rule does not automatically authorize resolved IPs; add relevant IP or CIDR rules when active scanning of those addresses is intended.

Scope-constrained tasks run only same-origin Custom HTTP PoCs. Nuclei or Neutron templates that cannot accept the network validator are skipped, and custom scripts are rejected. Compatibility mode retains prior behavior. MCP clients can call `list_scan_scopes` and then use the local, read-only `validate_scan_scope` tool; preflight validation performs no DNS, HTTP, or port requests.

## API and authentication

- `GET /health`: public liveness check
- `POST /api/v1/auth/login`: authenticate and receive a JWT
- Other `/api/v1/*`: require `Authorization: Bearer <JWT>`
- `/api/v1/ws/progress`: task progress over WebSocket
- `/mcp`: mounted only with a valid, separate MCP bearer key

Routes are defined in [backend/internal/api/router.go](backend/internal/api/router.go). Error responses contain an `error` field; search errors also return an `example` and `supported_fields`.

## Project structure

~~~text
backend/
  cmd/                  server and init-admin entry points
  internal/api/         Gin routes and HTTP handlers
  internal/mcpserver/   MCP handler and tools
  internal/proxypool/   proxy health checks and request integration
  internal/scanner/     scan engine and result persistence
  internal/searchquery/ search-expression parser
  internal/services/    domain services
  configs/              templates, dictionaries, and default fingerprints
  web/src/app/          application shell and lazy-loaded routes
  web/src/components/   shared UI components
  web/src/hooks/        React hooks
  web/src/lib/          API clients, constants, and utilities
  web/src/pages/        route pages
~~~

## Testing and quality checks

~~~bash
cd backend
go test ./...
go vet ./...
go test -race ./internal/services ./internal/api/handlers ./internal/mcpserver

cd web
npm run build
~~~

Changes to interactions, bulk actions, or layout should also be checked in a browser at desktop widths, including disabled states, confirmation paths, overflow, and console errors. Do not commit `backend/web/dist`, `node_modules`, local configuration, logs, screenshots, or runtime data.

## Troubleshooting

- Docker logs: `docker compose logs -f backend`
- Local logs: configured by `logging.file`; default `./logs/arl.log`
- **Failed to fetch:** Check `/health`, backend logs, the JWT, and frontend API address.
- **MCP unavailable:** Check `MCP_API_KEY` length and confirm `/health` reports `mcp_enabled: true`.
- **Database connection failed:** Check PostgreSQL and `database.host`, `port`, `user`, and `dbname`.
- **Dynamic module load failed:** Rebuild the frontend and force-refresh the browser cache.

## Contributing

Before submitting changes, run at least `go test ./...` and `npm run build`. Changes affecting APIs, MCP, proxies, or scanner behavior should include relevant tests or browser validation.

Do not commit `.env`, `backend/configs/config.yaml`, `backend/data`, `backend/logs`, `backend/web/dist`, `backend/web/node_modules`, local screenshots, compiled binaries, or reference projects.
