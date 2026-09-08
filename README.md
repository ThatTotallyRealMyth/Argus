# Eclipse Recon

Eclipse Recon is an asset reconnaissance platform for authorized security testing and attack-surface operations. It brings scan orchestration, asset management, HTTP observations, fingerprint and proof-of-concept (PoC) libraries, proxy management, internet intelligence providers, and MCP tools into one web console.

The application uses a Go backend and a React/Vite frontend. PostgreSQL stores application data, while Redis stores runtime state and cache data. The interface uses a dark ctOS-inspired design with route-level lazy loading.

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

On first startup, the `init-admin` container creates the administrator account. JWT and encryption keys are generated in the Docker data volume. Do not delete `.storage/app/data`; doing so can make previously encrypted configuration unrecoverable.

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
