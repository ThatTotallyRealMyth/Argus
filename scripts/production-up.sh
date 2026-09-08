#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing ${ENV_FILE}; copy .env.example to .env and replace every secret." >&2
  exit 1
fi
if docker compose version >/dev/null 2>&1; then
  compose_command=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  compose_command=(docker-compose)
else
  echo "Docker Compose v2 is required (docker compose or docker-compose)." >&2
  exit 1
fi

compose=("${compose_command[@]}" --env-file "${ENV_FILE}" -f "${ROOT_DIR}/docker-compose.yaml")
"${compose[@]}" config --quiet

db_container="$("${compose[@]}" ps -q db)"
if [[ -n "${db_container}" ]] && [[ "$(docker inspect -f '{{.State.Running}}' "${db_container}" 2>/dev/null || true)" == "true" ]]; then
  ENV_FILE="${ENV_FILE}" "${ROOT_DIR}/scripts/backup.sh"
fi

"${compose[@]}" up -d --build --remove-orphans

deadline=$((SECONDS + 240))
while (( SECONDS < deadline )); do
  backend_container="$("${compose[@]}" ps -q backend)"
  if [[ -n "${backend_container}" ]]; then
    health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${backend_container}" 2>/dev/null || true)"
    if [[ "${health}" == "healthy" ]]; then
      echo "Argus is ready: ${DEPLOY_URL:-http://127.0.0.1:5003}"
      exit 0
    fi
    if [[ "$(docker inspect -f '{{.State.Status}}' "${backend_container}" 2>/dev/null || true)" == "exited" ]]; then
      break
    fi
  fi
  sleep 3
done

"${compose[@]}" ps >&2
"${compose[@]}" logs --tail=160 backend prepare-storage init-admin db redis >&2
echo "Deployment did not become healthy within 240 seconds." >&2
exit 1
