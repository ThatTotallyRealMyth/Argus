#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"
BACKUP_DIR="${BACKUP_DIR:-${ROOT_DIR}/.storage/backups}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing ${ENV_FILE}; copy .env.example to .env and replace every secret." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

compose=(docker compose --env-file "${ENV_FILE}" -f "${ROOT_DIR}/docker-compose.yaml")
db_container="$("${compose[@]}" ps -q db)"
if [[ -z "${db_container}" ]] || [[ "$(docker inspect -f '{{.State.Running}}' "${db_container}" 2>/dev/null || true)" != "true" ]]; then
  echo "PostgreSQL container is not running; no backup was created." >&2
  exit 1
fi

mkdir -p "${BACKUP_DIR}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
destination="${BACKUP_DIR}/moon-gazing-tower-${timestamp}.sql.gz"
temporary="${destination}.tmp"
trap 'rm -f "${temporary}"' EXIT

"${compose[@]}" exec -T db pg_dump --clean --if-exists --no-owner --no-privileges -U arl -d arl_vp3 | gzip -9 >"${temporary}"
test -s "${temporary}"
mv "${temporary}" "${destination}"
trap - EXIT
echo "Backup created: ${destination}"
