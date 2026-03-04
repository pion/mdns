#!/usr/bin/env bash
# SPDX-FileCopyrightText: The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

# End-to-end test orchestration for pion/mdns vs avahi-daemon.
# Usage: bash e2e/test.sh

set -euo pipefail

PROFILE="bridge"
COMPOSE_FILE="e2e/compose.yml"

export GO_VERSION="${GO_VERSION:-1.25}"

cleanup() {
  echo "--- Collecting logs ---"
  docker compose -f "$COMPOSE_FILE" --profile "$PROFILE" logs avahi 2>/dev/null || true
  docker compose -f "$COMPOSE_FILE" --profile "$PROFILE" logs sut 2>/dev/null || true
  echo "--- Cleaning up ---"
  docker compose -f "$COMPOSE_FILE" --profile "$PROFILE" down -v --remove-orphans 2>/dev/null || true
}

trap cleanup EXIT

echo "=== E2E: go=$GO_VERSION ==="

echo "--- Building ---"
docker compose -f "$COMPOSE_FILE" --profile "$PROFILE" build

echo "--- Running ---"
docker compose -f "$COMPOSE_FILE" --profile "$PROFILE" up \
  --abort-on-container-exit \
  --exit-code-from sut
