#!/usr/bin/env bash
#
# Waits until StrongDM reports the domain controller as reachable.
#
# The DC installs AD, DNS and ADCS through a PowerShell sequence with several
# reboots, and only re-enables NLA at the very end. Its StrongDM health check
# therefore fails until the domain is genuinely ready, which makes it a usable
# readiness signal for the Windows target that has to join that domain.
#
# Usage: wait-for-dc.sh <resource-id> [timeout-seconds]
#
# Requires the sdm CLI and jq on PATH. The CLI authenticates with the same
# SDM_API_ACCESS_KEY and SDM_API_SECRET_KEY the Terraform provider uses.

set -uo pipefail

resource_id="${1:?resource id required}"
timeout_seconds="${2:-1800}"
interval_seconds=30

for cmd in sdm jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "wait-for-dc: $cmd is not on PATH" >&2
    exit 1
  fi
done

deadline=$(($(date +%s) + timeout_seconds))

while :; do
  # Ask for a fresh check rather than trusting the last scheduled one, which
  # was probably recorded while the DC was still installing.
  sdm admin resources healthcheck "$resource_id" >/dev/null 2>&1

  if sdm admin healthchecks list --json --filter "resourceID:${resource_id}" 2>/dev/null |
    jq -e 'any(.[]; .healthy)' >/dev/null 2>&1; then
    echo "wait-for-dc: domain controller ${resource_id} is reachable"
    exit 0
  fi

  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "wait-for-dc: gave up after ${timeout_seconds}s waiting for ${resource_id}" >&2
    echo "wait-for-dc: check progress with 'sdm admin healthchecks list --filter resourceID:${resource_id}'" >&2
    exit 1
  fi

  echo "wait-for-dc: not ready yet, retrying in ${interval_seconds}s"
  sleep "$interval_seconds"
done
