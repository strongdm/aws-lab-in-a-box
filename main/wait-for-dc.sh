#!/usr/bin/env bash
#
# Waits until the domain controller's install script reports itself finished.
#
# The script publishes a completion marker to Parameter Store as its last act,
# after promoting the domain, creating the service accounts, installing ADCS and
# linking the GPO that disables NLA. Anything that joins the domain or reads
# those accounts must wait for that marker.
#
# This deliberately does NOT use the DC's StrongDM health check. That check
# passes within about two minutes of launch, because the base Windows AMI
# answers RDP with NLA enabled from first boot - long before the domain exists.
# Gating on it released the Windows target roughly fifteen minutes early, so it
# attempted its domain join against a server that was still promoting, and it
# missed the NLA group policy entirely because that policy had not been created
# yet.
#
# Usage: wait-for-dc.sh <parameter-name> <region> [timeout-seconds]
#
# Requires the AWS CLI and credentials that can read the parameter - the same
# credentials Terraform is already using.

set -uo pipefail

parameter_name="${1:?parameter name required}"
region="${2:?region required}"
timeout_seconds="${3:-2400}"
interval_seconds=30

if ! command -v aws >/dev/null 2>&1; then
  echo "wait-for-dc: the aws CLI is not on PATH" >&2
  exit 1
fi

deadline=$(($(date +%s) + timeout_seconds))

while :; do
  if completed_at=$(aws ssm get-parameter \
    --name "$parameter_name" \
    --region "$region" \
    --query 'Parameter.Value' \
    --output text 2>/dev/null) && [ -n "$completed_at" ] && [ "$completed_at" != "None" ]; then
    echo "wait-for-dc: domain controller finished provisioning at ${completed_at}"
    exit 0
  fi

  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "wait-for-dc: gave up after ${timeout_seconds}s waiting for ${parameter_name}" >&2
    echo "wait-for-dc: check C:\\*.done flag files on the domain controller, or its bootstrap log, to see how far the script got" >&2
    exit 1
  fi

  echo "wait-for-dc: domain controller still provisioning, checking again in ${interval_seconds}s"
  sleep "$interval_seconds"
done
