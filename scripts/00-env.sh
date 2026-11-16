#!/usr/bin/env bash
# ==============================================================================
# 00-env.sh: Shared Configuration, CLI Flag Parsing & Dynamic Apigee Discovery
#   - Supports CLI flags (--project, --region, --env, --hostname, --audience)
#     or environment variable overrides.
#   - Dynamically queries the Apigee Management API using 'gcloud auth print-access-token'
#     and 'jq' to discover APIGEE_ENV (/environments) and resolve APIGEE_HOSTNAME
#     via environment group attachments (/envgroups/{eg}/attachments).
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT

# ------------------------------------------------------------------------------
# 1. Optional CLI Flag Parsing
# ------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--project)
      export PROJECT_ID="$2"
      shift 2
      ;;
    -r|--region)
      export REGION="$2"
      shift 2
      ;;
    -e|--env)
      export APIGEE_ENV="$2"
      shift 2
      ;;
    -h|--hostname)
      export APIGEE_HOSTNAME="$2"
      shift 2
      ;;
    -a|--audience)
      export CUSTOM_AUDIENCE="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

# ------------------------------------------------------------------------------
# 2. Core GCP & Cloud Run Configuration
# ------------------------------------------------------------------------------
export PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
if [[ -z "${PROJECT_ID}" ]]; then
  echo "❌ ERROR: PROJECT_ID is not set. Run 'gcloud config set project <PROJECT_ID>' or pass --project <PROJECT_ID>." >&2
  exit 1
fi

export REGION="${REGION:-europe-west2}"
export SERVICE_NAME="${SERVICE_NAME:-ldap-policy-connector}"
export CUSTOM_AUDIENCE="${CUSTOM_AUDIENCE:-ldap-policy-service}"
export INGRESS_MODE="${INGRESS_MODE:-all}"

# Dedicated Least-Privilege Service Accounts:
#  1) Cloud Run Runtime Identity (runs the Go LDAP connector container)
export RUNTIME_SA_NAME="${RUNTIME_SA_NAME:-ldap-cloudrun-runtime}"
export RUNTIME_SA_EMAIL="${RUNTIME_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

#  2) Apigee Proxy Identity (mints OIDC ID tokens with CUSTOM_AUDIENCE to invoke Cloud Run)
export INVOKER_SA_NAME="${INVOKER_SA_NAME:-apigee-ldap-invoker}"
export INVOKER_SA_EMAIL="${INVOKER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Apigee Proxy & KVM Names
export APIGEE_ORG="${APIGEE_ORG:-${PROJECT_ID}}"
export KVM_NAME="${KVM_NAME:-ldap-providers-kvm}"
export ADMIN_PROXY_NAME="${ADMIN_PROXY_NAME:-ldap-admin-v1}"
export ADMIN_BASE_PATH="${ADMIN_BASE_PATH:-/v1/ldap-admin}"
export POLICY_PROXY_NAME="${POLICY_PROXY_NAME:-ldap-policy-callout-v1}"
export POLICY_BASE_PATH="${POLICY_BASE_PATH:-/v1/ldap-policy}"

# ------------------------------------------------------------------------------
# 3. Dynamic Apigee Environment & Hostname Auto-Discovery via Apigee Management API
# ------------------------------------------------------------------------------
discover_apigee_topology() {
  local token="${APIGEE_TOKEN:-$(gcloud auth print-access-token 2>/dev/null || true)}"
  if [[ -z "${token}" ]]; then
    return 0
  fi

  local api_base="https://apigee.googleapis.com/v1/organizations/${APIGEE_ORG}"

  # 3A. Auto-discover APIGEE_ENV from /environments if not provided
  if [[ -z "${APIGEE_ENV:-}" ]]; then
    local envs_json
    envs_json="$(curl -sf -H "Authorization: Bearer ${token}" "${api_base}/environments" || echo "[]")"
    if command -v jq >/dev/null 2>&1; then
      APIGEE_ENV="$(echo "${envs_json}" | jq -r '.[0] // empty')"
    else
      APIGEE_ENV="$(echo "${envs_json}" | tr -d '[]" \n' | cut -d',' -f1)"
    fi
  fi
  export APIGEE_ENV="${APIGEE_ENV:-dev}"

  # 3B. Auto-discover APIGEE_HOSTNAME attached to APIGEE_ENV via /envgroups & /attachments
  if [[ -z "${APIGEE_HOSTNAME:-}" ]]; then
    local envgroups_json
    envgroups_json="$(curl -sf -H "Authorization: Bearer ${token}" "${api_base}/envgroups" || echo "{}")"

    if command -v jq >/dev/null 2>&1; then
      local groups
      groups="$(echo "${envgroups_json}" | jq -r '.environmentGroups[]?.name // empty')"
      for eg in ${groups}; do
        local attach_json matched_env
        attach_json="$(curl -sf -H "Authorization: Bearer ${token}" "${api_base}/envgroups/${eg}/attachments" || echo "{}")"
        matched_env="$(echo "${attach_json}" | jq -r --arg env "${APIGEE_ENV}" '.environmentGroupAttachments[]? | select(.environment == $env) | .environment' | head -n 1)"
        if [[ "${matched_env}" == "${APIGEE_ENV}" ]]; then
          APIGEE_HOSTNAME="$(echo "${envgroups_json}" | jq -r --arg eg "${eg}" '.environmentGroups[]? | select(.name == $eg) | .hostnames[0] // empty')"
          break
        fi
      done

      # Fallback to first available envgroup hostname if attachment lookup returned empty
      if [[ -z "${APIGEE_HOSTNAME:-}" ]]; then
        APIGEE_HOSTNAME="$(echo "${envgroups_json}" | jq -r '.environmentGroups[0].hostnames[0] // empty')"
      fi
    else
      APIGEE_HOSTNAME="$(echo "${envgroups_json}" | grep -o '"hostnames": *\[[^]]*\]' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/' || true)"
    fi
  fi
  export APIGEE_HOSTNAME="${APIGEE_HOSTNAME:-api.example.com}"
}

discover_apigee_topology
