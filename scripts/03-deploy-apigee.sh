#!/usr/bin/env bash
# ==============================================================================
# 03-deploy-apigee.sh: Provision Encrypted KVM & Deploy Both Apigee Proxies via AFT
#   - Auto-discovers APIGEE_ENV and APIGEE_HOSTNAME via Apigee Management API
#   - Creates Encrypted Environment KVM (${KVM_NAME})
#   - Renders & deploys Proxy 1: ldap-admin-v1 (KVM + Cloud Run TargetEndpoint)
#   - Renders & deploys Proxy 2: ldap-policy-callout-v1 (ServiceCallout + GoogleIDToken)
# ==============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/00-env.sh
source "${SCRIPT_DIR}/00-env.sh" "$@"

CLOUD_RUN_URL="${CLOUD_RUN_URL:-$(gcloud run services describe "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --format="value(status.url)" 2>/dev/null || true)}"

if [[ -z "${CLOUD_RUN_URL}" ]]; then
  echo "❌ ERROR: Cloud Run service '${SERVICE_NAME}' not found in ${REGION}. Run ./scripts/02-deploy-cloudrun.sh first." >&2
  exit 1
fi

echo "=============================================================================="
echo " [Step 3/3] Deploying Apigee X Proxies via Apigee Templater (AFT)"
echo " Apigee Org            : ${APIGEE_ORG}"
echo " Discovered Env        : ${APIGEE_ENV}"
echo " Discovered Hostname   : ${APIGEE_HOST_DISPLAY:-${APIGEE_HOSTNAME}}"
echo " Encrypted KVM         : ${KVM_NAME}"
echo " Admin Proxy           : ${ADMIN_PROXY_NAME} (${ADMIN_BASE_PATH}) -> TargetEndpoint"
echo " Runtime Policy Proxy  : ${POLICY_PROXY_NAME} (${POLICY_BASE_PATH}) -> ServiceCallout"
echo " Cloud Run URL         : ${CLOUD_RUN_URL}"
echo " Custom OIDC Audience  : ${CUSTOM_AUDIENCE}"
echo " Proxy Service Account : ${INVOKER_SA_EMAIL}"
echo "=============================================================================="

TOKEN="${APIGEE_TOKEN:-$(gcloud auth print-access-token)}"

echo "🗄️  [3.1] Ensuring Encrypted Apigee Environment KVM '${KVM_NAME}' exists in '${APIGEE_ENV}'..."
curl -s -X POST "https://apigee.googleapis.com/v1/organizations/${APIGEE_ORG}/environments/${APIGEE_ENV}/keyvaluemaps" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"${KVM_NAME}\", \"encrypted\": true}" >/dev/null || true

BUILD_DIR="${REPO_ROOT}/apigee/.build"
mkdir -p "${BUILD_DIR}"

echo "📝 [3.2] Rendering AFT YAML definitions with Cloud Run URL and Custom Audience..."
sed \
  -e "s|__ADMIN_PROXY_NAME__|${ADMIN_PROXY_NAME}|g" \
  -e "s|__ADMIN_BASE_PATH__|${ADMIN_BASE_PATH}|g" \
  -e "s|__KVM_NAME__|${KVM_NAME}|g" \
  -e "s|__CLOUD_RUN_URL__|${CLOUD_RUN_URL}|g" \
  -e "s|__CUSTOM_AUDIENCE__|${CUSTOM_AUDIENCE}|g" \
  "${REPO_ROOT}/apigee/ldap-admin-proxy.template.yaml" > "${BUILD_DIR}/${ADMIN_PROXY_NAME}.aft.yaml"

sed \
  -e "s|__POLICY_PROXY_NAME__|${POLICY_PROXY_NAME}|g" \
  -e "s|__POLICY_BASE_PATH__|${POLICY_BASE_PATH}|g" \
  -e "s|__CLOUD_RUN_URL__|${CLOUD_RUN_URL}|g" \
  -e "s|__CUSTOM_AUDIENCE__|${CUSTOM_AUDIENCE}|g" \
  "${REPO_ROOT}/apigee/ldap-policy-proxy.template.yaml" > "${BUILD_DIR}/${POLICY_PROXY_NAME}.aft.yaml"

echo "📦 [3.3] Resolving Apigee Feature Templater ('aft') CLI..."
if ! command -v aft >/dev/null 2>&1 && [[ ! -x "${REPO_ROOT}/aft" ]]; then
  echo "   -> Downloading 'aft' binary..."
  OS_ARCH="linux-x64"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    OS_ARCH="darwin-$(uname -m | sed 's/x86_64/x64/')"
  fi
  curl -sL "https://github.com/apigee/apigee-templater/releases/latest/download/aft-${OS_ARCH}" -o "${REPO_ROOT}/aft"
  chmod +x "${REPO_ROOT}/aft"
fi
AFT_BIN="$(command -v aft 2>/dev/null || echo "${REPO_ROOT}/aft")"

echo "🚀 [3.4] Deploying Admin Proxy '${ADMIN_PROXY_NAME}' (KVM + Cloud Run TargetEndpoint)..."
"${AFT_BIN}" -i "${BUILD_DIR}/${ADMIN_PROXY_NAME}.aft.yaml" -o "${BUILD_DIR}/${ADMIN_PROXY_NAME}.zip" --no-anim
"${AFT_BIN}" -i "${BUILD_DIR}/${ADMIN_PROXY_NAME}.aft.yaml" \
  -o "${APIGEE_ORG}:${ADMIN_PROXY_NAME}:${APIGEE_ENV}:${INVOKER_SA_EMAIL}" \
  -t "${TOKEN}" --no-anim

echo "🚀 [3.5] Deploying Runtime LDAP Policy Proxy '${POLICY_PROXY_NAME}' (Cloud Run ServiceCallout)..."
"${AFT_BIN}" -i "${BUILD_DIR}/${POLICY_PROXY_NAME}.aft.yaml" -o "${BUILD_DIR}/${POLICY_PROXY_NAME}.zip" --no-anim
"${AFT_BIN}" -i "${BUILD_DIR}/${POLICY_PROXY_NAME}.aft.yaml" \
  -o "${APIGEE_ORG}:${POLICY_PROXY_NAME}:${APIGEE_ENV}:${INVOKER_SA_EMAIL}" \
  -t "${TOKEN}" --no-anim

echo ""
echo "✅ [Step 3/3] Both Apigee Proxies deployed to environment '${APIGEE_ENV}':"
echo "   -> Admin Proxy Endpoint   : https://${APIGEE_HOSTNAME}${ADMIN_BASE_PATH}/providers"
echo "   -> Runtime Policy Endpoint: https://${APIGEE_HOSTNAME}${POLICY_BASE_PATH}"
