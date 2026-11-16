#!/usr/bin/env bash
# ==============================================================================
# 02-deploy-cloudrun.sh: Build & Deploy Private Cloud Run LDAP Connector
#   - Deploys from ./src with --no-allow-unauthenticated
#   - Attaches the dedicated Runtime Service Account (${RUNTIME_SA_EMAIL})
#   - Configures the Custom OIDC Audience (--custom-audiences="${CUSTOM_AUDIENCE}")
#   - Grants roles/run.invoker exclusively to the Apigee Invoker SA (${INVOKER_SA_EMAIL})
# ==============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/00-env.sh
source "${SCRIPT_DIR}/00-env.sh" "$@"

echo "=============================================================================="
echo " [Step 2/3] Deploying Private Cloud Run LDAP Connector"
echo " Service Name          : ${SERVICE_NAME}"
echo " Source Directory      : ${REPO_ROOT}/src"
echo " Custom OIDC Audience  : ${CUSTOM_AUDIENCE}"
echo " Runtime SA            : ${RUNTIME_SA_EMAIL}"
echo " Authorized Invoker SA : ${INVOKER_SA_EMAIL}"
echo "=============================================================================="

echo "🚀 [2.1] Building and deploying '${SERVICE_NAME}' to Cloud Run (${REGION})..."
gcloud run deploy "${SERVICE_NAME}" \
  --source="${REPO_ROOT}/src" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --platform=managed \
  --service-account="${RUNTIME_SA_EMAIL}" \
  --no-allow-unauthenticated \
  --ingress="${INGRESS_MODE}" \
  --set-custom-audiences="${CUSTOM_AUDIENCE}" \
  --set-env-vars="LDAP_PROVIDERS_CONFIG_PATH=/etc/ldap/providers.json" \
  --cpu=1 \
  --memory=256Mi \
  --min-instances=1 \
  --max-instances=10 \
  --concurrency=80 \
  --quiet

echo "🔒 [2.2] Enforcing Custom OIDC Audience '${CUSTOM_AUDIENCE}'..."
gcloud run services update "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --set-custom-audiences="${CUSTOM_AUDIENCE}" \
  --quiet

echo "🛡️  [2.3] Binding roles/run.invoker on '${SERVICE_NAME}' to ${INVOKER_SA_EMAIL}..."
gcloud run services add-iam-policy-binding "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --member="serviceAccount:${INVOKER_SA_EMAIL}" \
  --role="roles/run.invoker" \
  --quiet >/dev/null

CLOUD_RUN_URL="$(gcloud run services describe "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --format="value(status.url)")"
export CLOUD_RUN_URL

echo "✅ [Step 2/3] Private Cloud Run LDAP Connector deployed:"
echo "   -> Service URL      : ${CLOUD_RUN_URL}"
echo "   -> Custom Audience  : ${CUSTOM_AUDIENCE}"
echo "   -> Invoker Identity : ${INVOKER_SA_EMAIL}"
