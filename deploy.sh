#!/usr/bin/env bash
# ==============================================================================
# deploy.sh: Master End-to-End Orchestrator
#   1. scripts/01-setup-gcp.sh       (APIs, Cloud Run Runtime SA, Apigee Invoker SA, IAM)
#   2. scripts/02-deploy-cloudrun.sh (Private Cloud Run + Custom OIDC Audience + run.invoker)
#   3. scripts/03-deploy-apigee.sh   (Auto-discover Env/Host, Encrypted KVM, Deploy Proxies via AFT)
# ==============================================================================
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

chmod +x "${REPO_ROOT}/scripts/"*.sh "${REPO_ROOT}/test.sh" 2>/dev/null || true

"${REPO_ROOT}/scripts/01-setup-gcp.sh" "$@"
"${REPO_ROOT}/scripts/02-deploy-cloudrun.sh" "$@"
"${REPO_ROOT}/scripts/03-deploy-apigee.sh" "$@"

echo ""
echo "🎉 Full End-to-End Deployment Complete!"
echo "👉 Run './test.sh' to execute the 9 end-to-end verification tests."
