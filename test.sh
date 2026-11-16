#!/usr/bin/env bash
# ==============================================================================
# test.sh: End-to-End Verification Suite
#   Uses dynamically discovered/configured APIGEE_HOSTNAME from scripts/00-env.sh
#   to verify:
#     1. LDAP Admin Proxy (ldap-admin-v1 -> Apigee KVM + Cloud Run TargetEndpoint)
#     2. Runtime LDAP Policy Proxy (ldap-policy-callout-v1 -> Cloud Run ServiceCallout)
#     3. Strict provider_id enforcement (400 Bad Request when x-ldap-provider is omitted)
# ==============================================================================
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/00-env.sh
source "${REPO_ROOT}/scripts/00-env.sh" "$@"

ADMIN_URL="https://${APIGEE_HOSTNAME}${ADMIN_BASE_PATH}"
POLICY_URL="https://${APIGEE_HOSTNAME}${POLICY_BASE_PATH}"

echo "=============================================================================="
echo " End-to-End Verification Suite"
echo " Discovered Apigee Env      : ${APIGEE_ENV}"
echo " Discovered Apigee Hostname : ${APIGEE_HOSTNAME}"
echo " Admin Proxy Endpoint       : ${ADMIN_URL}/providers"
echo " Runtime Policy Endpoint    : ${POLICY_URL}"
echo "=============================================================================="

echo "🔧 [Admin Test 1] List Initial LDAP Providers Before Onboarding 'forumsys-public'"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X GET "${ADMIN_URL}/providers"

echo "🔧 [Admin Test 2] Dynamically Register 'forumsys-public' (ldap://ldap.forumsys.com:389) via Admin Proxy (Saves to KVM + Warms Pool in Cloud Run)"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X POST "${ADMIN_URL}/providers" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "forumsys-public",
    "profile": "ORACLE",
    "user_login_attr": "uid",
    "urls": ["ldap://ldap.forumsys.com:389"],
    "base_dn": "dc=example,dc=com",
    "bind_dn": "cn=read-only-admin,dc=example,dc=com",
    "bind_password": "password",
    "default_require_group": "ou=scientists,dc=example,dc=com",
    "conn_timeout": "5s",
    "read_timeout": "5s"
  }'

echo "🔧 [Admin Test 3] Verify 'forumsys-public' is Registered & Active"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X GET "${ADMIN_URL}/providers?id=forumsys-public"

echo "=============================================================================="
echo " PART 2: RUNTIME LDAP POLICY PROXY WITH 'x-ldap-provider: forumsys-public' HEADER"
echo "=============================================================================="

echo "🌐 [Runtime Test 1] Authenticate Albert Einstein (einstein:password) via x-ldap-provider: forumsys-public (-> 200 OK)"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X GET "${POLICY_URL}/orders" \
  -H "x-ldap-provider: forumsys-public" \
  -u "einstein:password"

echo "🌐 [Runtime Test 2] Group Rejection for Leonhard Euler (euler:password is in mathematicians, not scientists -> 403 Forbidden)"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X GET "${POLICY_URL}/orders" \
  -H "x-ldap-provider: forumsys-public" \
  -u "euler:password"

echo "🌐 [Runtime Test 3] Invalid Password against forumsys-public (einstein:wrongpass -> 401 Unauthorized)"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X GET "${POLICY_URL}/orders" \
  -H "x-ldap-provider: forumsys-public" \
  -u "einstein:wrongpass"

echo "🌐 [Runtime Test 4] Query LDAP Operation for Nikola Tesla (?username=tesla) via x-ldap-provider: forumsys-public (-> 200 OK)"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X GET "${POLICY_URL}/query?username=tesla" \
  -H "x-ldap-provider: forumsys-public"

echo "=============================================================================="
echo " PART 3: STRICT PROVIDER_ID ENFORCEMENT & ENTERPRISE DIRECTORY TESTS"
echo "=============================================================================="

echo "🚫 [Runtime Test 5] Omitting 'x-ldap-provider' Header is Strictly Rejected (-> 400 Bad Request: provider_id is required)"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X GET "${POLICY_URL}/orders" \
  -u "jdoe:SecretPassword123"

echo "🧪 [Runtime Test 6] Authenticate jdoe with Explicit Header 'x-ldap-provider: ldap-policy-service' (-> 200 OK)"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X GET "${POLICY_URL}/orders" \
  -H "x-ldap-provider: ldap-policy-service" \
  -u "jdoe:SecretPassword123"

echo "🧪 [Runtime Test 7] Nested AD Group Resolution 1.2.840.113556.1.4.1941 (carlos.ruiz -> 200 OK)"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X GET "${POLICY_URL}/orders" \
  -H "x-ldap-provider: ldap-policy-service" \
  -u "carlos.ruiz:Enterprise2026!"

echo "🧪 [Runtime Test 8] Write LDAP Operation via LDIF inside Permitted Write Base DN (ou=Subscribers -> 200 OK)"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X POST "${POLICY_URL}/write?cn=jdoe&ou=Subscribers" \
  -H "x-ldap-provider: ldap-policy-service" \
  -H "x-new-phone: +34-91-777-8899"

echo "🧪 [Runtime Test 9] Write LDAP Operation Blocked by Write Base DN Security Boundary (ou=Admins -> 403 Forbidden)"
curl -ks -w "\nHTTP Status: %{http_code}\n\n" -X POST "${POLICY_URL}/write?cn=jdoe&ou=Admins" \
  -H "x-ldap-provider: ldap-policy-service" \
  -H "x-new-phone: +34-91-000-0000"
