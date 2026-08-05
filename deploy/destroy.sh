#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-agentbase}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-${SERVICE}-run}"

if [[ -z "$PROJECT_ID" ]]; then
  echo "Set PROJECT_ID, or run: gcloud config set project YOUR_PROJECT" >&2
  exit 1
fi

SA_EMAIL="${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "This will delete:"
echo "  Cloud Run service  ${SERVICE} (${REGION})"
echo "  Service account    ${SA_EMAIL}"
echo "  Project IAM        roles/aiplatform.user for that account"
echo "  Project            ${PROJECT_ID}"
read -r -p "Proceed? [y/N] " reply
[[ "$reply" =~ ^[Yy]$ ]] || exit 0

echo "==> Deleting Cloud Run service"
gcloud run services delete "$SERVICE" \
  --region "$REGION" --project "$PROJECT_ID" --quiet 2>/dev/null ||
  echo "    not found, skipping"

echo "==> Removing project IAM binding"
gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
  --member "serviceAccount:${SA_EMAIL}" \
  --role roles/aiplatform.user \
  --condition None >/dev/null 2>&1 || echo "    not bound, skipping"

echo "==> Deleting service account"
gcloud iam service-accounts delete "$SA_EMAIL" \
  --project "$PROJECT_ID" --quiet 2>/dev/null ||
  echo "    not found, skipping"

echo
echo "Done. APIs are left enabled; disable them manually if you want a full reset."
