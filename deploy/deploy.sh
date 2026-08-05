#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-agentbase}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-${SERVICE}-run}"
USER_EMAIL="${USER_EMAIL:-$(gcloud config get-value account 2>/dev/null || true)}"

if [[ -z "$PROJECT_ID" ]]; then
  echo "Set PROJECT_ID, or run: gcloud config set project YOUR_PROJECT" >&2
  exit 1
fi

PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
SA_EMAIL="${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com"
IAP_SA="service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com"
AUDIENCE="/projects/${PROJECT_NUMBER}/locations/${REGION}/services/${SERVICE}"

IAP="gcloud iap"
gcloud iap web add-iam-policy-binding --help >/dev/null 2>&1 || IAP="gcloud beta iap"

echo "==> Enabling APIs"
gcloud services enable \
  run.googleapis.com \
  iap.googleapis.com \
  aiplatform.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  --project "$PROJECT_ID"

echo "==> Runtime service account: ${SA_EMAIL}"
gcloud iam service-accounts describe "$SA_EMAIL" --project "$PROJECT_ID" >/dev/null 2>&1 ||
  gcloud iam service-accounts create "$SERVICE_ACCOUNT" \
    --display-name "${SERVICE} Cloud Run runtime" \
    --project "$PROJECT_ID"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member "serviceAccount:${SA_EMAIL}" \
  --role roles/aiplatform.user \
  --condition None >/dev/null

echo "==> IAP service agent"
gcloud beta services identity create \
  --service=iap.googleapis.com --project "$PROJECT_ID" >/dev/null

echo "==> Deploying ${SERVICE} to ${REGION}"
gcloud run deploy "$SERVICE" \
  --source . \
  --region "$REGION" \
  --project "$PROJECT_ID" \
  --service-account "$SA_EMAIL" \
  --no-allow-unauthenticated \
  --iap \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION},IAP_AUDIENCE=${AUDIENCE}"

echo "==> Granting run.invoker to the IAP service agent"
gcloud run services add-iam-policy-binding "$SERVICE" \
  --region "$REGION" \
  --project "$PROJECT_ID" \
  --member "serviceAccount:${IAP_SA}" \
  --role roles/run.invoker >/dev/null

if [[ -n "$USER_EMAIL" ]]; then
  echo "==> Granting ${USER_EMAIL} access through IAP"
  $IAP web add-iam-policy-binding \
    --resource-type=cloud-run \
    --service="$SERVICE" \
    --region="$REGION" \
    --member="user:${USER_EMAIL}" \
    --role=roles/iap.httpsResourceAccessor \
    --project "$PROJECT_ID" >/dev/null
fi

URL=$(gcloud run services describe "$SERVICE" \
  --region "$REGION" --project "$PROJECT_ID" --format='value(status.url)')

echo
echo "URL:      ${URL}"
echo "Audience: ${AUDIENCE}"
echo
echo "If IAP has never been enabled in this project and the project has no"
echo "organization, enable it once from the Cloud Run console, then re-run."
