# Agentbase

A Streamlit chat interface for agents deployed to [Vertex AI Agent Engine](https://cloud.google.com/vertex-ai/generative-ai/docs/agent-engine/overview), running on Cloud Run behind [Identity-Aware Proxy](https://cloud.google.com/iap/docs).

Agent Engine gives you an API and a console playground, but nothing you can hand to a colleague. Agentbase lists every agent deployed in a project, lets you pick one, and streams the conversation. Sessions are keyed by IAP-verified email and agent, so each user gets their own isolated conversation.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `GOOGLE_CLOUD_PROJECT` | yes | Project containing the deployed agents |
| `GOOGLE_CLOUD_LOCATION` | no | Defaults to `us-central1` |
| `IAP_AUDIENCE` | yes | `/projects/PROJECT_NUMBER/locations/REGION/services/SERVICE` for Cloud Run IAP, or `/projects/PROJECT_NUMBER/global/backendServices/BACKEND_SERVICE_ID` for a load balancer |
| `IAP_CERTS_URL` | no | Development only, see below |

The runtime service account needs `roles/aiplatform.user`.

## Deploy

```bash
PROJECT_ID=$(gcloud config get-value project)
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
REGION=us-central1
SERVICE=agentbase

gcloud beta services identity create --service=iap.googleapis.com

gcloud run deploy "$SERVICE" \
  --source . \
  --region "$REGION" \
  --no-allow-unauthenticated \
  --iap \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION},IAP_AUDIENCE=/projects/${PROJECT_NUMBER}/locations/${REGION}/services/${SERVICE}"

gcloud run services add-iam-policy-binding "$SERVICE" --region "$REGION" \
  --member "serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com" \
  --role roles/run.invoker
```

Then grant users `roles/iap.httpsResourceAccessor` on the service. If IAP has never been enabled in a project without an organization, enable it once from the Cloud Run console first.

## Local development

The app refuses to start without a valid IAP assertion, which you can't forge. `devauth.py` runs a local proxy that mints an ES256 JWT in the same shape, serves the matching public key, and injects the header — so the app's verification path runs for real rather than being bypassed.

```bash
pip install -r requirements-dev.txt

export GOOGLE_CLOUD_PROJECT=your-project
export IAP_AUDIENCE=/projects/1/locations/us-central1/services/agentbase
export IAP_CERTS_URL=http://localhost:8080/public_key

streamlit run streamlit_app.py --server.port 8501 --server.headless true &
python devauth.py
```

Browse to port 8080, not 8501 — traffic has to pass through the proxy for the header to be there. Set `DEVAUTH_EMAIL` to test as a different user.

`devauth.py` is a development tool. It only accepts a localhost upstream, and a deployed app should never have `IAP_CERTS_URL` set.
