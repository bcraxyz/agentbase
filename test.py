import json
import google.auth
from google.auth.transport.requests import AuthorizedSession

LOCATION = "global"
PROJECT_ID = ""
ENGINE_ID = ""
AGENT_ID = ""
PROMPT = ""

# Select the correct API endpoint based on the location
if LOCATION == "global":
    API_BASE = "discoveryengine.googleapis.com"
else:
    API_BASE = f"{LOCATION}-discoveryengine.googleapis.com"

API_ENDPOINT = (
    f"https://{API_BASE}/v1alpha/projects/{PROJECT_ID}/locations/{LOCATION}/"
    f"collections/default_collection/engines/{ENGINE_ID}/assistants/default_assistant:streamAssist"
)

credentials, project = google.auth.default()
authed_session = AuthorizedSession(credentials)

request_body = {
    "query": {"text": PROMPT},
    "filter": "",
    "fileIds": [],
    "answerGenerationMode": "AGENT",
    "assistSkippingMode": "REQUEST_ASSIST",
    "agentsConfig": {
        "agent": AGENT_ID
    },
    "agentsSpec": {
        "agentSpecs": [
            {"agentId": AGENT_ID}
        ]
    },
    "toolsSpec": {
        "vertexAiSearchSpec": {},
        "toolRegistry": "default_tool_registry",
        "imageGenerationSpec": {},
        "videoGenerationSpec": {},
        "webGroundingSpec": {}
    },
    "userMetadata": {
        "timeZone": "Asia/Singapore"
    }
}

response = authed_session.post(
    API_ENDPOINT,
    headers={"Content-Type": "application/json"},
    data=json.dumps(request_body)
)

output = ''
try:
    data_array = json.loads(response.text)
    for data in data_array:
        if data.get('answer', {}).get('state') == 'IN_PROGRESS':
            content = data['answer']['replies'][-1]['groundedContent'].get('content', {})
            if not content.get('thought', False):
                streaming_response = content.get('text', '')
                if streaming_response:
                    output += streaming_response
                    print(streaming_response)
except Exception as e:
    print(f"Error: {e}")
