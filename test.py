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
    "streamAssistRequest": {
        "query": {"parts": [{"text": PROMPT}]},
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
}

response = authed_session.post(
    API_ENDPOINT,
    headers={"Content-Type": "application/json"},
    data=json.dumps(request_body)
)
print(response.text)
print("--- Streaming Response ---")
full_model_output = ""
final_answer_data = None

try:
    response_chunks = response.text.strip().split('\n')
    
    for chunk in response_chunks:
        if not chunk.strip():
            continue
            
        try:
            response_part = json.loads(chunk)
        except json.JSONDecodeError:
            continue 

        answer_data = response_part.get('answer', {})
        
        if answer_data.get('state') == 'IN_PROGRESS':
            try:
                streaming_text = answer_data['replies'][-1]['groundedContent']['content']['text']
                print(streaming_text, end="") 
                full_model_output += streaming_text
            except (KeyError, IndexError):
                pass 
        
        elif answer_data.get('state') == 'SUCCEEDED':
            final_answer_data = response_part
            
    print("\n--- End of Stream ---")

except Exception as e:
    print(f"\nAn error occurred during stream processing: {e}")
    sys.exit(1)
    
model_response_text = full_model_output

if final_answer_data:
    pass 

print('Final consolidated model response:', model_response_text)
