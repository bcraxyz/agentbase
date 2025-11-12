import json
import google.auth
from google.api_core import exceptions
from google.cloud import discoveryengine_v1
from google.cloud.discoveryengine_v1 import types

LOCATION = "global"
PROJECT_ID = ""
ENGINE_ID = ""
AGENT_ID = ""
ASSISTANT_NAME = f"projects/{PROJECT_ID}/locations/{LOCATION}/collections/default_collection/engines/{ENGINE_ID}/assistants/default_assistant"
PROMPT = ""

# Select the correct API endpoint based on the location
if LOCATION == "global":
    API_BASE = "discoveryengine.googleapis.com"
else:
    API_BASE = f"{LOCATION}-discoveryengine.googleapis.com"

client = discoveryengine_v1.AssistantServiceClient(
    client_options={
        'api_endpoint': API_BASE
    }
)

#web_risk_agent_spec = types.StreamAssistRequest.AgentsSpec.AgentSpec(
#    agent_id=AGENT_ID
#)

#agents_spec = types.StreamAssistRequest.AgentsSpec(
#    agent_specs=[web_risk_agent_spec]
#)

#tools_spec = types.StreamAssistRequest.ToolsSpec()

request = discoveryengine_v1.StreamAssistRequest(
    name=ASSISTANT_NAME, 
    query={'text': PROMPT}
)

try:
    stream = client.stream_assist(request=request)
    output = ''
    for response in stream:
        if response.answer.state == types.AssistAnswer.State.IN_PROGRESS:
            streaming_response = response.answer.replies[-1].grounded_content.content.text
            output += streaming_response
            print(streaming_response)

except exceptions.PermissionDenied as e:
    print(f'Permission Denied: {e.message}')
    print(
        "Please ensure your account has the required 'discoveryengine.sessions.streamAssist' permission."
    )
except exceptions.InvalidArgument as e:
    print(f'Invalid Argument: {e.message}')
    print(
        'Please check that your project_id, location, and engine_id are correct.'
    )
except Exception as e:
    print(f'An unexpected error occurred: {e}')
