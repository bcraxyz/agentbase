import os
import dotenv
import streamlit as st
import vertexai 
from vertexai import agent_engines
from google.auth.transport import requests
from google.oauth2 import id_token

dotenv.load_dotenv()

def validate_iap_jwt(iap_jwt, expected_audience):
    """
    Validate and decode IAP JWT token. Returns user email if valid, None otherwise.
    """
    try:
        if not iap_jwt:
            return None
        
        if not expected_audience:
            raise Exception("IAP_AUDIENCE not configured")

        iap_certs_url = "https://www.gstatic.com/iap/verify/public_key"
        decoded_token = id_token.verify_token(
            iap_jwt,
            requests.Request(),
            audience=expected_audience,
            certs_url=iap_certs_url
        )
        
        return decoded_token.get("email")
    except Exception as e:
        raise Exception(f"JWT validation failed: {e}")

def get_authenticated_user():
    """
    Extract authenticated user from IAP headers using st.context.
    Falls back to development mode if IAP headers not present.
    """
    if os.getenv("ENVIRONMENT") == "dev":
        return os.getenv("DEV_USER_EMAIL", "dev@example.com")
    
    try:
        headers = st.context.headers
        if headers is None:
            return None
        
        iap_jwt = headers.get("X-Goog-Iap-Jwt-Assertion")
        if not iap_jwt:
            return None
        
        expected_audience = os.getenv("IAP_AUDIENCE", "")
        if not expected_audience:
            st.error("IAP_AUDIENCE environment variable not set")
            return None
        
        return validate_iap_jwt(iap_jwt, expected_audience)
        
    except Exception as e:
        st.error(f"Error extracting IAP user: {e}")
        return None

def get_user_session_key(user_email, agent_resource):
    """
    Generate a unique session key for user-agent combination.
    This ensures session isolation between users and agents.
    """
    return f"{user_email}::{agent_resource}"

def chat_with_agent(agent_resource, message, user_email):
    """
    Send a message to the agent and get response.
    Sessions are now keyed by user email and agent resource.
    """
    agent = agent_engines.get(agent_resource)
    session_key = get_user_session_key(user_email, agent_resource)
    
    if session_key not in st.session_state.agent_sessions:
        session = agent.create_session(user_id=user_email)
        session_id = f"{agent_resource}/sessions/{session['id']}"
        st.session_state.agent_sessions[session_key] = session_id
    else:
        session_id = st.session_state.agent_sessions[session_key]
    
    response_stream = agent.stream_query(
        user_id=user_email,
        session_id=session_id,
        message=message,
    )
    
    for chunk in response_stream:
        if hasattr(chunk, "text") and chunk.text:
            yield chunk.text
        elif hasattr(chunk, "content") and chunk.content:
            yield chunk.content

def list_agents():
    """List available agents from Vertex AI Agent Engine."""
    try:
        agents_list = {}
        for agent in agent_engines.list():
            agents_list[agent.display_name] = agent.resource_name
        return agents_list
    except Exception as e:
        st.error(f"Error listing agents: {e}")
        return {}

def reset_conversation(user_email, agent_resource, history_key):
    """Reset the conversation session for current user and agent."""
    session_key = get_user_session_key(user_email, agent_resource)
    if session_key in st.session_state.agent_sessions:
        del st.session_state.agent_sessions[session_key]
    
    if history_key in st.session_state:
        st.session_state[history_key] = []

# Page configuration
st.set_page_config(
    page_title="Agentbase", 
    page_icon="💬", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Get authenticated user
authenticated_user = get_authenticated_user()

if not authenticated_user:
    st.error("⛔ Authentication Required")
    st.info("This application requires authentication via Google Cloud IAP. Please ensure IAP is properly configured.")
    st.stop()

# Initialize session state for agent sessions (keyed by user:agent)
if "agent_sessions" not in st.session_state:
    st.session_state.agent_sessions = {}

# Sidebar configuration
with st.sidebar:
    st.title("💬 Agentbase")
    
    # Google Cloud configuration
    with st.expander("**☁️ Google Cloud Settings**", expanded=False):
        project = st.text_input("Project ID", value=os.getenv("GOOGLE_CLOUD_PROJECT", ""), help="Your Google Cloud Project ID")        
        location = st.text_input("Location", value=os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1"), help="Your Google Cloud Region for Vertex AI")

    agents = {}
    selected_agent = None
    
    # Initialize Vertex AI if credentials provided
    if project and location:
        if "vertex_initialized" not in st.session_state or \
            st.session_state.get("project") != project or \
            st.session_state.get("location") != location:
            try:
                vertexai.init(project=project, location=location)
                st.session_state.vertex_initialized = True
                st.session_state.project = project
                st.session_state.location = location
            except Exception as e:
                st.error(f"Failed to initialize Vertex AI: {e}")
        
        if st.session_state.get("vertex_initialized"):
            with st.expander("**🎯 Agent Selection**", expanded=True):
                agents = list_agents()        
                if agents:
                    selected_agent = st.selectbox(
                        "Available Agents",
                        list(agents.keys()),
                        index=0,
                        help="Select an agent to chat with"
                    )
                    
                    if selected_agent:
                        if st.button("🔄 Reset Conversation", use_container_width=True):
                            reset_conversation(authenticated_user, agents[selected_agent], f"messages_{agents[selected_agent]}")
                            st.rerun()
                else:
                    st.warning("⚠️ No agents found")
    else:
        st.warning("⚠️ Please configure Project ID and Location")

    # Display authenticated user
    st.success(f"👤 **Logged in as:**  \n{authenticated_user}")

    # Logout button - clears all sessions and state
    if st.button("🚪 Logout", use_container_width=True, type="secondary"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        
        if os.getenv("ENVIRONMENT") != "dev":
            st.markdown(
                '<meta http-equiv="refresh" content="0;url=/_gcp_iap/clear_login_cookie">', 
                unsafe_allow_html=True
            )
        else:
            st.rerun()

# Main chat interface
if not st.session_state.get("vertex_initialized"):
    st.info("👈 Please configure Google Cloud Project and Location to get started.")
    st.stop()

if not selected_agent or not agents:
    st.info("👈 Please select an agent to start chatting.")
    st.stop()

agent_resource = agents[selected_agent]

# Initialize messages for this specific agent
messages_key = f"messages_{agent_resource}"
if messages_key not in st.session_state:
    st.session_state[messages_key] = []

# Display chat history
for message in st.session_state[messages_key]:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("Ask anything..."):
    st.session_state[messages_key].append({"role": "user", "content": prompt})
    
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        try:
            stream = chat_with_agent(
                agent_resource=agent_resource,
                message=prompt,
                user_email=authenticated_user
            )
            
            response_text = st.write_stream(stream)
            
            st.session_state[messages_key].append({
                "role": "assistant", 
                "content": response_text
            })
            
        except Exception as e:
            error_msg = f"❌ Error: {str(e)}"
            st.error(error_msg)
