import os
import json
import uuid
import dotenv
import streamlit as st
import vertexai 
from vertexai import agent_engines
from google.auth.transport import requests
from google.oauth2 import id_token

dotenv.load_dotenv()

def validate_iap_jwt(iap_jwt, expected_audience):
    """
    Validate and decode IAP JWT token.
    Returns user email if valid, None otherwise.
    """
    try:
        if not iap_jwt:
            return None
        
        if not expected_audience:
            raise Exception("IAP_AUDIENCE not configured")
            
        decoded_token = id_token.verify_oauth2_token(
            iap_jwt,
            requests.Request(),
            audience=expected_audience
        )
        
        return decoded_token.get("email")
    except Exception as e:
        raise Exception(f"JWT validation failed: {e}")

def get_authenticated_user():
    """
    Extract authenticated user from IAP headers using st.context.
    Falls back to development mode if IAP headers not present.
    """
    if os.getenv("ENVIRONMENT") == "development":
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

def init_vertex(project, location):
    """Initialize Vertex AI with project and location."""
    vertexai.init(project=project, location=location)

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
    try:
        agent = agent_engines.get(agent_resource)
        
        # Use a session key that combines user and agent
        session_key = get_user_session_key(user_email, agent_resource)
        
        # Check if we have an existing session for this user-agent combo
        if session_key not in st.session_state.agent_sessions:
            # Create new session
            session = agent.create_session(user_id=user_email)
            session_id = f"{agent_resource}/sessions/{session['id']}"
            st.session_state.agent_sessions[session_key] = session_id
        else:
            session_id = st.session_state.agent_sessions[session_key]
        
        # Stream response from agent
        response_text = ""
        for response in agent.stream_query(
            user_id=user_email,
            session_id=session_id,
            message=message,
        ):
            if hasattr(response, 'text') and response.text:
                response_text += response.text
                
        return response_text
    except Exception as e:
        raise Exception(f"Error chatting with agent: {str(e)}")

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

def reset_conversation(user_email, agent_resource):
    """Reset the conversation session for current user and agent."""
    session_key = get_user_session_key(user_email, agent_resource)
    if session_key in st.session_state.agent_sessions:
        del st.session_state.agent_sessions[session_key]
    
    # Clear chat messages for this agent
    messages_key = f"messages_{agent_resource}"
    if messages_key in st.session_state:
        st.session_state[messages_key] = []

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
    
    # Display authenticated user
    st.success(f"👤 **Logged in as:**  \n{authenticated_user}")

    # Logout button - clears all sessions and state
    if st.button("🚪 Logout", use_container_width=True, type="secondary"):
        # Clear all session state
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        
        # In production with IAP, redirect to IAP logout URL
        if os.getenv("ENVIRONMENT") != "dev":
            st.info("To fully logout, close your browser or clear cookies for this domain.")
        
        st.rerun()
    
    # Google Cloud configuration
    st.subheader("☁️ GCP Configuration")
    
    project = st.text_input(
        "Project ID", 
        value=os.getenv("GOOGLE_CLOUD_PROJECT", ""),
        placeholder="your-gcp-project-id",
        help="Your Google Cloud Project ID"
    )
    
    location = st.text_input(
        "Location", 
        value=os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1"),
        placeholder="your-gcp-region",
        help="Your Google Cloud Region for Vertex AI"
    )

    agents = {}
    selected_agent = None
    
    # Initialize Vertex AI if credentials provided
    if project and location:
        if "vertex_initialized" not in st.session_state or \
            st.session_state.get("project") != project or \
            st.session_state.get("location") != location:
            try:
                init_vertex(project, location)
                st.session_state.vertex_initialized = True
                st.session_state.project = project
                st.session_state.location = location
            except Exception as e:
                st.error(f"Failed to initialize Vertex AI: {e}")
                st.session_state.vertex_initialized = False
        
        if st.session_state.get("vertex_initialized"):
            st.subheader("🎯 Agent Selection")
            
            agents = list_agents()        
            if agents:
                selected_agent = st.selectbox(
                    "Available Agents",
                    list(agents.keys()),
                    index=0,
                    help="Select an agent to chat with"
                )
                
                # Reset conversation button
                if selected_agent:
                    if st.button("🔄 Reset Conversation", use_container_width=True):
                        reset_conversation(authenticated_user, agents[selected_agent])
                        st.rerun()
            else:
                st.warning("⚠️ No agents found in this project/location")
    else:
        st.warning("⚠️ Please configure Google Cloud Project ID and Location")

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

# Display agent info
with st.expander("ℹ️ Agent Information", expanded=False):
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Agent Name:**", selected_agent)
        st.write("**User:**", authenticated_user)
    with col2:
        st.write("**Project:**", project)
        st.write("**Location:**", location)

# Display chat history
for message in st.session_state[messages_key]:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("Ask anything..."):
    # Add user message to chat
    st.session_state[messages_key].append({"role": "user", "content": prompt})
    
    with st.chat_message("user"):
        st.markdown(prompt)

    # Get agent response
    with st.chat_message("assistant"):
        with st.spinner("🤔 Thinking..."):
            try:
                response_text = chat_with_agent(
                    agent_resource=agent_resource,
                    message=prompt,
                    user_email=authenticated_user
                )
                
                st.session_state[messages_key].append({
                    "role": "assistant", 
                    "content": response_text
                })
                st.markdown(response_text)
                
            except Exception as e:
                error_msg = f"❌ Error: {str(e)}"
                st.error(error_msg)
                st.session_state[messages_key].append({
                    "role": "assistant", 
                    "content": error_msg
                })
