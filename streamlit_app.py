import os
import uuid
import dotenv
import streamlit as st
import vertexai 
from vertexai import agent_engines

dotenv.load_dotenv()

def init_vertex(project, location):
    """Initialize Vertex AI"""
    vertexai.init(project=project, location=location)

def chat_with_agent(agent_resource, message, session_id=None, user_id="default_user"):
    """Send a message to the agent and get response"""
    try:
        agent = agent_engines.get(agent_resource)
        
        if not session_id:
            session = agent.create_session(user_id=user_id)
            session_id = session.name
        
        response = agent.query(
            session=session_id,
            query=message,
            user_id=user_id
        )
        
        return response.text, session_id
    except Exception as e:
        raise Exception(f"Error chatting with agent: {str(e)}")

def list_agents():
    """List available agents from Vertex AI"""
    try:
        agents_list = {}
        for agent in agent_engines.list():
            agents_list[agent.display_name] = agent.resource_name
        return agents_list
    except Exception as e:
        st.error(f"Error listing agents: {e}")
        return {}

st.set_page_config(page_title="Agentbase", page_icon="🤖", initial_sidebar_state="auto")

# Generate a unique user ID for this session
if "user_id" not in st.session_state:
    st.session_state.user_id = str(uuid.uuid4())

with st.sidebar:
    st.title("💬 Agentbase")

    project = st.text_input("Google Cloud Project ID", value=os.getenv("GOOGLE_CLOUD_PROJECT", ""), placeholder="your-gcp-project-id")
    location = st.text_input("Google Cloud Location", value=os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1"), placeholder="us-central1")

    agents = {}
    selected_agent = None
    
    if project and location:
        if "vertex_initialized" not in st.session_state or \
            st.session_state.get("project") != project or \
            st.session_state.get("location") != location:
            try:
                init_vertex(project, location)
                st.session_state.vertex_initialized = True
                st.session_state.project = project
                st.session_state.location = location
                if "agent_session_id" in st.session_state:
                    del st.session_state.agent_session_id
            except Exception as e:
                st.error(f"Error initializing Vertex AI: {e}")
                st.session_state.vertex_initialized = False
        
        if st.session_state.get("vertex_initialized"):
            agents = list_agents()        
            if agents:
                selected_agent = st.selectbox(
                    "Select Agent",
                    list(agents.keys()),
                    index=0
                )
            else:
                st.warning("No agents found in this project/location")
    else:
        st.warning("Please enter Google Cloud Project ID and Location")

# Initialize messages
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# User-Assistant chat interaction
if prompt := st.chat_input("Ask anything"):
    if not st.session_state.get("vertex_initialized"):
        st.error("Please configure Google Cloud Project and Location first")
        st.stop()
    
    if not selected_agent or not agents:
        st.error("Please select an agent from the sidebar")
        st.stop()
        
    with st.chat_message("user"):
        st.markdown(prompt)
        st.session_state.messages.append({"role": "user", "content": prompt})

    with st.chat_message("assistant"):
        try:
            with st.spinner("Thinking..."):
                agent_resource = agents[selected_agent]
                session_id = st.session_state.get("agent_session_id")

                response_text, new_session_id = chat_with_agent(
                    agent_resource=agent_resource,
                    message=prompt,
                    session_id=session_id,
                    user_id=st.session_state.user_id
                )

                st.session_state.agent_session_id = new_session_id
                
                st.session_state.messages.append({"role": "assistant", "content": response_text})
                st.rerun()
        except Exception as e:
            st.error(f"Error generating response: {e}")
            st.session_state.messages.append({"role": "assistant", "content": e})
            st.rerun()
