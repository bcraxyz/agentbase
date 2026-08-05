import os
import streamlit as st
import vertexai
from vertexai import agent_engines
from google.auth.transport import requests
from google.oauth2 import id_token

PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT", "")
LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
IAP_AUDIENCE = os.getenv("IAP_AUDIENCE", "")
IAP_CERTS_URL = os.getenv(
    "IAP_CERTS_URL", "https://www.gstatic.com/iap/verify/public_key"
)

st.set_page_config(
    page_title="Agentbase",
    page_icon="💬",
    layout="wide",
    initial_sidebar_state="expanded",
)


def get_authenticated_user():
    headers = st.context.headers
    if not headers:
        return None

    iap_jwt = headers.get("X-Goog-Iap-Jwt-Assertion")
    if not iap_jwt:
        return None

    try:
        decoded = id_token.verify_token(
            iap_jwt,
            requests.Request(),
            audience=IAP_AUDIENCE,
            certs_url=IAP_CERTS_URL,
        )
    except Exception:
        return None

    email = decoded.get("email")
    if email and ":" in email:
        email = email.split(":")[-1]
    return email


@st.cache_data(ttl=300, show_spinner=False)
def list_agents(project, location):
    return {a.display_name: a.resource_name for a in agent_engines.list()}


@st.cache_resource(show_spinner=False)
def get_agent(agent_resource):
    return agent_engines.get(agent_resource)


def stream_reply(agent_resource, message, user_email):
    agent = get_agent(agent_resource)
    session_key = f"{user_email}::{agent_resource}"

    session_id = st.session_state.agent_sessions.get(session_key)
    if session_id is None:
        session_id = agent.create_session(user_id=user_email)["id"]
        st.session_state.agent_sessions[session_key] = session_id

    for chunk in agent.stream_query(
        user_id=user_email, session_id=session_id, message=message
    ):
        if not isinstance(chunk, dict):
            continue
        for part in chunk.get("content", {}).get("parts", []):
            if isinstance(part, dict) and part.get("text"):
                yield part["text"]


missing = [
    name
    for name, value in (
        ("GOOGLE_CLOUD_PROJECT", PROJECT),
        ("IAP_AUDIENCE", IAP_AUDIENCE),
    )
    if not value
]
if missing:
    st.error(f"⛔ Not configured: {', '.join(missing)}")
    st.stop()

user_email = get_authenticated_user()
if not user_email:
    st.error("⛔ Authentication required")
    st.info("This application must be served behind Google Cloud IAP.")
    st.stop()

vertexai.init(project=PROJECT, location=LOCATION)

if "agent_sessions" not in st.session_state:
    st.session_state.agent_sessions = {}

with st.sidebar:
    st.title("💬 Agentbase")

    try:
        agents = list_agents(PROJECT, LOCATION)
    except Exception as e:
        st.error(f"⚠️ Could not list agents: {e}")
        st.stop()

    if not agents:
        st.warning(f"⚠️ No agents found in {PROJECT} / {LOCATION}")
        st.stop()

    selected_agent = st.selectbox("Agent", list(agents))
    agent_resource = agents[selected_agent]

    if st.button("🔄 Reset conversation", use_container_width=True):
        st.session_state.agent_sessions.pop(f"{user_email}::{agent_resource}", None)
        st.session_state[f"messages_{agent_resource}"] = []
        st.rerun()

    st.success(f"👤 **Logged in as:**  \n{user_email}")
    st.link_button(
        "➡️ Logout", "/_gcp_iap/clear_login_cookie", use_container_width=True
    )

messages_key = f"messages_{agent_resource}"
if messages_key not in st.session_state:
    st.session_state[messages_key] = []
messages = st.session_state[messages_key]

for message in messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if prompt := st.chat_input("Ask anything..."):
    messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        try:
            reply = st.write_stream(stream_reply(agent_resource, prompt, user_email))
            if not reply:
                st.warning("⚠️ No response received from agent")
        except Exception as e:
            reply = None
            st.error(f"❌ {e}")

    if reply:
        messages.append({"role": "assistant", "content": reply})
    else:
        messages.pop()
