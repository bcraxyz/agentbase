import os
import dotenv
import streamlit as st
import google.genai as genai

dotenv.load_dotenv()
MODEL = "gemini-2.5-flash-lite"

use_vertex = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "false").lower() == "true"

def get_client():
    if use_vertex:
        project = os.getenv("GOOGLE_CLOUD_PROJECT")
        location = os.getenv("GOOGLE_CLOUD_LOCATION")
        if not project or not location:
            raise EnvironmentError("Missing GOOGLE_CLOUD_PROJECT or GOOGLE_CLOUD_LOCATION environment variables.")
        return genai.Client(vertexai=True, project=project, location=location)

    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise EnvironmentError("Missing GOOGLE_API_KEY environment variable.")
    return genai.Client(api_key=api_key)

st.set_page_config(page_title="Agentbase", page_icon="🤖", initial_sidebar_state="auto")
with st.sidebar:
    st.title("💬 Agentbase")

if "messages" not in st.session_state:
    st.session_state.messages = []

if "genai_client" not in st.session_state:
    try:
        st.session_state.genai_client = get_client()
    except Exception as e:
        st.error(e)

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# User-Assistant chat interaction
if prompt := st.chat_input("Ask anything"):
    with st.chat_message("user"):
        st.markdown(prompt)
        st.session_state.messages.append({"role": "user", "content": prompt})

    with st.chat_message("assistant"):
        try:
            with st.spinner("Thinking..."):
                response = st.session_state.genai_client.models.generate_content(
                    model=MODEL,
                    contents=prompt,
                )
                st.markdown(response.text)
                st.session_state.messages.append({"role": "assistant", "content": response.text})
        except Exception as e:
            st.error(f"Error generating response: {e}")
            st.session_state.messages.append({"role": "assistant", "content": e})
            st.stop()
