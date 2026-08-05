FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY .streamlit/ .streamlit/
COPY streamlit_app.py .

RUN useradd --create-home --uid 1000 app && chown -R app:app /app
USER app

EXPOSE 8080

CMD streamlit run streamlit_app.py \
    --server.port=$PORT \
    --server.address=0.0.0.0 \
    --server.headless=true
