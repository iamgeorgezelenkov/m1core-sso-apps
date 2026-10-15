FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/iamgeorgezelenkov/m1core-sso-apps"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

USER 10001
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
