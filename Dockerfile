FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PAYPAL_WEB_ALLOW_DEBUG_LOGS=0

WORKDIR /app

COPY requirements.txt requirements-headless.txt ./
RUN pip install --no-cache-dir -r requirements-headless.txt \
    && python -m playwright install --with-deps chromium

COPY . .
RUN mkdir -p /app/captures && chmod 700 /app/captures

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3).read()" || exit 1

CMD ["python", "web.py", "--host", "0.0.0.0", "--port", "8080"]
