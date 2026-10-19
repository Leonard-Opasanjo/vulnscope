FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY vulnscope ./vulnscope
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 1000 app \
    && mkdir -p /data && chown app:app /data
USER app
ENV VULNSCOPE_DB=/data/vulnscope.db
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["vulnscope", "serve", "--host", "0.0.0.0"]
