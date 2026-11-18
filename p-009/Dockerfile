FROM python:3.12.14-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
LABEL io.p009.owner=p009
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src:/opt/site
WORKDIR /app
COPY --chown=1000:1000 .venv/lib/python3.12/site-packages /opt/site
COPY --chown=1000:1000 src /app/src
COPY --chown=1000:1000 config /app/config
USER 1000:1000
CMD ["python", "-m", "p009.service"]
