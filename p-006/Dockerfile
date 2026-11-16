FROM python:3.12.14-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
WORKDIR /app
COPY requirements.lock /app/requirements.lock
COPY .tools/wheels /wheels
RUN pip install --no-index --find-links=/wheels --require-hashes -r requirements.lock && rm -rf /wheels
ARG P006_LOCK_SHA
LABEL io.p006.owner="p006" io.p006.requirements="$P006_LOCK_SHA"
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 1000:1000
ENTRYPOINT ["python", "-m", "p006.entrypoint"]
