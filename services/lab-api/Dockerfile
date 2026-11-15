FROM python:3.12.14-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY services/lab-api/requirements.lock /app/requirements.lock
COPY .tools/wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels --require-hashes -r requirements.lock && rm -rf /wheels
COPY --chmod=0444 services/common/app.py /app/app.py
USER 10001:10001
EXPOSE 8080
CMD ["python", "app.py"]
