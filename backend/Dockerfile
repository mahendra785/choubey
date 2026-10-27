FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Never run the app as root inside the container.
RUN useradd --create-home --uid 1000 app
WORKDIR /app

ARG INSTALL_DEV=false
ARG INSTALL_ML=false
COPY requirements.txt requirements-dev.txt requirements-ml.txt ./
RUN pip install --no-cache-dir -r $([ "$INSTALL_DEV" = "true" ] && echo requirements-dev.txt || echo requirements.txt)  && if [ "$INSTALL_ML" = "true" ]; then pip install --no-cache-dir -r requirements-ml.txt --extra-index-url https://download.pytorch.org/whl/cpu; fi

COPY --chown=app:app . .
USER app

EXPOSE 8000
# Migrate, seed the admin (if ADMIN_* are set), then serve.
CMD ["sh", "-c", "alembic upgrade head && (python -m app.db.seed || true) && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
