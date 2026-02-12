FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md alembic.ini /app/
COPY alembic /app/alembic
COPY agent /app/agent
COPY core /app/core
COPY server /app/server
COPY shared /app/shared

RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir .

EXPOSE 8000
CMD ["python", "-m", "server", "run"]
