FROM python:3.12-slim

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 \
      --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp \
    HOME=/tmp

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app app.py .

USER app:app
EXPOSE 8475
CMD ["gunicorn", "-b", "0.0.0.0:8475", "-w", "1", "--threads", "8", "--timeout", "60", "--worker-tmp-dir", "/tmp", "app:app"]
