FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8475
CMD ["gunicorn", "-b", "0.0.0.0:8475", "-w", "1", "--threads", "8", "--timeout", "60", "app:app"]
