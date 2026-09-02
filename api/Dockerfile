FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# data dir for SQLite + photos (will be volume-mounted)
RUN mkdir -p /app/data/photos \
    && adduser --disabled-password --no-create-home --gecos "" appuser \
    && chown -R appuser:appuser /app/data

USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
