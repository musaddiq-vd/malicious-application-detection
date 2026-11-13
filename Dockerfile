FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MALDETECT_HOST=0.0.0.0 \
    MALDETECT_PORT=8000 \
    MALDETECT_DB=/data/maldetect.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY maldetect ./maldetect
COPY web ./web
COPY models ./models
COPY data ./data

# Run as an unprivileged user; the SQLite database lives on a mounted volume.
RUN useradd --create-home appuser && mkdir /data && chown appuser /data
USER appuser
VOLUME /data
EXPOSE 8000

CMD ["python", "-m", "maldetect"]
