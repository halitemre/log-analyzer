FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir requests==2.34.1

COPY aggregator/ aggregator/
COPY analyze.py .

ENTRYPOINT ["python", "analyze.py"]
