FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libpq-dev && rm -rf /var/lib/apt/lists/*
COPY xct_server_requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir ecdsa
RUN mkdir -p /app/static
COPY . .
RUN chmod +x /app/start.sh
EXPOSE 8001
CMD ["/app/start.sh"]
