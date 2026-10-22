# =============================================================================
# CipherSong Web — Standalone FastAPI & Flet Web (PWA) Multi-Platform Container
# Pronto para deploy em produção: Fly.io / Render / Cloud Run
# =============================================================================
FROM python:3.12-slim

WORKDIR /app

# Instala dependências do sistema necessárias para compilação e rede
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copia e instala dependências Python limpas
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copia código-fonte e assets estáticos PWA
COPY ciphersong ./ciphersong
COPY assets ./assets
COPY backend_api.py ./backend_api.py

# Observabilidade e variáveis de ambiente
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

EXPOSE 8000

# Execução do Uvicorn com suporte a WebSockets/WSS, proxy headers e porta dinâmica
CMD ["sh", "-c", "uvicorn backend_api:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
