# Imagen base
FROM python:3.10-slim

# Evitar pyc y usar buffering
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Cloud Run usa esta variable, por si acaso
ENV PORT=8080

# Crear directorio
WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

# Copiar código
COPY . .

# Exponer puerto correcto
EXPOSE 8080

# Comando final: migraciones + gunicorn (producción)
CMD ["sh", "-c", "python manage.py migrate && gunicorn pcbackend.wsgi:application --bind 0.0.0.0:$PORT"]
