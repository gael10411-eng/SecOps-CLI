FROM python:3.12-slim

# Imagen exclusiva para el laboratorio de pentesting.
# NO exponer a internet ni a ninguna red real.

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# La carpeta data/ se monta como volumen (docker-compose.yml).
RUN mkdir -p data/archivos

EXPOSE 5000

# gunicorn sirve la app en producción dentro del contenedor.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
