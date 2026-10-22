# Build UI
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Runtime — Python only
FROM python:3.12-slim
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
COPY start.py ./start.py
COPY --from=ui /ui/dist ./backend/app/web

EXPOSE 8000
CMD ["python", "start.py", "--host", "0.0.0.0", "--port", "8000", "--no-browser"]
