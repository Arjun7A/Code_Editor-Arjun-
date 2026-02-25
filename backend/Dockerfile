FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ./app ./app

# Expose port (Render injects $PORT at runtime; default 10000)
EXPOSE ${PORT:-10000}

# Run the application – no --reload in production
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}
