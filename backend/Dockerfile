FROM python:3.11-slim

# Set working directory — parent of the backend package
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install security scanning tools
RUN pip install bandit semgrep

# Install ESLint + security plugin for JavaScript scanning
RUN npm install -g eslint eslint-plugin-security

# Copy backend package into /app/backend/
COPY . ./backend/

# Expose port
EXPOSE 8000

# Run as non-root user
RUN useradd -r -s /bin/false appuser && chown -R appuser /app
USER appuser

# Run from /app so "backend" is importable as a package
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
