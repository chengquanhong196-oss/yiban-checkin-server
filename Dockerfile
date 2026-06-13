FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Generate Fernet key if not provided
RUN python3 -c "from cryptography.fernet import Fernet; print('CREDENTIAL_ENCRYPTION_KEY=' + Fernet.generate_key().decode())" > /app/.env.example

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
