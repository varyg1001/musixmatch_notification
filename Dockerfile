FROM python:3.11-slim

# Environment settings
ENV POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_CREATE=false \
    PATH="$POETRY_HOME/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install Poetry using the universal installer
RUN apt-get update && apt-get install -y curl \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && apt-get remove --purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy pyproject.toml and lock file
COPY pyproject.toml poetry.lock* /app/

# Install dependencies
RUN poetry install --no-root --only main

# Copy your app code
COPY . .

# Default command
CMD ["python", "main.py"]