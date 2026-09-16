FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 scanner \
    && mkdir /work && chown scanner:scanner /work
USER scanner
WORKDIR /work
ENTRYPOINT ["awsherlock"]
CMD ["--help"]
