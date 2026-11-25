# Sandbox image for the stand-in demo target and for candidate-patch test runs.
# Code is bind-mounted read-only at /app at run time (see security/sandbox.py),
# so original and patched trees swap without a rebuild.
FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.1.3 \
 && useradd --uid 10001 --no-create-home ksx
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 KSX_HOST=0.0.0.0 KSX_PORT=5001
WORKDIR /app
USER 10001
EXPOSE 5001
CMD ["python", "/app/app.py"]
