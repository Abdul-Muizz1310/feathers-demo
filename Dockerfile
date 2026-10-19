FROM python:3.12-slim

WORKDIR /app
# README.md and LICENSE are referenced by pyproject.toml (`readme`, `license-files`);
# without them `pip install .` fails metadata generation inside the image.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# alembic.ini + migrations are copied so `alembic upgrade head` (render.yaml
# preDeployCommand) can run inside this image, which has no uv.
COPY alembic.ini ./
COPY alembic ./alembic
RUN pip install --no-cache-dir .

# Run as an unprivileged user to limit blast radius of any app/dependency RCE.
RUN adduser --disabled-password --gecos "" app && chown -R app /app
USER app

EXPOSE 8000
# Behind Render's proxy: trust X-Forwarded-* so the client address is the caller's.
CMD ["uvicorn", "feathers_demo.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
