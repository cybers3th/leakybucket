FROM docker.io/library/python:3.14-slim@sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY requirements/observe-py314.lock /app/requirements/observe-py314.lock
COPY firewall ./firewall
RUN python -m pip install --no-cache-dir --require-hashes -r requirements/observe-py314.lock && \
    python -m pip install --no-cache-dir --no-deps . && \
    useradd --uid 10001 --create-home leakybucket && \
    mkdir /data && chown 10001:10001 /data
COPY deploy/policy.yaml /app/policy.yaml
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=2)"
ENTRYPOINT ["leakybucket", "start"]
CMD ["--foreground", "--policy", "/app/policy.yaml", "--bootstrap-dir", "/data"]
