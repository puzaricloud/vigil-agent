# Vigil server agent image: the single-file, standard-library agent plus the docker CLI (container states) and
# iproute2 (per-connection flows). Run it with the host root mounted read-only at /host; see README.md.
FROM python:3.13.16-alpine3.24
RUN apk add --no-cache docker-cli iproute2
COPY vigil-server-agent.py /usr/local/bin/vigil-server-agent
COPY docker-entrypoint.py /usr/local/bin/docker-entrypoint.py
ENV PYTHONUNBUFFERED=1 \
    VIGIL_URL=https://puzaricloud.in \
    VIGIL_PROC_ROOT=/host/proc
VOLUME ["/var/lib/vigil-agent"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
  CMD pgrep -f vigil-server-agent >/dev/null || exit 1
ENTRYPOINT ["python3", "/usr/local/bin/docker-entrypoint.py"]
