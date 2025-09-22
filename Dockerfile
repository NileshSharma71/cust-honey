# Dockerfile for cust_honey honeypot (improved)
FROM python:3.10-slim

# Install minimal system deps (only what's necessary)
# If you need to build binary wheels (cryptography, paramiko deps), uncomment the build-deps block below.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# create runtime user early so we can use --chown when copying files
RUN groupadd -r honeypot && useradd -r -g honeypot -d /home/honeypot -s /usr/sbin/nologin honeypot

# copy requirements & install
COPY --chown=honeypot:honeypot requirements.txt ./

# If pip install fails for packages that need compilation (e.g. cryptography),
# uncomment the next block, rebuild, then comment it out again to slim the image.
#
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     build-essential libssl-dev libffi-dev python3-dev \
#     && pip install --no-cache-dir -r requirements.txt \
#     && apt-get remove -y build-essential python3-dev libssl-dev libffi-dev \
#     && apt-get autoremove -y \
#     && rm -rf /var/lib/apt/lists/*

# Normal fast path when build deps aren't required
RUN pip install --no-cache-dir -r requirements.txt

# copy application files and set ownership to honeypot user
COPY --chown=honeypot:honeypot cust_honey.py main.py ./

# create folders with correct ownership
RUN mkdir -p /app/logs /app/static && chown -R honeypot:honeypot /app/logs /app/static

# switch to non-root user
USER honeypot

# make Python output unbuffered (helps 'docker logs' show output immediately)
ENV PYTHONUNBUFFERED=1
ENV PORTS=2222
ENV BIND_ADDR=0.0.0.0

EXPOSE 2222

CMD ["python", "main.py"]
