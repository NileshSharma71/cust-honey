# Dockerfile (honeypot, attacker account = admin:PASSWORD)
FROM python:3.10-slim

# Install minimal deps + openssh-server for attacker access
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    netcat-openbsd \
    openssh-server \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create non-root runtime user for the app
RUN groupadd -r honeypot && useradd -r -g honeypot -d /home/honeypot -s /bin/bash honeypot \
    && mkdir -p /home/honeypot && chown -R honeypot:honeypot /home/honeypot

# Create attacker-visible account (container-only). Change these to what you want.
RUN useradd -m -s /bin/bash admin && echo 'admin:PASSWORD' | chpasswd

# Copy requirements & install
COPY --chown=honeypot:honeypot requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files and ensure ownership
COPY --chown=honeypot:honeypot cust_honey.py main.py ./
RUN mkdir -p /app/logs /app/static && chown -R honeypot:honeypot /app/logs /app/static

# Prepare sshd
RUN mkdir -p /var/run/sshd \
    && sed -i 's/#ListenAddress.*/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config || true \
    && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true \
    && sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true

# Expose container SSH port
EXPOSE 22

# Entrypoint that starts sshd then runs your app as non-root
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONUNBUFFERED=1
USER root
ENTRYPOINT ["/entrypoint.sh"]
