#!/bin/bash
set -e

# Start sshd for attacker logins
/usr/sbin/sshd

# ensure log dir permission
chown -R honeypot:honeypot /app/logs /app/static /home/honeypot || true

# Run the app as non-root honeypot user
exec su -s /bin/sh -c "python3 /app/main.py" honeypot
