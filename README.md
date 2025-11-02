# Cust-Honey — Lightweight SSH Honeypot

Cust-Honey is a small, focused SSH honeypot that captures attacker interactions and writes structured logs for later analysis (for example: ELK). This repo contains the custom honeypot I built: lightweight, easy to run in Docker, and easy to extend.

Status: **Work-in-progress / actively maintained.**

Expect this code to be experimental — it's suitable for testing and development. For long-term production use, treat this as a starting point and follow the security notes.

---

## Why this project exists
Honeypots let you observe attacker behaviour in the wild. Cust-Honey is deliberately minimal so you can:
- Deploy quickly in Docker.
- Collect structured logs for later correlation.
- Extend services (SSH is the initial target) and improve realism over time.

---

## Features (current)
- Lightweight SSH listener (container listens on port `22`; examples map host `2222` → container `22`).
- Basic authentication handling with configurable credentials via environment variables.
- Fake interactive shell that answers common commands (`ls`, `cat`, `whoami`, `tail`, `grep`, etc.).
- Separate rotating logs for credentials and commands for easier ingestion.
- Optional tarpit behavior (slow banner) per-port.
- Dockerfile + docker-compose example for quick local deployment.

---

## Quick start (recommended, safe)

1.  **Build:**
    ```bash
    docker build -t cust-honey .
    ```

2.  **Run (safe local mapping — host `2222` → container `22`):**
    ```bash
    docker run -d --name cust-honey \
      -p 2222:22 \
      -v /path/on/vm/cust-honey-logs:/app/logs \
      --read-only \
      --tmpfs /tmp:rw \
      --tmpfs /run:rw \
      --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
      --restart unless-stopped \
      cust-honey
    ```

3.  **Test locally:**
    ```bash
    ssh -p 2222 admin@localhost
    # password: set via HP_PASSWORD or default in entrypoint
    ```

### Expose as port 22 for attackers (options)
**Important:** If your host already runs SSH on port 22, do not bind container to 22 unless you move host SSH to another port first.
keep container on 2222 and redirect host 22 → 2222:
Run container on 2222:22 (see Quick start).
Add iptables PREROUTING redirect (replace eth0 with your external interface if necessary):
```bash
EXT_IF=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
sudo iptables -t nat -A PREROUTING -i "$EXT_IF" -p tcp --dport 22 -j REDIRECT --to-ports 2222
```


## License

MIT License — see `LICENSE`.

---
