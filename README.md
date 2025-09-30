# Cust-Honey — Lightweight SSH Honeypot

> **Cust-Honey** — a focused SSH honeypot that captures attacker interactions and writes structured logs for later analysis and correlation (e.g., with Dionaea/Glastopf + ELK). This repository contains the custom honeypot I’ve built and is intended to be simple to run, inspect, and extend.

---

## Status

**Work-in-progress / actively maintained.**

This repo is under active development — I am currently fixing a few minor issues and refining the fake shell behavior.

If you clone this repo, expect the current code to work for testing and development, but consider it experimental for long-term production use until the pending fixes are merged.

---

## Why this project exists

Honeypots are useful to observe attacker behavior in the wild. Cust-Honey is deliberately minimal so you can:

* Deploy quickly in Docker.
* Collect structured logs for later correlation in ELK or other pipelines.
* Extend services (SSH is the initial target) and improve realism over time.

---

## Features (current)

* Lightweight SSH listener (default port `2222`).
* Basic authentication handling with configurable credentials (via environment variables).
* Fake interactive shell that answers common commands (`ls`, `cat`, `whoami`, `tail`, `grep`, etc.).
* Separate rotating logs for credentials and commands for easier ingestion.
* Optional tarpit behavior (slow banner) per-port.
* Dockerfile and `docker-compose.yml` example for quick local deployment.

---

## Configuration

Configuration is done primarily via environment variables:

* `PORTS` — comma-separated list of ports to listen on (default: `2222`).
* `TARPIT_PORTS` — comma-separated list of ports to enable tarpit behavior on.
* `HP_USERNAME` / `HP_PASSWORD` — credentials that the honeypot accepts (leave empty to accept any credentials in the current build).
* `BIND_ADDR` — interface to bind on (default: `0.0.0.0`).

---

## Logging & ELK integration

* Two log files are produced under `/app/logs/`:

  * `creds_audits.log` — credential attempts in CSV-like lines.
  * `cmd_audits.log` — recorded commands and interactions.

* Recommended parsing: use Filebeat to harvest `./logs/*` and parse with Logstash or Elasticsearch ingest pipelines.

* Current code uses `RotatingFileHandler` (size-based). Consider switching to `TimedRotatingFileHandler` for day-aligned logs.

---

## Known issues & Limitations (WIP)

1. **Graceful shutdown** — listener threads currently run as daemon threads; sockets don’t always close cleanly.
2. **Env-driven credentials** — passing `HP_USERNAME`/`HP_PASSWORD` into `cust_honey` is partially wired and under refinement.
3. **Thread exhaustion risk** — thread per client; heavy load may exhaust resources.
4. **Prompt-toolkit attempt & PTY behavior** — tested `prompt_toolkit`, but attackers could edit the prompt string (e.g., `root@ubuntu`). A real PTY is needed for full realism.

---

## Future work / Roadmap

* **PTY-based fake shell (planned):** Implement a pseudo-TTY emulated shell for realistic behavior (protected prompt, cursor control). Sandbox command handling strictly.
* **Sandboxing / containment:** Add constrained shell execution inside a containerized or chroot-like environment.
* **Structured JSON logs:** Move to JSON logs for easier ingestion and searching.
* **Rate-limiting & connection caps:** Add connection limits and tarpit tuning.
* **Metrics & monitoring:** Prometheus metrics for connections, auth attempts, sessions.

---

## Security notes

* This honeypot is intentionally vulnerable. Isolate carefully.
* Avoid binding to privileged ports (e.g., `22`) unless you understand the risks.
* Keep host-mounted `./logs` and `./static` directories correctly owned and permissioned.

---

## License

MIT License — see `LICENSE`.
---
