# Cust-Honey — Lightweight SSH Honeypot

Cust-Honey — a focused SSH honeypot that captures attacker interactions and writes structured logs for later analysis and correlation (e.g., with Dionaea/Glastopf + ELK). This repository contains the custom honeypot I’ve built and is intended to be simple to run, inspect, and extend.

# Status

Work-in-progress / actively maintained.

This repo is under active development — I am currently fixing a few minor issues  and refining the fake shell behavior.

If you clone this repo, expect the current code to work for testing and development, but consider it experimental for long-term production use until the pending fixes are merged.

# Why this project exists

Honeypots are useful to observe attacker behavior in the wild. Cust-Honey is deliberately minimal so you can:

Deploy quickly in Docker.

Collect structured logs for later correlation in ELK or other pipelines.

Extend services (SSH is the initial target) and improve realism over time.

# Features (current)

Lightweight SSH listener (default port 2222).

Basic authentication handling with configurable credentials (via environment variables).

Fake interactive shell that answers common commands (ls, cat, whoami, tail, grep, etc.).

Separate rotating logs for credentials and commands for easier ingestion.

Optional tarpit behavior (slow banner) per-port.

Dockerfile and docker-compose.yml example for quick local deployment.
