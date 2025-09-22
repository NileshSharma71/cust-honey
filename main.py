# main.py
import os
import signal
import threading
import time
from typing import List

# import your honeypot() function from your module
# make sure ssh_honeypot.py exports a honeypot(address, port, username, password, tarpit=False)
from cust_honey import honey

# --------- Config helpers ---------
def parse_int_list(s: str, default: List[int] = None) -> List[int]:
    if not s:
        return default or []
    try:
        return [int(x.strip()) for x in s.split(",") if x.strip()]
    except Exception:
        return default or []

def parse_str_list(s: str) -> List[str]:
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]

# --------- Read configuration from environment ---------
# default ports if not provided
DEFAULT_PORTS = [2222]  # safe non-privileged default for testing

PORTS = parse_int_list(os.environ.get("PORTS", ""), DEFAULT_PORTS)
# e.g. export PORTS="2222,2200,2022"

# optional list of ports to enable tarpit mode on (comma separated)
TARPIT_PORTS = set(parse_int_list(os.environ.get("TARPIT_PORTS", ""), []))
# e.g. export TARPIT_PORTS="22,2200"

# optional username/password (single pair used for all honeypots) - or leave blank to accept any creds
HP_USERNAME = os.environ.get("HP_USERNAME", "admin")
HP_PASSWORD = os.environ.get("HP_PASSWORD", "PASSWORD")

# bind address
BIND_ADDR = os.environ.get("BIND_ADDR", "0.0.0.0")

# threads list for cleanup
threads = []
stop_event = threading.Event()

# --------- Signal handling for graceful shutdown ---------
def shutdown(signum, frame):
    print("[*] shutdown signal received, stopping listeners...")
    stop_event.set()

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

# --------- Worker starter ---------
def start_honeypot_thread(address: str, port: int, username, password, tarpit: bool):
    """
    Launches the honeypot() function in a daemon thread.
    """
    def target():
        try:
            honey(address, port, username, password, tarpit=tarpit)
        except Exception as e:
            print(f"[!] Exception in honeypot on port {port}: {e}")

    t = threading.Thread(target=target, name=f"honeypot-{port}", daemon=True)
    t.start()
    return t

# --------- Main launcher ---------
def main():
    print("[*] Starting honeypot main...")
    print(f"[*] Ports: {PORTS}")
    print(f"[*] Tarpit ports: {sorted(list(TARPIT_PORTS))}")
    print(f"[*] Bind address: {BIND_ADDR}")

    for p in PORTS:
        tarpit = p in TARPIT_PORTS
        t = start_honeypot_thread(BIND_ADDR, p, HP_USERNAME, HP_PASSWORD, tarpit)
        threads.append(t)
        time.sleep(0.1)  # small stagger to avoid simultaneous bind races

    # keep main alive until signal
    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown(None, None)

    print("[*] Waiting for threads to finish (they are daemon threads so will exit)...")
    # daemon threads exit when main exits; we can sleep briefly
    time.sleep(0.5)
    print("[*] Exiting.")

if __name__ == "__main__":
    main()
