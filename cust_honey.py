import os
import socket
import threading
import time
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import paramiko
import re

# ----------------------
# Constants & base paths
# ----------------------
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

# Hardcoded enforced credentials
ALLOWED_USERNAME = "admin"
ALLOWED_PASSWORD = "PASSWORD"

base_dir = Path(__file__).parent.resolve()

# Ensure static folder (for SSH host key)
static_dir = base_dir / "static"
static_dir.mkdir(parents=True, exist_ok=True)
server_key = static_dir / "server.key"

# Ensure logs folder
logs_dir = base_dir / "logs"
logs_dir.mkdir(parents=True, exist_ok=True)

# File paths inside logs/
CREDS_LOG = logs_dir / "creds_audits.log"
CMD_LOG = logs_dir / "cmd_audits.log"

# ----------------------
# Fake files for shell
# ----------------------
FAKE_SSHD_CONFIG = """# OpenSSH server configuration mock
Port 22
Protocol 2
# ListenAddress 0.0.0.0
PermitRootLogin prohibit-password
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
SyslogFacility AUTH
LogLevel INFO
"""

# A short fake auth.log with multiple lines to allow grep/tail/head
FAKE_AUTH_LOG = """Sep 21 09:55:01 ubuntu sshd[1023]: Accepted password for admin from 10.0.0.5 port 54812 ssh2
Sep 21 09:57:12 ubuntu sshd[1030]: Failed password for invalid user test from 10.0.0.9 port 55321 ssh2
Sep 21 09:58:31 ubuntu sshd[1035]: Accepted password for admin from 10.0.0.6 port 55233 ssh2
Sep 21 10:00:02 ubuntu sshd[1040]: pam_unix(sshd:session): session opened for user admin by (uid=0)
Sep 21 10:05:12 ubuntu sshd[1051]: Failed password for root from 10.0.0.12 port 55999 ssh2
Sep 21 10:10:22 ubuntu sshd[1058]: Accepted password for ubuntu from 10.0.0.7 port 56001 ssh2
Sep 21 10:15:00 ubuntu sshd[1064]: pam_unix(sshd:session): session closed for user admin
Sep 21 10:20:33 ubuntu sshd[1072]: Failed password for invalid user guest from 10.0.0.15 port 56112 ssh2
Sep 21 10:21:44 ubuntu sshd[1080]: Accepted password for admin from 10.0.0.5 port 54820 ssh2
Sep 21 10:30:00 ubuntu sshd[1100]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)
"""

def _lines_tail(text, n=10):
    lines = text.strip().splitlines()
    return lines[-n:]

def _lines_head(text, n=10):
    lines = text.strip().splitlines()
    return lines[:n]

def _grep_lines(text, pattern):
    if not pattern:
        return []
    lines = text.strip().splitlines()
    pat = pattern.strip().strip('"').strip("'")
    return [L for L in lines if pat in L]

# ----------------------
# Logging setup
# ----------------------
LOG_FMT = logging.Formatter(
    "%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Funnel (commands) logger
funnel_logger = logging.getLogger("FunnelLogger")
funnel_logger.setLevel(logging.INFO)
funnel_logger.handlers = []  # clear duplicate handlers if module reloaded
funnel_handler = RotatingFileHandler(str(CMD_LOG), maxBytes=5 * 1024 * 1024, backupCount=5)
funnel_handler.setFormatter(LOG_FMT)
funnel_logger.addHandler(funnel_handler)

# Credentials logger
creds_logger = logging.getLogger("CredsLogger")
creds_logger.setLevel(logging.INFO)
creds_logger.handlers = []
creds_handler = RotatingFileHandler(str(CREDS_LOG), maxBytes=5 * 1024 * 1024, backupCount=5)
creds_handler.setFormatter(LOG_FMT)
creds_logger.addHandler(creds_handler)

# Optional: console output while debugging
console = logging.StreamHandler()
console.setFormatter(LOG_FMT)
console.setLevel(logging.INFO)
funnel_logger.addHandler(console)
creds_logger.addHandler(console)

# ----------------------
# Ensure host key exists
# ----------------------
def ensure_host_key(path: Path):
    if path.exists():
        try:
            return paramiko.RSAKey(filename=str(path))
        except Exception:
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass

    creds_logger.info(f"Generating new SSH host key at {path}")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(path))
    try:
        os.chmod(str(path), 0o600)
    except Exception:
        pass
    return key

host_key = ensure_host_key(server_key)

# ----------------------
# Server interface
# ----------------------
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        # keep the passed-in values but we will enforce ALLOWED_* constants
        self.input_username = input_username
        self.input_password = input_password
        # will be set to the username that successfully authenticated
        self.authenticated_username = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        # log attempts (human-readable + CSV-like)
        funnel_logger.info(
            f"Client {self.client_ip} attempted connection with username: {username}, password: {password}"
        )
        creds_logger.info(f"{self.client_ip},{username},{password}")

        # Enforce the hardcoded allowed credentials
        if username == ALLOWED_USERNAME and password == ALLOWED_PASSWORD:
            self.authenticated_username = username
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def check_channel_exec_request(self, channel, command):
        # one-shot exec requests (ssh host "cmd")
        try:
            cmd = (
                command.decode("utf-8", errors="ignore")
                if isinstance(command, (bytes, bytearray))
                else str(command)
            )
        except Exception:
            cmd = "<unreadable>"
        funnel_logger.info(f"Client {self.client_ip} EXEC: {cmd}")
        creds_logger.info(f"{self.client_ip},EXEC,{cmd}")
        return True

# ----------------------
# Helper to skip ANSI/CSI escape sequences
# ----------------------
CSI_RE = re.compile(rb'\x1b\[[0-9;?]*[A-Za-z]')

def _skip_escape_sequence(data: bytes, start: int) -> int:
    """
    Given raw data and index at an ESC (27), return the index after skipping a
    likely escape/CSI sequence. This is a conservative skip: it advances until
    it sees a terminating ASCII letter or runs out of bytes.
    """
    i = start
    ln = len(data)
    # if next byte suggests CSI or 'O' style
    if i + 1 < ln and data[i + 1] in (ord('['), ord('O')):
        j = i + 2
        while j < ln and not (65 <= data[j] <= 122):  # A..z
            j += 1
        if j < ln:
            return j + 1
        return j
    # fallback: skip single ESC
    return i + 1

# ----------------------
# Fake interactive shell
# ----------------------
def emulated_shell(channel, client_ip, username=None, prompt="root@ubuntu:~# "):
    """
    Interactive fake shell: sanitized so that arrow keys and other terminal
    escape sequences do NOT allow the remote to move the cursor or edit prior output.
    The server still maintains an internal buffer (so backspace/Ctrl-U/Ctrl-W work
    server-side) and logs final commands as before.
    """
    try:
        # welcome banner + initial prompt
        try:
            channel.send("Welcome to Ubuntu 22.04 LTS (mock)\r\n")
            channel.send(prompt)
        except Exception:
            pass

        buffer = b""
        while True:
            try:
                data = channel.recv(1024)
            except Exception as e:
                funnel_logger.error(f"recv() failed for {client_ip}: {e}")
                break

            if not data:
                break

            # Process incoming bytes with an index so we can skip ESC sequences safely.
            i = 0
            ln = len(data)
            while i < ln:
                byte = data[i]

                # ESC (start of escape sequences) -> skip the whole sequence (do NOT echo or apply)
                if byte == 27:  # 0x1b
                    i = _skip_escape_sequence(data, i)
                    # continue without echoing or modifying buffer
                    continue

                # Ctrl-C (interrupt)
                if byte == 3:
                    buffer = b""
                    try:
                        channel.send("^C\r\n")
                        channel.send(prompt)
                    except Exception:
                        pass
                    i += 1
                    continue

                # Ctrl-U (kill entire line)
                if byte == 21:
                    buffer = b""
                    try:
                        channel.send("\r\n")
                        channel.send(prompt)
                    except Exception:
                        pass
                    i += 1
                    continue

                # Ctrl-W (delete last word) - update server buffer; redraw prompt+buffer (no cursor tricks)
                if byte == 23:
                    if buffer:
                        s = buffer.decode("latin-1")
                        s = s.rstrip()
                        idx = s.rfind(" ")
                        if idx == -1:
                            buffer = b""
                        else:
                            buffer = s[:idx].encode("latin-1")
                        # redraw line: CR + prompt + current buffer (this rewrites, but we don't allow cursor moves)
                        try:
                            channel.send("\r")
                            channel.send(prompt + buffer.decode("latin-1"))
                        except Exception:
                            pass
                    i += 1
                    continue

                # Backspace / DEL (update server-side buffer, but DO NOT echo backspace escape to client)
                if byte in (8, 127):
                    if buffer:
                        buffer = buffer[:-1]
                        try:
                            channel.send("\b \b")  # move cursor back, overwrite with space, move cursor back again
                        except Exception:
                            pass
                    i += 1
                    continue

                # Newline or carriage return -> treat as line terminator
                if byte in (10, 13):
                    # append the newline so we can partition buffer below
                    buffer += bytes([byte])
                    i += 1
                    # now handle full lines below outside this per-byte loop
                    continue

                # Printable ASCII -> append and echo
                if 32 <= byte <= 126 or byte == 9:  # include tab
                    buffer += bytes([byte])
                    try:
                        # echo the printable char so the remote sees typing, but because ESC sequences were skipped,
                        # they cannot move cursor around previously printed text.
                        channel.send(bytes([byte]).decode("latin-1"))
                    except Exception:
                        pass
                    i += 1
                    continue

                # Other control bytes: ignore/display nothing
                i += 1

            # handle complete lines (LF or CR) in buffer
            while b"\n" in buffer or b"\r" in buffer:
                # support either LF or CR as line terminator
                if b"\n" in buffer:
                    line, sep, rest = buffer.partition(b"\n")
                else:
                    line, sep, rest = buffer.partition(b"\r")
                buffer = rest

                try:
                    cmd = line.decode("utf-8", errors="ignore").strip()
                except Exception:
                    cmd = "<unreadable>"

                # logging (unchanged)
                funnel_logger.info(f"Client {client_ip} ran: {cmd}")
                creds_logger.info(f"{client_ip},CMD,{cmd}")

                lower = cmd.lower()

                # All outputs now explicitly start with "\r\n" so they appear on the next line.
                if cmd == "" or cmd == "\x03":
                    try:
                        channel.send("\r\n")
                    except Exception:
                        pass

                elif lower.startswith("ls"):
                    if "-l" in lower or "-la" in lower or "-al" in lower:
                        try:
                            channel.send("\r\ntotal 8\r\n-rw-r--r-- 1 root root  0 Sep 17 12:00 file1.txt\r\n"
                                         "-rw-r--r-- 1 root root 47 Sep 17 12:00 README.md\r\n")
                        except Exception:
                            pass
                    else:
                        try:
                            channel.send("\r\nfile1.txt  README.md\r\n")
                        except Exception:
                            pass

                elif lower in ("ll", "ls -la"):
                    try:
                        channel.send("\r\ntotal 8\r\n-rw-r--r-- 1 root root  0 Sep 17 12:00 file1.txt\r\n"
                                     "-rw-r--r-- 1 root root 47 Sep 17 12:00 README.md\r\n")
                    except Exception:
                        pass

                elif lower == "whoami":
                    chname = username if username else "ubuntu"
                    try:
                        channel.send(f"\r\n{chname}\r\n")
                    except Exception:
                        pass

                elif lower == "id":
                    try:
                        channel.send("\r\nuid=0(root) gid=0(root) groups=0(root)\r\n")
                    except Exception:
                        pass

                elif lower == "pwd":
                    try:
                        channel.send("\r\n/root\r\n")
                    except Exception:
                        pass

                elif lower.startswith("cat "):
                    target = cmd[4:].strip().strip('"').strip("'")
                    try:
                        if "sshd_config" in target:
                            channel.send("\r\n" + FAKE_SSHD_CONFIG + "\r\n")
                        elif "auth.log" in target:
                            channel.send("\r\n" + FAKE_AUTH_LOG + "\r\n")
                        elif "/etc/passwd" in target:
                            channel.send("\r\nroot:x:0:0:root:/root:/bin/bash\r\n")
                        elif "server.key" in target:
                            channel.send("\r\n-----BEGIN RSA PRIVATE KEY-----\nMII...mock...\n-----END RSA PRIVATE KEY-----\r\n")
                        else:
                            channel.send(f"\r\ncat: {target or ''}: No such file or directory\r\n")
                    except Exception:
                        pass

                elif lower.startswith("tail ") or lower.startswith("head ") or lower.startswith("grep "):
                    # Unified parsing for tail/head/grep aimed at auth.log
                    parts = cmd.split()
                    cmdbase = parts[0] if parts else ""
                    if "auth.log" in cmd:
                        try:
                            if cmdbase == "tail":
                                # support: tail -n N file  OR tail file
                                n = 10
                                if "-n" in parts:
                                    try:
                                        idx = parts.index("-n")
                                        n = int(parts[idx + 1])
                                    except Exception:
                                        n = 10
                                lines = _lines_tail(FAKE_AUTH_LOG, n)
                                channel.send("\r\n" + "\n".join(lines) + "\r\n")
                            elif cmdbase == "head":
                                n = 10
                                if "-n" in parts:
                                    try:
                                        idx = parts.index("-n")
                                        n = int(parts[idx + 1])
                                    except Exception:
                                        n = 10
                                lines = _lines_head(FAKE_AUTH_LOG, n)
                                channel.send("\r\n" + "\n".join(lines) + "\r\n")
                            elif cmdbase == "grep":
                                pattern = parts[1].strip('"').strip("'") if len(parts) > 1 else ""
                                matches = _grep_lines(FAKE_AUTH_LOG, pattern)
                                if matches:
                                    channel.send("\r\n" + "\n".join(matches) + "\r\n")
                                else:
                                    channel.send("\r\n")  # no matches -> just new line
                        except Exception:
                            pass
                    else:
                        # quiet fallback (no output but ensure newline)
                        try:
                            channel.send("\r\n")
                        except Exception:
                            pass

                elif lower == "uname -a":
                    try:
                        channel.send("\r\nLinux ubuntu 5.15.0-100-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n")
                    except Exception:
                        pass

                elif lower == "ps" or lower.startswith("ps "):
                    try:
                        channel.send("\r\n  PID TTY          TIME CMD\r\n    1 ?        00:00:00 systemd\r\n  100 ?        00:00:00 sshd\r\n")
                    except Exception:
                        pass

                elif lower == "df -h":
                    try:
                        channel.send("\r\nFilesystem      Size  Used Avail Use% Mounted on\r\n/dev/sda1        40G  4.0G   34G  11% /\r\n")
                    except Exception:
                        pass

                elif lower == "free -h":
                    try:
                        channel.send("\r\n              total        used        free      shared  buff/cache   available\r\n"
                                     "Mem:           7.7Gi       1.2Gi       5.8Gi       100Mi       700Mi       6.1Gi\r\n")
                    except Exception:
                        pass

                elif lower == "who":
                    try:
                        channel.send("\r\nroot     pts/0        2025-09-21 10:00 (:0)\r\n")
                    except Exception:
                        pass

                elif lower == "last":
                    try:
                        channel.send("\r\nroot     pts/0        127.0.0.1    Mon Sep 21 10:00   still logged in\r\n")
                    except Exception:
                        pass

                elif lower.startswith("echo "):
                    try:
                        to_echo = cmd[5:].strip()
                        channel.send(f"\r\n{to_echo}\r\n")
                    except Exception:
                        pass

                elif lower.startswith(("mkdir ", "touch ", "rm ")):
                    # pretend success silently (no stdout) but ensure prompt redraw stays correct
                    try:
                        channel.send("\r\n")
                    except Exception:
                        pass

                elif lower == "uptime":
                    try:
                        channel.send("\r\n 10:00:00 up 1 day,  3:42,  2 users,  load average: 0.00, 0.01, 0.05\r\n")
                    except Exception:
                        pass

                elif lower == "exit":
                    try:
                        channel.send("\r\nGoodbye!\r\n")
                        channel.close()
                    except Exception:
                        pass
                    return

                else:
                    safe_cmd = cmd if cmd else "<empty>"
                    try:
                        channel.send(f"\r\nbash: {safe_cmd}: command not found\r\n")
                    except Exception:
                        pass

                # prompt again
                try:
                    channel.send(prompt)
                except Exception:
                    return

            # small sleep to avoid busy loop
            time.sleep(0.01)

    except Exception as e:
        funnel_logger.error(f"Error in emulated_shell for {client_ip}: {e}")
    finally:
        try:
            channel.close()
        except Exception:
            pass


# ----------------------
# Per-client handler
# ----------------------
def client_handle(client, addr, username=None, password=None, tarpit=False):
    client_ip = addr[0]
    funnel_logger.info(f"{client_ip} connected to server.")
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER

        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)
        transport.start_server(server=server)

        # wait for a channel (auth happens during start_server)
        channel = transport.accept(20)
        if channel is None:
            funnel_logger.info(f"No channel opened for {client_ip}")
            return

        # pick authenticated username to show in shell (if available)
        auth_user = getattr(server, "authenticated_username", None)

        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"

        # tarpit: optional slow banner; keep it light to avoid resource exhaustion
        if tarpit:
            for chunk in [standard_banner[i:i+80] for i in range(0, len(standard_banner), 80)]:
                try:
                    channel.send(chunk)
                except Exception:
                    break
                time.sleep(0.5)
        else:
            try:
                channel.send(standard_banner)
            except Exception:
                pass

        # start the interactive fake shell (blocking until client disconnects)
        emulated_shell(channel, client_ip=client_ip, username=auth_user, prompt="root@ubuntu:~# ")

    except Exception as e:
        funnel_logger.error(f"Exception in client_handle for {client_ip}: {e}")
    finally:
        try:
            if transport:
                transport.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass

# ----------------------
# Listener: honey(...)
# ----------------------
def honey(address, port, username=None, password=None, tarpit=False):
    """
    Bind to (address, port) and accept connections. Each client gets a thread running client_handle.
    NOTE: do NOT bind to privileged ports (<1024) unless you know what you are doing (sudo required).
    """
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)
    funnel_logger.info(f"SSH honeypot listening on {address}:{port}")

    try:
        while True:
            client, addr = socks.accept()
            t = threading.Thread(
                target=client_handle, args=(client, addr, username, password, tarpit), daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        funnel_logger.info("honey() interrupted by user, shutting down listener.")
    except Exception as e:
        funnel_logger.error(f"honey() listener error on {address}:{port}: {e}")
    finally:
        try:
            socks.close()
        except Exception:
            pass

# ----------------------
# Quick-run helper (optional)
# ----------------------
if __name__ == "__main__":
    # simple CLI run for dev/testing
    ports_env = os.environ.get("PORTS", "2222")
    ports = [int(x.strip()) for x in ports_env.split(",") if x.strip()]
    tarpit_env = os.environ.get("TARPIT_PORTS", "")
    tarpit_ports = {int(x.strip()) for x in tarpit_env.split(",") if x.strip()}

    threads = []
    bind_addr = os.environ.get("BIND_ADDR", "0.0.0.0")
    for p in ports:
        t = threading.Thread(
            target=honey,
            args=(bind_addr, p, None, None, p in tarpit_ports),
            daemon=True,
            name=f"honey-{p}",
        )
        t.start()
        threads.append(t)
        time.sleep(0.1)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down.")
