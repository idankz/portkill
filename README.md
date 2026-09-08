# portkill ?

> Zero-config, visually polished, cross-distro Linux / WSL CLI and interactive TUI utility to scan listening ports, inspect rich process trees, and safely terminate stubborn listeners.

Say goodbye to `lsof -i :3000` -> `kill -9 <PID>` rituals when encountering `EADDRINUSE: port already in use`.

---

## Features

- ? **Instant Direct Termination**: Terminate listeners on single or multiple ports (`portkill 3000 8080`).
- ??? **Graceful Escalation**: Sends `SIGTERM` first, waits 500ms, and safely escalates to `SIGKILL` if unresponsive.
- ?? **Docker & Container Awareness**: Identifies `docker-proxy`, `containerd-shim`, and container IPs/IDs bound to ports.
- ?? **Rich Terminal UI**: Formatted tables with color-coded runtimes (Node, Bun, Python, Go, Rust, Java, Docker, Postgres, Redis).
- ?? **Interactive TUI Dashboard**: Launch with `portkill` or `portkill -i` to browse open ports and interactively inspect or kill processes.
- ?? **Critical System Safety Guards**: Blocks termination of critical services (SSH, DNS, DHCP, PID 1, systemd) unless explicitly passed `--dangerous`.
- ?? **Actionable Permission Guidance**: Clear feedback for non-root users recommending `sudo portkill <port>`.

---

## Installation

### From Source / Pip
```bash
git clone https://github.com/your-org/portkill.git
cd portkill
pip install -e .
```

---

## Quick Usage

### 1. Direct Kill
```bash
# Graceful kill with confirmation prompt
portkill 3000

# Kill multiple ports with force (SIGKILL) skipping confirmation
portkill 3000 8080 -f

# Verbose inspection showing full process tree and arguments
portkill 5173 -v
```

### 2. Common Dev Band Scanner
Scans popular development server bands (Next.js, Vite, Flask, Rails, Django, Postgres, Redis, Mongo, Kafka):
```bash
portkill scan

# Scan ALL open ports on the machine (TCP + UDP)
portkill scan --all

# Filter by protocol
portkill scan --proto tcp
```

### 3. Interactive TUI Dashboard
Launch without arguments or with `-i`:
```bash
portkill
```
- Type the port number to select a listener.
- Press `[k]` to terminate gracefully.
- Press `[f]` to force kill (`SIGKILL`).
- Press `[d]` to view process details & command arguments.
- Press `[q]` to quit.

---

## Safety Flags

- `--dangerous`: Allows killing critical system ports (e.g. port 22 SSH) or core system processes.
- `-f`, `--force`: Directly sends `SIGKILL` without waiting or prompting.

---

## Running Tests

```bash
pytest
```
