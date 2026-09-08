# portkill

CLI and interactive terminal tool to kill processes hogging your ports. No drama, tachles.

---

## Why

You run `npm run dev` or `docker compose up` and get `EADDRINUSE: port already in use`. Instead of wasting time with `lsof`, `netstat`, or guessing PIDs, just run `portkill`.

---

## Features

- **Direct Kill**: `portkill 3000 8080` terminates listeners instantly.
- **Graceful Escalation**: Sends `SIGTERM` first, waits 500ms, and escalates to `SIGKILL` if unresponsive.
- **Docker Radar**: Detects `docker-proxy`, `containerd-shim`, and container IPs/IDs.
- **Resource Stats**: Shows process RAM, CPU, uptime, and user.
- **Safety Guards**: Blocks killing critical ports (SSH 22, DNS 53, PID 1) without `--dangerous`.
- **Interactive Mode**: Run `portkill` with no arguments to inspect and kill via terminal prompt.

---

## Installation

```bash
git clone https://github.com/idankuz/portkill.git
cd portkill
pip install -e .
```

---

## Usage

### Kill Ports
```bash
# Graceful kill with confirmation
portkill 3000

# Force kill without confirmation
portkill 3000 8080 -f

# Verbose process lineage
portkill 3000 -v
```

### Scan Ports
```bash
# Scan common dev ports (3000, 5173, 8000, 5432, 6379, etc.)
portkill scan

# Scan all open ports
portkill scan --all

# Filter by protocol
portkill scan --proto tcp
```

### Interactive Dashboard
```bash
portkill
```
- Enter `<port>` to target a listener.
- Press `k` to kill gracefully.
- Press `f` to force kill (`SIGKILL`).
- Press `d` for process details.
- Press `r` to refresh.
- Press `q` to quit.

---

## Permissions

If a port belongs to another user or Docker daemon, run with elevated privileges:
```bash
sudo portkill <port>
```

---

## Tests

```bash
pytest tests
```

---

## License

MIT
