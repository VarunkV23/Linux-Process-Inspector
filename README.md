# procsnoop

A Linux process inspector written in Rust. Reads directly from `/proc` and uses `ptrace` to give you a detailed, colour-coded view of any running process — its memory, file descriptors, network sockets, capabilities, namespaces, syscalls, and more.

Also ships with `infra_setup.sh`, a one-shot installer for a self-hosted stack: **Pi-hole + WireGuard + Gitea**.

---

## Requirements

- Linux (x86-64)
- Rust 1.70+ / Cargo
- `sudo` for `ptrace`-based commands (`--trace`, `--audit`, and the `run` Makefile target)

---

## Build & Install

```bash
# Debug build
make build

# Optimised release build
make release

# Install to /usr/local/bin
make install

# Remove
make uninstall
```

---

## Usage

```
procsnoop <pid>                  Full inspection of a process
procsnoop --list                 List all running processes
procsnoop --tree                 Process tree
procsnoop --watch   <pid>        Live dashboard, refreshes every second
procsnoop --fds     <pid>        Open file descriptors
procsnoop --maps    <pid>        Memory map (address ranges, permissions, labels)
procsnoop --smaps   <pid>        Detailed memory breakdown (PSS, swap, dirty pages)
procsnoop --sockets <pid>        Network connections (TCP/UDP, IPv4/IPv6)
procsnoop --caps    <pid>        Linux capabilities & seccomp status
procsnoop --trace   <pid>        Syscall trace (like strace)
procsnoop --ns      <pid>        Namespaces + container runtime detection
procsnoop --diff    <pid> [sec]  State delta over N seconds (default 5)
procsnoop --audit   <pid>        Security anomaly detection
procsnoop --json    <pid>        Full JSON dump of all gathered data
```

### Quick examples

```bash
# Inspect PID 1234 (full report)
sudo procsnoop 1234

# Watch memory and FD counts live
sudo procsnoop --watch 1234

# Trace syscalls (requires ptrace)
sudo procsnoop --trace 1234

# Show what changed in the process over 10 seconds
sudo procsnoop --diff 1234 10

# Run a specific subcommand via make (handles sudo)
make run ARGS="--audit 1234"
make run ARGS="--trace 1234"
```

---

## Features

| Command | What it shows |
|---|---|
| `<pid>` | Name, state, PPID, UID, threads, RSS/VmSize, cmdline, seccomp, capabilities, FDs, maps, sockets, namespaces, cgroup |
| `--watch` | Live-refreshing summary: state, memory, FD count, socket count |
| `--fds` | Every open file descriptor with its type (file / socket / pipe) and target path |
| `--maps` | All virtual memory regions — address, permissions, size, backing file |
| `--smaps` | PSS, private dirty, shared dirty/clean, swap — per region and as totals |
| `--sockets` | TCP/UDP (v4 + v6) connections with fd, local/remote address, and state |
| `--caps` | Effective, permitted, inheritable, and bounding capability sets; seccomp mode |
| `--trace` | Live syscall stream decoded to names (uses `ptrace`) |
| `--ns` | All 8 namespace types; flags namespaces that differ from PID 1 (i.e. isolated); detects Docker / LXC / Kubernetes / containerd / Podman from cgroup paths |
| `--diff` | Takes two snapshots N seconds apart and reports opened/closed FDs, new/closed sockets, and RSS delta |
| `--audit` | Flags dangerous capabilities on non-root processes, disabled seccomp, RWX memory pages, binaries running from `/tmp` or `/dev/shm`, deleted on-disk binaries, and `memfd` (fileless execution) patterns |
| `--json` | Serialises the full `ProcessInfo` struct to pretty-printed JSON — suitable for piping into `jq` or log aggregators |

---

## JSON output

`--json` emits a structured document covering all gathered fields:

```json
{
  "pid": 1234,
  "name": "nginx",
  "state": "S (sleeping)",
  "ppid": "1",
  "threads": "4",
  "uid": "33",
  "vm_rss": "12288 kB",
  "vm_size": "204800 kB",
  "seccomp": "2",
  "caps_effective": ["CAP_NET_BIND_SERVICE"],
  "caps_permitted": ["CAP_NET_BIND_SERVICE"],
  "cmdline": "nginx: master process /usr/sbin/nginx",
  "fds": [ ... ],
  "maps": [ ... ],
  "sockets": [ ... ],
  "smaps": { ... },
  "namespaces": [ ... ],
  "cgroup": [ ... ]
}
```

---

## infra_setup.sh — Self-Hosted Stack Installer

Installs and configures **Pi-hole**, **WireGuard**, and **Gitea** on a fresh Debian 12 / Ubuntu 22.04+ server in a single run.

### What it sets up

| Service | Details |
|---|---|
| **Pi-hole** | Network-wide ad and tracker blocking; DNS set to Cloudflare (1.1.1.1 / 1.0.0.1) |
| **WireGuard** | VPN on UDP port 51820; server IP `10.8.0.1`, client IP `10.8.0.2`; Pi-hole used as DNS inside the tunnel; QR code printed to terminal for easy mobile import |
| **Gitea** | Lightweight self-hosted Git server on port 3000 (HTTP) and 2222 (SSH); SQLite backend; registration disabled; **only reachable over the WireGuard tunnel** |
| **UFW** | Denies all inbound by default; opens SSH, 80/443 (Pi-hole admin), WireGuard UDP; Gitea ports are restricted to the `wg0` interface |

### Usage

```bash
# Edit config variables at the top of the script first
nano infra_setup.sh   # set PIHOLE_PASSWORD at minimum

sudo bash infra_setup.sh
```

> **Note:** Change `PIHOLE_PASSWORD` before running. The script will print a warning if you forget.

After the script completes, connect to WireGuard first, then visit `http://10.8.0.1:3000` to finish Gitea's initial setup wizard.

---

## Dependencies

**procsnoop** (`Cargo.toml`):

| Crate | Purpose |
|---|---|
| `libc` | Raw Linux syscall and ptrace bindings |
| `serde` + `serde_json` | JSON serialisation for `--json` output |

---

## License

MIT
