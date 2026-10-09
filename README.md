# Educational TCP Port Scanner

A small Python port scanner built with the standard-library `socket` module.
It grows in three stages so the progression is easy to follow:

1. **Single-threaded scan** — `scan_port` / `scan_single_threaded`: a plain
   blocking TCP connect over a port range.
2. **Threaded scan** — `scan_threaded`: the same scan run through a
   `ThreadPoolExecutor` for a large speedup on wide ranges.
3. **Banner grabbing** — `grab_banner`: reads a short service banner from each
   open port (and nudges HTTP-style ports with a `HEAD` request).

> ⚠️ Only scan hosts you own or have written permission to test.
> Unauthorized scanning of third-party systems may be illegal.

## Usage

```bash
python3 scanner.py <host> [--start 1] [--end 1024] [--timeout 0.5]
                          [--threads 100] [--no-banner]
```

### Options
| Flag | Default | Meaning |
|------|---------|---------|
| `--start` | `1` | First port in the range |
| `--end` | `1024` | Last port in the range |
| `--timeout` | `0.5` | Per-port connect timeout (seconds) |
| `--threads` | `100` | Thread pool size; use `1` for the single-threaded path |
| `--no-banner` | off | Skip banner grabbing on open ports |

### Examples

```bash
# Scan the well-known ports on localhost
python3 scanner.py 127.0.0.1

# Full range, more threads
python3 scanner.py 127.0.0.1 --start 1 --end 65535 --threads 200

# Compare the single-threaded path (slower, same result)
python3 scanner.py 127.0.0.1 --threads 1
```

### Sample output

```
[*] Target: 127.0.0.1 (127.0.0.1)
[*] Ports:  9995-10000 (6 ports)
[*] Mode:   100 threads

[+] 1 open port(s):

    PORT    SERVICE         BANNER
    ----    -------         ------
    9999    unknown         SSH-2.0-TestServer_1.0

[*] Done in 0.01s
```

## Defaults chosen
- **Port range:** 1–1024 (the well-known ports) when none is given.
- **Timeout:** 0.5s per port — fast on a LAN; raise it for slow/remote hosts.
- **Threads:** 100 — a good balance for most ranges. Set `--threads 1` to run
  the single-threaded Stage 1 code instead.

## How it works
`scan_port` uses `socket.connect_ex`, which returns `0` on a successful TCP
handshake instead of raising — any other value means the port is closed or
filtered. The threaded version submits every port to a pool and collects the
open ones as futures complete. `grab_banner` opens a fresh connection to each
open port, optionally sends a minimal HTTP request, and returns the first line
of whatever the service replies with.
