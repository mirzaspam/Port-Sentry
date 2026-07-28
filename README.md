# PortSentry

A multi-threaded TCP port scanner written in C for my OS Lab course (CS225L, BS Cyber Security, Semester 4).

Scans a target host across a port range using a pool of worker threads, grabs service banners on open ports, and can dump the results to a timestamped report file.

## What it does

- Resolves a hostname or IP and TCP-connects to every port in a given range
- Splits the work across a configurable pool of threads (up to 100) using a shared "next port" counter protected by a mutex — no static ranges per thread, so faster threads just pick up more work
- On an open port, grabs whatever banner the service sends back within a 1-second timeout
- Maps common ports (FTP, SSH, HTTP, MySQL, RDP, MongoDB, etc.) to service names for readability
- Prints results live as ports are found, color-coded in the terminal
- Optionally saves a formatted scan report to `scan_YYYYMMDD_HHMMSS.txt`

## Concepts this demonstrates

- **Sockets**: raw TCP connect scanning with `connect()`, `setsockopt()` timeouts
- **pthreads**: thread pool pattern, shared state guarded by two separate mutexes (one for the port counter, one for the results array) to avoid unnecessary lock contention
- **Race condition handling**: the port counter and results array are the two pieces of shared state, and each has its own critical section
- **File I/O**: writing a formatted report using `fopen`/`fprintf`, timestamped with `strftime`
- **DNS resolution**: `gethostbyname()` to support both IPs and hostnames

## Build

```bash
gcc -o portsentry portsentry.c -lpthread
```

## Run

```bash
./portsentry
```

It'll prompt you interactively for:
- Target (IP or hostname)
- Start port (default 1)
- End port (default 1024)
- Number of threads (default 50, capped at 100)

Example session:

```
  Target (IP or hostname): scanme.nmap.org
  Start port [1]:
  End port   [1024]:
  Threads    [50]:

  [*] Target   : scanme.nmap.org (45.33.32.156)
  [*] Range    : 1 - 1024
  [*] Threads  : 50

  STATE    PORT          SERVICE / BANNER
  ──────────────────────────────────────────
  [OPEN]   22            SSH           SSH-2.0-OpenSSH_6.6.1p1
  [OPEN]   80            HTTP          -

  ──────────────────────────────────────────
  Scan complete in 1.84s
  Open ports : 2
  Scanned    : 1024 ports

  Save results to file? (y/n):
```

## Known limitations

- Interactive prompts only — no CLI flags/arguments yet
- TCP connect scan only (no SYN/stealth scanning, no UDP)
- Banner grabbing is passive (just reads whatever the service sends); doesn't send protocol-specific probes, so some services won't return anything
- No IPv6 support
- Thread count is a flat pool, not adaptive to network conditions

## Why I built it

Wanted a practical, security-flavored project for the OS course instead of a toy scheduler/allocator sim — something that actually touches concurrency, synchronization, and networking together. Port scanning was the natural fit since it's inherently parallelizable (one connect() per port, wait on I/O) and maps directly to a real blue/red team tool category.
