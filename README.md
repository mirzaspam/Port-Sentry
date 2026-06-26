# PortSentry — Multi-threaded TCP Port Scanner

An efficient, multi-threaded TCP port scanner and service banner grabber written in C. This project was developed as an **Operating Systems Laboratory Project** to demonstrate low-level networking and concurrency control in POSIX environments.

PortSentry utilizes low-level POSIX sockets and POSIX threads (`pthreads`) to achieve high-performance scanning across wide network port ranges, complete with automated service identification and multi-threaded synchronization.

---

## 🚀 Key Features

- **Multi-threaded Architecture:** Dynamically distributes scanning tasks across a highly customizable pool of worker threads (up to 100 concurrent threads) using thread-safe shared state synchronization via `pthread` mutex locks.
- **Service Fingerprinting:** Resolves standard protocol signatures (e.g., FTP, SSH, Telnet, HTTP, HTTPS, SMB, RDP) dynamically based on open port matching.
- **Live Banner Grabbing:** Probes established socket connections to capture remote application headers and service banners for deep reconnaissance.
- **Dynamic Hostname Resolution:** Implements network address conversion capable of evaluating both explicit IP addresses and remote hostnames.
- **Automated Report Generation:** Exports scan summary telemetry, including total elapsed time, port statistics, and structural banner mappings, directly to a structured `.txt` log file.
- **Interactive UI:** Features real-time ANSI-colored console logs marking open pathways (`[OPEN]`) alongside an interactive runtime configuration shell.

---

## 🛠️ Core OS & Networking Concepts Explored

- **Network Sockets (`sys/socket.h`):** Creation, configuration, and structural state-handling of standard TCP stream sockets (`SOCK_STREAM`) using Internet address protocols (`AF_INET`).
- **Socket Options (`setsockopt`):** Fine-tuning network connection states by enforcing deterministic send (`SO_SNDTIMEO`) and receive (`SO_RCVTIMEO`) timeouts to mitigate zombie threads or hanging sockets.
- **Shared Memory Synchronization:** Mitigates race conditions over sequential port blocks (`next_port`) and global logging arrays (`open_ports[]`) via atomic mutual exclusions (`pthread_mutex_t`).
- **File System Handling (`stdio.h`):** Formats, isolates, and pipes runtime memory blocks directly into external file systems upon user verification.

---

## 📂 Project Structure
