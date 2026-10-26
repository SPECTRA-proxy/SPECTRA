# Module 3 - Bidirectional eBPF Kernel Telemetry

## Objective
Capture live TCP network metadata and performance metrics using eBPF and BCC from the Linux kernel to feed the SPECTRA Module 4 Zero-Trust AI Risk Engine.

## Bidirectional Hooking Architecture
To dynamically calculate both client behavior and server response statistics, the kernel socket filter inspects traffic bidirectionally around proxy port `8443`:

1. **Inbound Traffic (`dport == 8443` - Client to Proxy)**:
   - Evaluates client request behavior
   - Extracts `sttl` (Source IP TTL) directly from IPv4 header
   - Measures `packet_size` and cumulative `smean`
   - Computes `inter_arrival_time` (`sinpkt`) and source jitter (`sjit`)
   - Tracks incoming `SYN` and `ACK` flags to measure TCP handshake RTT

2. **Outbound Traffic (`sport == 8443` - Proxy to Client)**:
   - Measures server response sizes to calculate `dmean` (Destination Mean Packet Size)
   - Captures `SYN-ACK` transmission timestamps to calculate `synack` latency

## The 8 Extracted Telemetries (Canonical Unit Contract)
Matches the UNSW-NB15 feature schema used by Module 4:
1. `packet_size` / `smean`: Request packet size and cumulative mean (**Bytes**)
2. `request_rate`: Inbound request frequency (**Packets / second**)
3. `connection_count`: Active concurrent TCP flows (`ct_srv_src`, **Integer count**)
4. `inter_arrival_time` (`sinpkt`): Inter-packet arrival delta (**Milliseconds, ms**)
5. `sttl`: Source IP Time-To-Live (**Hops / integer**, ~64)
6. `sjit`: Source jitter (**Milliseconds, ms**)
7. `dmean`: Destination mean packet size (**Bytes**)
8. `synack` / `tcprtt`: TCP handshake latency & RTT (**Milliseconds, ms**)

## Technology
- Linux eBPF (`BPF.SOCKET_FILTER` via BCC)
- BCC (BPF Compiler Collection)
- Python 3 & `ctypes` (64-byte naturally aligned C structs)
- Kali Linux / Ubuntu 22.04+ (Kernel 5.4+)

## Usage

### 1. Live Kernel Hooking (Requires Root & BCC)
```bash
sudo python3 ebpf_telemetry.py --interface eth0 --port 8443
```

To forward telemetry live to the Module 4 AI service:
```bash
sudo python3 ebpf_telemetry.py --interface eth0 --port 8443 --forward http://127.0.0.1:7000/score
```

### 2. Simulation Mode (Runs without Root / BCC)
```bash
python3 ebpf_telemetry.py --simulate --port 8443
```
