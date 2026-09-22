# Module 3 - eBPF Kernel Telemetry

## Objective
Capture live TCP network metadata using eBPF and BCC from the Linux kernel.

## Captured Metadata
- Source IP
- Destination Port
- Packet Size

## Technology
- Linux eBPF
- BCC
- Python 3
- Kali Linux

## Network Interface
The program uses `eth0`.

## Run

```bash
sudo python3 ebpf_telemetry.py
