#!/usr/bin/env python3
"""
SPECTRA Module 3 - Bidirectional eBPF Kernel Telemetry Engine
Extracts 8-feature telemetry vector for Zero-Trust AI Risk Engine (Module 4):
  1. packet_size (and smean - Source Mean Packet Size)
  2. request_rate (Packets / Requests per second)
  3. connection_count (Active concurrent TCP connections)
  4. inter_arrival_time (sinpkt - Inter-packet arrival delta)
  5. sttl (Source IPv4 Time-To-Live)
  6. sjit (Source Packet Jitter)
  7. dmean (Destination Mean Packet Size - Outbound proxy response)
  8. synack / tcprtt (TCP Handshake RTT & SYN-ACK latency)

Bidirectional Hooking Architecture:
  - Inbound (dport == PROXY_PORT):
      Extracts sttl, packet_size, smean, calculates sinpkt (IAT),
      sjit (jitter), request_rate, and tracks incoming SYN & ACK.
  - Outbound (sport == PROXY_PORT):
      Inspects response packets to calculate dmean (proxy response size),
      and records SYN-ACK timestamp to calculate synack and tcprtt latency.
"""

import sys
import time
import socket
import struct
import argparse
import ctypes
import json
import urllib.request
import urllib.error

DEFAULT_INTERFACE = "eth0"
DEFAULT_PROXY_PORT = 8443

# -----------------------------------------------------------------------------
# eBPF C Kernel Program (Compiled by BCC into in-kernel bytecode)
# -----------------------------------------------------------------------------

def generate_bpf_program(proxy_port):
    return f"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>

#define PROXY_PORT {proxy_port}

/* 4-tuple key for TCP flow tracking (client endpoint) */
struct flow_key_t {{
    u32 client_ip;
    u16 client_port;
}};

/* Flow state for tracking TCP handshake latency and active connections */
struct flow_state_t {{
    u64 syn_ts;         /* Timestamp of inbound SYN (ns) */
    u64 synack_ts;      /* Timestamp of outbound SYN-ACK (ns) */
    u32 synack_ns;      /* Handshake duration between SYN and SYN-ACK */
    u32 tcprtt_ns;      /* Total 3-way handshake round trip time (SYN -> ACK) */
    u8  established;    /* 1 once handshake is complete */
}};

/* Cumulative client telemetry state per client IP */
struct client_state_t {{
    /* 1. packet_size & smean */
    u32 last_pkt_size;
    u64 s_bytes;
    u32 s_pkts;

    /* 2. request_rate */
    u64 first_seen_ns;
    u64 last_seen_ns;
    u32 request_rate;   /* Packets per second */

    /* 3. connection_count */
    u32 active_conns;

    /* 4. inter_arrival_time */
    u64 iat_ns;
    u64 prev_iat_ns;

    /* 5. sttl */
    u8  last_sttl;

    /* 6. sjit (jitter) */
    u64 sjit_ns;

    /* 7. dmean (outbound responses) */
    u64 d_bytes;
    u32 d_pkts;
    u32 dmean;

    /* 8. synack / tcprtt */
    u32 last_synack_ns;
    u32 last_tcprtt_ns;
}};

/* Telemetry Event struct emitted to userspace (64 bytes, naturally aligned) */
struct telemetry_event_t {{
    u64 inter_arrival_time_ns; /* 4. sinpkt: Inter-arrival time (ns) */
    u64 sjit_ns;               /* 6. sjit: Source jitter (ns) */
    u64 timestamp_ns;          /* Packet timestamp (ns) */
    u32 client_ip;             /* Client IPv4 address (network byte order) */
    u32 packet_size;           /* 1. packet_size: Latest packet length (bytes) */
    u32 smean;                 /* Source mean packet size (bytes) */
    u32 request_rate;          /* 2. request_rate: Packets per second */
    u32 connection_count;      /* 3. connection_count: Active TCP flows */
    u32 dmean;                 /* 7. dmean: Destination mean packet size */
    u32 synack_ns;             /* 8a. synack: SYN to SYN-ACK latency (ns) */
    u32 tcprtt_ns;             /* 8b. tcprtt: Full 3-way handshake RTT (ns) */
    u16 client_port;           /* Client TCP port */
    u16 server_port;           /* Proxy TCP port (8443) */
    u8  sttl;                  /* 5. sttl: Source IP Time-To-Live */
    u8  direction;             /* 0 = INBOUND, 1 = OUTBOUND */
    u8  tcp_flags;             /* TCP flags */
    u8  _pad;                  /* Alignment padding */
}};

/* BPF Maps */
BPF_HASH(client_stats, u32, struct client_state_t, 4096);
BPF_HASH(flow_table, struct flow_key_t, struct flow_state_t, 8192);
BPF_HASH(telemetry_map, u32, struct telemetry_event_t, 1024);
BPF_ARRAY(packet_counter, u32, 1);

int packet_parser(struct __sk_buff *skb)
{{
    unsigned char eth[14];
    unsigned char ip_header[20];
    unsigned char tcp_header[20];

    if (skb->len < 34)
        return 0;

    /* Read Ethernet header */
    if (bpf_skb_load_bytes(skb, 0, eth, 14) < 0)
        return 0;

    /* Filter for IPv4 (0x0800) */
    if (eth[12] != 0x08 || eth[13] != 0x00)
        return 0;

    /* Read IPv4 header */
    if (bpf_skb_load_bytes(skb, 14, ip_header, 20) < 0)
        return 0;

    /* Filter for TCP protocol (6) */
    if (ip_header[9] != 6)
        return 0;

    u32 ip_header_len = (ip_header[0] & 0x0F) * 4;
    if (ip_header_len < 20)
        return 0;

    if (skb->len < 14 + ip_header_len + 20)
        return 0;

    /* Read TCP header */
    if (bpf_skb_load_bytes(skb, 14 + ip_header_len, tcp_header, 20) < 0)
        return 0;

    /* Extract IPs, Ports, Flags, and TTL */
    u32 src_ip = (ip_header[12]) | (ip_header[13] << 8) | (ip_header[14] << 16) | (ip_header[15] << 24);
    u32 dst_ip = (ip_header[16]) | (ip_header[17] << 8) | (ip_header[18] << 16) | (ip_header[19] << 24);
    u16 sport = ((u16)tcp_header[0] << 8) | tcp_header[1];
    u16 dport = ((u16)tcp_header[2] << 8) | tcp_header[3];
    u8  tcp_flags = tcp_header[13];
    u8  ttl = ip_header[8];

    u8  is_inbound = 0;
    u8  is_outbound = 0;
    u32 client_ip = 0;
    u16 client_port = 0;
    u16 server_port = 0;

    /* Check direction: Bidirectional Hooking */
    if (dport == PROXY_PORT) {{
        is_inbound = 1;
        client_ip = src_ip;
        client_port = sport;
        server_port = dport;
    }} else if (sport == PROXY_PORT) {{
        is_outbound = 1;
        client_ip = dst_ip;
        client_port = dport;
        server_port = sport;
    }} else {{
        /* Packet unrelated to SPECTRA reverse proxy */
        return 0;
    }}

    u64 now = bpf_ktime_get_ns();
    struct flow_key_t fkey = {{}};
    fkey.client_ip = client_ip;
    fkey.client_port = client_port;

    /* Retrieve or initialize client cumulative state */
    struct client_state_t *cstate = client_stats.lookup(&client_ip);
    if (!cstate) {{
        struct client_state_t init_c = {{}};
        init_c.first_seen_ns = now;
        init_c.last_seen_ns = now;
        init_c.active_conns = 1;
        init_c.last_sttl = ttl;
        client_stats.update(&client_ip, &init_c);
        cstate = client_stats.lookup(&client_ip);
    }}
    if (!cstate)
        return 0;

    /* -------------------------------------------------------------
     * OUTBOUND HOOK (sport == PROXY_PORT): Proxy -> Client
     * Captures: dmean (response size) and synack latency (SYN-ACK)
     * ------------------------------------------------------------- */
    if (is_outbound) {{
        /* 7. Update Destination Response Size (dmean) */
        cstate->d_bytes += skb->len;
        cstate->d_pkts += 1;
        cstate->dmean = (u32)(cstate->d_bytes / cstate->d_pkts);

        /* 8. Handshake Step 2: Proxy sends SYN-ACK (SYN=1, ACK=1) */
        if ((tcp_flags & 0x02) && (tcp_flags & 0x10)) {{
            struct flow_state_t *fstate = flow_table.lookup(&fkey);
            if (fstate && fstate->syn_ts > 0) {{
                fstate->synack_ts = now;
                if (now >= fstate->syn_ts) {{
                    fstate->synack_ns = (u32)(now - fstate->syn_ts);
                    cstate->last_synack_ns = fstate->synack_ns;
                }}
                flow_table.update(&fkey, fstate);
            }}
        }}

        /* Teardown flow on FIN or RST */
        if ((tcp_flags & 0x01) || (tcp_flags & 0x04)) {{
            if (cstate->active_conns > 0)
                cstate->active_conns -= 1;
            flow_table.delete(&fkey);
        }}

        return 0;
    }}

    /* -------------------------------------------------------------
     * INBOUND HOOK (dport == PROXY_PORT): Client -> Proxy
     * Captures: packet_size, smean, sttl, sinpkt, sjit, request_rate,
     * connection_count, and completes tcprtt measurement.
     * ------------------------------------------------------------- */
    if (is_inbound) {{
        /* 1. packet_size and cumulative smean */
        cstate->last_pkt_size = skb->len;
        cstate->s_bytes += skb->len;
        cstate->s_pkts += 1;
        cstate->smean = (u32)(cstate->s_bytes / cstate->s_pkts);

        /* 5. sttl (Source TTL) */
        cstate->last_sttl = ttl;

        /* 4 & 6. inter_arrival_time (sinpkt) and sjit (Source Jitter) */
        if (cstate->last_seen_ns > 0 && now >= cstate->last_seen_ns) {{
            u64 iat = now - cstate->last_seen_ns;
            cstate->iat_ns = iat;
            if (cstate->prev_iat_ns > 0) {{
                s64 diff = (s64)iat - (s64)cstate->prev_iat_ns;
                if (diff < 0)
                    diff = -diff;
                cstate->sjit_ns = (u64)diff;
            }}
            cstate->prev_iat_ns = iat;
        }}
        cstate->last_seen_ns = now;

        /* 2. request_rate (Packets per second) */
        if (cstate->first_seen_ns > 0 && now > cstate->first_seen_ns) {{
            u64 elapsed_ns = now - cstate->first_seen_ns;
            cstate->request_rate = (u32)((cstate->s_pkts * 1000000000ULL) / elapsed_ns);
        }} else {{
            cstate->request_rate = 1;
        }}

        /* 3 & 8. Flow Connection Tracking: SYN, ACK, FIN, RST */
        if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {{
            /* Handshake Step 1: Inbound SYN */
            struct flow_state_t new_flow = {{}};
            new_flow.syn_ts = now;
            flow_table.update(&fkey, &new_flow);
            cstate->active_conns += 1;
        }} else if (!(tcp_flags & 0x02) && (tcp_flags & 0x10)) {{
            /* Handshake Step 3: Inbound final ACK (Completes 3-way handshake) */
            struct flow_state_t *fstate = flow_table.lookup(&fkey);
            if (fstate && fstate->syn_ts > 0 && !fstate->established) {{
                fstate->established = 1;
                if (now >= fstate->syn_ts) {{
                    fstate->tcprtt_ns = (u32)(now - fstate->syn_ts);
                    cstate->last_tcprtt_ns = fstate->tcprtt_ns;
                }}
                flow_table.update(&fkey, fstate);
            }}
        }}

        /* Teardown on FIN or RST */
        if ((tcp_flags & 0x01) || (tcp_flags & 0x04)) {{
            if (cstate->active_conns > 0)
                cstate->active_conns -= 1;
            flow_table.delete(&fkey);
        }}

        /* Emit Telemetry Event into Ring Hash Map */
        struct telemetry_event_t event = {{}};
        event.inter_arrival_time_ns = cstate->iat_ns;
        event.sjit_ns               = cstate->sjit_ns;
        event.timestamp_ns          = now;
        event.client_ip             = client_ip;
        event.packet_size           = skb->len;
        event.smean                 = cstate->smean;
        event.request_rate          = cstate->request_rate;
        event.connection_count      = cstate->active_conns;
        event.dmean                 = cstate->dmean;
        event.synack_ns             = cstate->last_synack_ns;
        event.tcprtt_ns             = cstate->last_tcprtt_ns;
        event.client_port           = client_port;
        event.server_port           = server_port;
        event.sttl                  = cstate->last_sttl;
        event.direction             = 0; /* Inbound */
        event.tcp_flags             = tcp_flags;
        event._pad                  = 0;

        u32 zero = 0;
        u32 *counter = packet_counter.lookup(&zero);
        if (counter) {{
            u32 key = *counter;
            if (key >= 1024)
                key = 0;
            key++;
            packet_counter.update(&zero, &key);
            telemetry_map.update(&key, &event);
        }}
    }}

    return 0;
}}
"""

# -----------------------------------------------------------------------------
# Python ctypes definition matching the 64-byte C struct telemetry_event_t
# -----------------------------------------------------------------------------

class TelemetryEvent(ctypes.Structure):
    _fields_ = [
        ("inter_arrival_time_ns", ctypes.c_uint64),
        ("sjit_ns",               ctypes.c_uint64),
        ("timestamp_ns",          ctypes.c_uint64),
        ("client_ip",             ctypes.c_uint32),
        ("packet_size",           ctypes.c_uint32),
        ("smean",                 ctypes.c_uint32),
        ("request_rate",          ctypes.c_uint32),
        ("connection_count",      ctypes.c_uint32),
        ("dmean",                 ctypes.c_uint32),
        ("synack_ns",             ctypes.c_uint32),
        ("tcprtt_ns",             ctypes.c_uint32),
        ("client_port",           ctypes.c_uint16),
        ("server_port",           ctypes.c_uint16),
        ("sttl",                  ctypes.c_uint8),
        ("direction",             ctypes.c_uint8),
        ("tcp_flags",             ctypes.c_uint8),
        ("_pad",                  ctypes.c_uint8),
    ]

# -----------------------------------------------------------------------------
# Telemetry Vector Formatter & Module 4 Forwarder
# -----------------------------------------------------------------------------

def format_telemetry_vector(event):
    """
    Extracts and scales the 8 telemetries for display and Module 4 evaluation.
    Canonical Unit Contract (UNSW-NB15 Aligned):
      - packet_size: Bytes (smean)
      - request_rate: Packets / second
      - connection_count: Active concurrent TCP flows
      - inter_arrival_time: Milliseconds (sinpkt, ms)
      - sttl: IPv4 TTL (hops)
      - sjit: Source jitter in Milliseconds (sjit, ms)
      - dmean: Bytes (outbound proxy response average)
      - synack: TCP handshake latency in Milliseconds (synack, ms)
      - tcprtt: Full 3-way handshake RTT in Milliseconds (tcprtt, ms)
    """
    client_ip_str = socket.inet_ntoa(struct.pack("=I", event.client_ip))
    iat_ms = event.inter_arrival_time_ns / 1_000_000.0
    sjit_ms = event.sjit_ns / 1_000_000.0
    synack_ms = event.synack_ns / 1_000_000.0
    tcprtt_ms = event.tcprtt_ns / 1_000_000.0

    return {
        "client_ip": client_ip_str,
        "client_port": int(event.client_port),
        "server_port": int(event.server_port),
        "packet_size": int(event.packet_size),
        "smean": int(event.smean),
        "request_rate": max(1, int(event.request_rate)),
        "connection_count": max(1, int(event.connection_count)),
        "inter_arrival_time": round(iat_ms, 3),
        "sttl": int(event.sttl),
        "sjit": round(sjit_ms, 3),
        "dmean": int(event.dmean),
        "synack": round(synack_ms, 3),
        "tcprtt": round(tcprtt_ms, 3),
    }

def print_telemetry_summary(t):
    """Prints the 8-feature telemetry vector in a readable dashboard layout."""
    print("+" + "-"*68 + "+")
    print(f"| [SPECTRA eBPF] 8-TELEMETRY VECTOR: {t['client_ip']}:{t['client_port']} -> :{t['server_port']:<5} |")
    print("+" + "-"*68 + "+")
    print(f"|  1. Packet Size (smean)        : {t['packet_size']:<5} B  (Mean: {t['smean']} B)")
    print(f"|  2. Request Rate (rate)        : {t['request_rate']:<5} pkts/sec")
    print(f"|  3. Connection Count (ct_con)  : {t['connection_count']:<5} active flows")
    print(f"|  4. Inter-Arrival Time (sinpkt): {t['inter_arrival_time']:<8.2f} ms")
    print(f"|  5. Source TTL (sttl)          : {t['sttl']:<5} (OS baseline / hop limit)")
    print(f"|  6. Source Jitter (sjit)       : {t['sjit']:<8.2f} ms")
    print(f"|  7. Destination Mean (dmean)   : {t['dmean']:<5} B (Outbound response size)")
    print(f"|  8. TCP Handshake RTT (synack) : {t['synack']:<8.2f} ms (tcprtt: {t['tcprtt']:.2f} ms)")
    print("+" + "-"*68 + "+\n")

def forward_to_m4(t, m4_url):
    """Optionally forwards the live telemetry to Module 4 (Flask port 7000)."""
    payload = json.dumps({
        "packet_size": t["packet_size"],
        "request_rate": t["request_rate"],
        "connection_count": t["connection_count"],
        "inter_arrival_time": t["inter_arrival_time"],
        "sttl": t["sttl"],
        "sjit": t["sjit"],
        "dmean": t["dmean"],
        "synack": t["synack"]
    }).encode("utf-8")

    req = urllib.request.Request(
        m4_url,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=0.1) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[MOD 4 AI Response] Score: {data.get('risk_score')} | Decision: {data.get('decision')}")
    except Exception as e:
        # Non-blocking, continue logging telemetry even if M4 service is offline
        pass

# -----------------------------------------------------------------------------
# Simulation Mode (Allows verification without root/BCC installed)
# -----------------------------------------------------------------------------

def run_simulation(proxy_port, forward_url=None):
    """
    Simulates bidirectional kernel packet capture for testing and validation:
      1. Inbound SYN from client
      2. Outbound SYN-ACK from proxy (calculates synack)
      3. Inbound ACK from client (completes tcprtt)
      4. Inbound HTTP/PQC request (calculates sttl, packet_size, sjit, sinpkt)
      5. Outbound HTTP/PQC response (calculates dmean)
    """
    print("="*70)
    print("  SPECTRA eBPF Telemetry Engine — BIDIRECTIONAL SIMULATION MODE")
    print("="*70)
    print(f"[i] Simulating bidirectional traffic on interface eth0 <-> proxy port {proxy_port}")
    print("[i] Hooking ingress (dport 8443) and egress (sport 8443)... Press Ctrl+C to stop.\n")

    sim_scenarios = [
        # Normal client connection (all timings in ms)
        {"ip": "192.168.1.105", "port": 52140, "size": 612, "sttl": 64, "iat_ms": 45.2, "jit_ms": 3.1, "dmean": 1280, "synack_ms": 12.4, "tcprtt_ms": 14.8, "rate": 5, "conns": 1},
        {"ip": "192.168.1.105", "port": 52140, "size": 640, "sttl": 64, "iat_ms": 42.1, "jit_ms": 3.1, "dmean": 1310, "synack_ms": 12.4, "tcprtt_ms": 14.8, "rate": 6, "conns": 1},
        # High-rate burst (DoS probe simulation)
        {"ip": "10.0.0.88", "port": 49120, "size": 1460, "sttl": 128, "iat_ms": 1.2, "jit_ms": 0.4, "dmean": 420, "synack_ms": 4.2, "tcprtt_ms": 5.1, "rate": 450, "conns": 18},
    ]

    try:
        step = 0
        while True:
            sc = sim_scenarios[step % len(sim_scenarios)]
            step += 1

            t = {
                "client_ip": sc["ip"],
                "client_port": sc["port"],
                "server_port": proxy_port,
                "packet_size": sc["size"],
                "smean": sc["size"] - 20,
                "request_rate": sc["rate"],
                "connection_count": sc["conns"],
                "inter_arrival_time": sc["iat_ms"],
                "sttl": sc["sttl"],
                "sjit": sc["jit_ms"],
                "dmean": sc["dmean"],
                "synack": sc["synack_ms"],
                "tcprtt": sc["tcprtt_ms"],
            }

            print_telemetry_summary(t)
            if forward_url:
                forward_to_m4(t, forward_url)

            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[+] Simulation stopped.")

# -----------------------------------------------------------------------------
# Main Execution (BCC Kernel Mode with fallback to Simulation)
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SPECTRA Bidirectional eBPF Telemetry Engine")
    parser.add_argument("-i", "--interface", default=DEFAULT_INTERFACE, help="Network interface (default: eth0)")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PROXY_PORT, help="SPECTRA proxy port (default: 8443)")
    parser.add_argument("-s", "--simulate", action="store_true", help="Run simulation mode without root / BCC")
    parser.add_argument("-f", "--forward", default=None, help="Forward telemetry JSON to Module 4 URL (e.g. http://127.0.0.1:7000/score)")
    args = parser.parse_args()

    if args.simulate:
        run_simulation(args.port, args.forward)
        return

    try:
        from bcc import BPF
    except ImportError:
        print("[!] BCC (BPF Compiler Collection) is not installed in this Python environment.")
        print("[!] To run with live kernel hooks, install BCC (e.g. apt-get install bpfcc-tools python3-bpfcc).")
        print("[!] Starting simulation mode instead...\n")
        run_simulation(args.port, args.forward)
        return

    print("="*70)
    print("  SPECTRA Module 3: Bidirectional eBPF Kernel Telemetry")
    print("="*70)
    print(f"[+] Compiling eBPF C program for proxy port: {args.port}...")

    bpf_source = generate_bpf_program(args.port)
    try:
        b = BPF(text=bpf_source)
        function = b.load_func("packet_parser", BPF.SOCKET_FILTER)
        BPF.attach_raw_socket(function, args.interface)
    except Exception as e:
        print(f"[!] Failed to attach eBPF program: {e}")
        print("[!] Ensure you are running as root (`sudo python3 ebpf_telemetry.py`) on a supported Linux kernel.")
        print("[!] Falling back to simulation mode...\n")
        run_simulation(args.port, args.forward)
        return

    print(f"[+] eBPF bidirectional hooks attached to interface: {args.interface}")
    print(f"[+] Monitoring Inbound (dport {args.port}) & Outbound (sport {args.port}) TCP traffic")
    print("[+] Extracting 8 telemetries: packet_size, rate, ct_con, sinpkt, sttl, sjit, dmean, synack")
    print("[+] Press Ctrl+C to stop.\n")

    telemetry_map = b["telemetry_map"]

    try:
        while True:
            items = list(telemetry_map.items())
            for key, event in items:
                t = format_telemetry_vector(event)
                print_telemetry_summary(t)
                if args.forward:
                    forward_to_m4(t, args.forward)
                del telemetry_map[key]

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n[+] eBPF telemetry engine stopped.")

if __name__ == "__main__":
    main()
