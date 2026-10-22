from bcc import BPF
import socket
import struct
import time

INTERFACE = "eth0"

bpf_program = r"""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>

struct event_t {
    u32 src_ip;
    u16 dst_port;
    u32 packet_size;
};

BPF_HASH(telemetry_map, u32, struct event_t, 1024);
BPF_ARRAY(packet_counter, u32, 1);

int packet_parser(struct __sk_buff *skb)
{
    u32 zero = 0;
    u32 key;

    unsigned char eth[14];
    unsigned char ip_header[20];
    unsigned char tcp_header[20];

    if (skb->len < 34)
        return 0;

    /* Read Ethernet header */
    if (bpf_skb_load_bytes(skb, 0, eth, 14) < 0)
        return 0;

    /* Check IPv4 */
    if (eth[12] != 0x08 || eth[13] != 0x00)
        return 0;

    /* Read IPv4 header */
    if (bpf_skb_load_bytes(skb, 14, ip_header, 20) < 0)
        return 0;

    /* Check TCP protocol */
    if (ip_header[9] != 6)
        return 0;

    u32 ip_header_len = (ip_header[0] & 0x0F) * 4;

    if (ip_header_len < 20)
        return 0;

    if (skb->len < 14 + ip_header_len + 20)
        return 0;

    /* Read TCP header */
    if (bpf_skb_load_bytes(
            skb,
            14 + ip_header_len,
            tcp_header,
            20) < 0)
        return 0;

    struct event_t event = {};

    /* Source IP */
    event.src_ip =
        (ip_header[12]) |
        (ip_header[13] << 8) |
        (ip_header[14] << 16) |
        (ip_header[15] << 24);

    /* Destination port */
    event.dst_port =
        ((u16)tcp_header[2] << 8) |
        tcp_header[3];

    /* Packet size */
    event.packet_size = skb->len;

    /* Generate unique map key */
    u32 *counter = packet_counter.lookup(&zero);

    if (!counter)
        return 0;

    key = *counter;

    if (key >= 1024)
        key = 0;

    key++;

    packet_counter.update(&zero, &key);

    telemetry_map.update(&key, &event);

    return 0;
}
"""

print("[+] Loading eBPF program...")

b = BPF(text=bpf_program)

function = b.load_func(
    "packet_parser",
    BPF.SOCKET_FILTER
)

BPF.attach_raw_socket(function, INTERFACE)

print("[+] eBPF program attached to:", INTERFACE)
print("[+] Listening for TCP packets...")
print("[+] Press Ctrl+C to stop.\n")

telemetry_map = b["telemetry_map"]

try:
    while True:

        items = list(telemetry_map.items())

        for key, event in items:

            src_ip = socket.inet_ntoa(
                struct.pack("=I", event.src_ip)
            )

            print(
                f"[TCP] Source IP: {src_ip:<15} "
                f"Destination Port: {event.dst_port:<5} "
                f"Packet Size: {event.packet_size} bytes"
            )

            del telemetry_map[key]

        time.sleep(0.2)

except KeyboardInterrupt:
    print("\n[+] eBPF telemetry stopped.")
