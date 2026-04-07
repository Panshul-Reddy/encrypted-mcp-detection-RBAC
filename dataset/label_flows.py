"""
label_flows.py — post-capture flow labeller

Processes one or more PCAP files, optionally gzip-compressed, and writes a CSV
in which each TCP flow is assigned one of three labels:

  0 — noise traffic      (dst_ip=10.10.0.20, dst_port=9443)
  1 — MCP SSE traffic    (dst_ip=10.10.0.10, dst_port=8443, long-lived downstream)
  2 — MCP RPC traffic    (dst_ip=10.10.0.10, dst_port=8443, request-response)

The script also computes flow-level features for downstream machine learning:
  - duration_s
  - total_pkts, total_bytes
  - pkts_up, pkts_down, bytes_up, bytes_down
  - mean/std/min/max of packet sizes in each direction
  - mean/std of inter-arrival times in each direction
  - first_N_pkt_sizes (first 20 packet sizes, zero-padded)
  - tls_record_lengths (parsed from plaintext TLS record headers)

Usage:
    pip install dpkt
    python label_flows.py ./capture/lab_20241101_120000.pcap
    python label_flows.py ./capture/*.pcap.gz       # glob also works
    python label_flows.py ./capture/lab*.pcap -o dataset.csv

Output CSV columns:
    flow_id, src_ip, src_port, dst_ip, dst_port, start_ts, end_ts,
    duration_s, total_pkts, total_bytes, pkts_up, pkts_down,
    bytes_up, bytes_down, mean_pkt_sz, std_pkt_sz, min_pkt_sz, max_pkt_sz,
    mean_iat, std_iat, mean_iat_up, mean_iat_down,
    pkt_sizes_0..19  (first 20 packet sizes, zero-padded),
    tls_up_0..19, tls_down_0..19  (directional TLS record lengths),
    label  (0=noise, 1=SSE, 2=RPC)
"""

import argparse
import csv
import gzip
import hashlib
import io
import ipaddress
import math
import os
import socket
import statistics
import struct
import sys
from collections import defaultdict
from pathlib import Path

try:
    import dpkt
except ImportError:
    sys.exit("Install dpkt first:  pip install dpkt")

# Lab network constants

MCP_IP    = "10.10.0.10"
MCP_PORT  = 8443
NOISE_IP  = "10.10.0.20"
NOISE_PORT = 9443

MCP_IP_INT   = struct.unpack("!I", socket.inet_aton(MCP_IP))[0]
NOISE_IP_INT = struct.unpack("!I", socket.inet_aton(NOISE_IP))[0]
SERVER_ENDPOINTS = {
    (MCP_IP_INT, MCP_PORT),
    (NOISE_IP_INT, NOISE_PORT),
}

# Bound packet-size and time samples so very long-lived flows do not consume
# unbounded memory while still allowing representative statistics.
MAX_PKT_SAMPLES = 5000

# Flow state

class Flow:
    __slots__ = [
        "src_ip", "src_port", "dst_ip", "dst_port",
        "start_ts", "end_ts",
        "pkts",           # list of (ts, direction, payload_len)  direction: 'up'|'down'
        "tls_records_up",
        "tls_records_down",
        "_tls_buf_up",    # running buffer for TLS record parsing (up direction)
        "_tls_buf_down",
    ]

    def __init__(self, src_ip, src_port, dst_ip, dst_port, ts):
        self.src_ip   = src_ip
        self.src_port = src_port
        self.dst_ip   = dst_ip
        self.dst_port = dst_port
        self.start_ts = ts
        self.end_ts   = ts
        self.pkts     = []
        self.tls_records_up = []
        self.tls_records_down = []
        self._tls_buf_up   = b""
        self._tls_buf_down = b""

    def add_packet(self, ts, direction, payload):
        self.end_ts = ts
        if len(self.pkts) < MAX_PKT_SAMPLES:
            self.pkts.append((ts, direction, len(payload)))
        # Parse TLS records from this payload fragment
        if direction == "up":
            self._tls_buf_up = self._parse_tls(
                self._tls_buf_up + payload,
                self.tls_records_up,
            )
        else:
            self._tls_buf_down = self._parse_tls(
                self._tls_buf_down + payload,
                self.tls_records_down,
            )

    def _parse_tls(self, buf: bytes, out_records: list) -> bytes:
        """
        Consume TLS records from the buffer.

        Each record contains:
          byte 0:   content type (20=change_cipher, 21=alert, 22=handshake, 23=app_data)
          bytes 1-2: version (0x0303 = TLS 1.2, 0x0303 = TLS 1.3)
          bytes 3-4: length (number of ciphertext bytes that follow)

        Returns any unconsumed bytes from a partial record.

        Protection: if corrupted or misaligned segments cause loss of framing
        synchronization, the buffer is capped at 4 MB to prevent unbounded memory
        growth during persistent parsing failures.
        """
        MAX_BUF_SIZE = 4 * 1024 * 1024  # 4 MB max recovery buffer
        while len(buf) >= 5:
            rec_type = buf[0]
            # Sanity check: TLS record types are 20–23.
            if rec_type not in (20, 21, 22, 23):
                # Framing synchronization was lost. Advance by one byte and retry
                # to avoid discarding subsequent valid records in this flow direction.
                buf = buf[1:]
                # If the buffer grows too large due to persistent corruption,
                # discard the oldest data to prevent memory exhaustion.
                if len(buf) > MAX_BUF_SIZE:
                    buf = buf[MAX_BUF_SIZE // 2:]
                continue
            rec_len = struct.unpack("!H", buf[3:5])[0]
            total   = 5 + rec_len
            if len(buf) < total:
                break    # Await additional data.
            # Record complete: store the length, not the content.
            if len(out_records) < 200:
                out_records.append(rec_len)
            buf = buf[total:]
        return buf


# Helpers

def _safe_mean(lst):  return statistics.mean(lst)   if lst else 0.0
def _safe_std(lst):   return statistics.stdev(lst)  if len(lst) > 1 else 0.0
def _safe_min(lst):   return min(lst)               if lst else 0
def _safe_max(lst):   return max(lst)               if lst else 0

def inter_arrivals(times):
    if len(times) < 2:
        return []
    return [times[i+1] - times[i] for i in range(len(times)-1)]

def pad(lst, n, fill=0):
    """Return the first n elements of lst, padded with fill if shorter."""
    return (list(lst[:n]) + [fill] * n)[:n]

def ip_int_to_str(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def session_id_for_flow(flow: Flow, bucket_s: int = 300) -> str:
    """Return a stable session identifier suitable for grouped splitting."""
    bucket = int(flow.start_ts // bucket_s) * bucket_s
    raw = (
        f"{ip_int_to_str(flow.src_ip)}:"
        f"{ip_int_to_str(flow.dst_ip)}:"
        f"{flow.dst_port}:{bucket}"
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20]

# Core processing

def label_flow(flow: Flow):
    """Return 1 for MCP traffic, 0 for noise traffic, or None for other flows."""
    dst = flow.dst_ip
    dport = flow.dst_port
    if dst == MCP_IP_INT   and dport == MCP_PORT:   return 1
    if dst == NOISE_IP_INT and dport == NOISE_PORT:  return 0
    # Also check the reverse direction (the flow is stored as initiator to responder,
    # but the capture may see the responder IP in src).
    src = flow.src_ip
    sport = flow.src_port
    if src == MCP_IP_INT   and sport == MCP_PORT:   return 1
    if src == NOISE_IP_INT and sport == NOISE_PORT:  return 0
    return None


def flow_to_row(flow_id: str, flow: Flow, label: int, include_endpoints: bool) -> dict:
    """Extract all features from a flow into a flat dict."""

    pkts_up   = [(ts, sz) for ts, d, sz in flow.pkts if d == "up"]
    pkts_down = [(ts, sz) for ts, d, sz in flow.pkts if d == "down"]

    all_sizes = [sz for _, _, sz in flow.pkts]
    sizes_up  = [sz for _, sz in pkts_up]
    sizes_down= [sz for _, sz in pkts_down]

    times_all = [ts for ts, _, _ in flow.pkts]
    times_up  = [ts for ts, _  in pkts_up]
    times_down= [ts for ts, _  in pkts_down]

    iats_all  = inter_arrivals(times_all)
    iats_up   = inter_arrivals(times_up)
    iats_down = inter_arrivals(times_down)

    duration = flow.end_ts - flow.start_ts
    bytes_up_total = sum(sizes_up)
    # MCP SSE channels are long-lived, mostly downstream, and include very few
    # upstream packets (TLS handshake plus a single initial HTTP GET request).
    # The heuristic checks for a downstream-heavy pattern and the absence of
    # sustained request-response cycles, which is indicated by sparse upstream packets.
    # SSE flows are typically long-lived (>10s), have minimal upstream traffic
    # (<= 5 packets), small upstream payloads (<2.5 KB), and an upstream payload
    # ratio below 15% of total traffic.
    bytes_down_total = sum(sizes_down)
    upstream_payload_ratio = bytes_up_total / max(bytes_up_total + bytes_down_total, 1)
    flow_type = "noise" if label == 0 else (
        "sse" if (duration > 10 and len(pkts_up) <= 5 and bytes_up_total < 2500 and upstream_payload_ratio < 0.15) else "rpc"
    )
    est_call_count = (sum(1 for iat in iats_up if iat > 0.5) + 1) if flow_type == "rpc" else 0

    # Three-class label: 0=noise, 1=SSE, 2=RPC. This enables sub-classification
    # of MCP traffic.
    label_3class = 0 if label == 0 else (1 if flow_type == "sse" else 2)

    row = {
        "flow_id":    flow_id,
        "session_id": session_id_for_flow(flow),
        "flow_type":  flow_type,
        "start_ts":   f"{flow.start_ts:.6f}",
        "end_ts":     f"{flow.end_ts:.6f}",
        "duration_s": f"{duration:.6f}",
        "total_pkts": len(flow.pkts),
        "total_bytes":sum(all_sizes),
        "pkts_up":    len(pkts_up),
        "pkts_down":  len(pkts_down),
        "bytes_up":   sum(sizes_up),
        "bytes_down": sum(sizes_down),
        "est_call_count": est_call_count,
        # Packet size statistics
        "mean_pkt_sz": f"{_safe_mean(all_sizes):.2f}",
        "std_pkt_sz":  f"{_safe_std(all_sizes):.2f}",
        "min_pkt_sz":  _safe_min(all_sizes),
        "max_pkt_sz":  _safe_max(all_sizes),
        "mean_pkt_sz_up":   f"{_safe_mean(sizes_up):.2f}",
        "mean_pkt_sz_down": f"{_safe_mean(sizes_down):.2f}",
        # Inter-arrival time statistics (seconds)
        "mean_iat":      f"{_safe_mean(iats_all):.6f}",
        "std_iat":       f"{_safe_std(iats_all):.6f}",
        "mean_iat_up":   f"{_safe_mean(iats_up):.6f}",
        "mean_iat_down": f"{_safe_mean(iats_down):.6f}",
        "std_iat_up":    f"{_safe_std(iats_up):.6f}",
        "std_iat_down":  f"{_safe_std(iats_down):.6f}",
        # Byte ratio features
        "byte_ratio_up": f"{sum(sizes_up)/max(sum(all_sizes),1):.4f}",
        "pkt_ratio_up":  f"{len(pkts_up)/max(len(flow.pkts),1):.4f}",
    }

    if include_endpoints:
        row["src_ip"] = ip_int_to_str(flow.src_ip)
        row["src_port"] = flow.src_port
        row["dst_ip"] = ip_int_to_str(flow.dst_ip)
        row["dst_port"] = flow.dst_port

    # First 20 packet sizes across all directions, in chronological order.
    for i, sz in enumerate(pad(all_sizes, 20)):
        row[f"pkt_sz_{i:02d}"] = sz

    # Directional TLS record lengths preserve client-to-server and server-to-client shape.
    for i, rlen in enumerate(pad(flow.tls_records_up, 20)):
        row[f"tls_up_{i:02d}"] = rlen
    for i, rlen in enumerate(pad(flow.tls_records_down, 20)):
        row[f"tls_down_{i:02d}"] = rlen

    # Use 3-class label instead of 2-class
    row["label"] = label_3class

    return row


def open_pcap(path: Path):
    """Open plain or gzip-compressed pcap by magic bytes."""
    with open(path, "rb") as fh:
        magic = fh.read(2)
    return gzip.open(path, "rb") if magic == b"\x1f\x8b" else open(path, "rb")


def process_pcap(path: Path, flows: dict, on_flow_complete) -> tuple[int, int]:
    """Parse one pcap file and emit finalized flows via callback."""
    pkt_count = 0
    completed_count = 0

    with open_pcap(path) as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception as e:
            print(f"  [!] Cannot open {path.name}: {e}", file=sys.stderr)
            return 0, 0

        for ts, raw in pcap:
            pkt_count += 1
            try:
                eth = dpkt.ethernet.Ethernet(raw)
            except Exception:
                continue
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue

            tcp    = ip.data
            src_ip = struct.unpack("!I", ip.src)[0]
            dst_ip = struct.unpack("!I", ip.dst)[0]
            sport  = tcp.sport
            dport  = tcp.dport

            if (dst_ip, dport) in SERVER_ENDPOINTS:
                # Client-to-server packet.
                key = (src_ip, sport, dst_ip, dport)
                direction = "up"
            elif (src_ip, sport) in SERVER_ENDPOINTS:
                # Server-to-client packet; keep the canonical key as
                # (client_ip, client_port, server_ip, server_port).
                key = (dst_ip, dport, src_ip, sport)
                direction = "down"
            else:
                # Ignore unrelated TCP traffic outside the known server endpoints.
                continue

            syn_start = bool((tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK))
            if syn_start and key in flows:
                on_flow_complete(flows.pop(key))
                completed_count += 1

            if key not in flows:
                # Initialize a new flow using the canonical direction.
                fip, fport, tip, tport = key
                flows[key] = Flow(fip, fport, tip, tport, ts)

            payload = bytes(tcp.data)
            if payload:
                flows[key].add_packet(ts, direction, payload)

    return pkt_count, completed_count


# CLI

def main():
    parser = argparse.ArgumentParser(
        description="Label TCP flows in PCAP files as MCP (1-2) or noise (0)")
    parser.add_argument("pcaps", nargs="+", help="pcap or pcap.gz files")
    parser.add_argument("-o", "--output", default="labels.csv",
                        help="Output CSV path (default: labels.csv)")
    parser.add_argument("--min-pkts", type=int, default=6,
                        help="Skip flows with fewer than N packets (default: 6, filters out handshake noise)")
    parser.add_argument("--include-endpoints", action="store_true",
                        help="Include src/dst IP and port metadata in output CSV")
    args = parser.parse_args()

    flows: dict = {}

    labelled = skipped_label = skipped_pkts = 0
    sse_count = noise_count = rpc_count = 0
    flow_seq = 0
    total_packets = 0
    total_completed = 0

    with open(args.output, "w", newline="") as out_fh:
        writer = None

        def emit_flow(flow: Flow):
            nonlocal labelled, skipped_label, skipped_pkts
            nonlocal sse_count, noise_count, rpc_count, flow_seq, writer
            if len(flow.pkts) < args.min_pkts:
                skipped_pkts += 1
                return
            label = label_flow(flow)
            if label is None:
                skipped_label += 1
                return

            flow_id = f"flow_{flow_seq:08d}"
            flow_seq += 1
            row = flow_to_row(flow_id, flow, label, args.include_endpoints)

            if writer is None:
                writer = csv.DictWriter(out_fh, fieldnames=list(row.keys()))
                writer.writeheader()
            writer.writerow(row)

            labelled += 1
            if label == 0:
                noise_count += 1
            elif row["label"] == 1:
                sse_count += 1
            else:
                rpc_count += 1

        # Sort PCAP paths chronologically to prevent cross-boundary flow corruption.
        # Filenames are timestamped (for example, mcp_20250401_074659.pcap), so
        # lexicographic sorting is correct. Without sorting, flows active at rotation
        # time may be split across two files and reconstructed incorrectly.
        for pcap_path_str in sorted(args.pcaps):
            path = Path(pcap_path_str)
            if not path.exists():
                print(f"[!] Not found: {path}", file=sys.stderr)
                continue

            print(f"[*] Processing {path.name} ...")
            n_pkts, n_completed = process_pcap(path, flows, emit_flow)
            total_packets += n_pkts
            total_completed += n_completed
            print(
                f"    {n_pkts:,} packets read, {len(flows):,} active flows, "
                f"{n_completed:,} finalized"
            )

        # Finalize all flows still open at EOF.
        remaining = list(flows.values())
        for flow in remaining:
            emit_flow(flow)

    print(f"\n[*] Total packets: {total_packets:,}")
    print(f"[*] Total flows: {(total_completed + len(flows)):,}")

    if labelled == 0:
        print("[!] No labelled flows found. Check IP/port constants.", file=sys.stderr)
        sys.exit(1)

    print(f"\n[*] Labelled flows written to {args.output}")
    print(f"    Noise     (label=0): {noise_count:,}")
    print(f"    SSE       (label=1): {sse_count:,}")
    print(f"    RPC       (label=2): {rpc_count:,}")
    print(f"    Skipped (not lab traffic): {skipped_label:,}")
    print(f"    Skipped (< {args.min_pkts} pkts):       {skipped_pkts:,}")
    mcp_total = sse_count + rpc_count
    if labelled > 0:
        print(f"    Class balance: {mcp_total/labelled*100:.1f}% MCP (SSE {sse_count}, RPC {rpc_count})")


if __name__ == "__main__":
    main()
