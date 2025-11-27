#!/usr/bin/env python3
"""
Packet capture analyzer built on top of tshark.

The script parses PCAP/PCAPNG files and produces a set of rich metrics such as:
* time span, packet and byte counters
* protocol distribution (high level column + underlying layers)
* talker statistics (top sources/destinations, destination ports, conversations)
* application insights (HTTP hosts/requests, DNS queries & answers, TLS SNI, ARP)

Example:
    python packet_analyzer.py idle.pcapng netflix.pcapng --pretty --json analysis.json
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence


# Fields pulled from tshark for every packet. Keep this list small to avoid
# unnecessary decoding overhead.
TSHARK_FIELDS: Sequence[str] = (
    "frame.time_epoch",
    "frame.len",
    "_ws.col.Protocol",
    "frame.protocols",
    "frame.interface_id",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "arp.opcode",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "http.host",
    "http.request.method",
    "http.request.full_uri",
    "http.response.code",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "dns.time",
    "tls.handshake.extensions_server_name",
    "quic.header_form",
    "quic.long.packet_type",
    "ip.ttl",
    "ipv6.hlim",
    "ip.hdr_len",
    "icmp.type",
    "icmp.code",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.analysis.retransmission",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.bytes_in_flight",
    "tcp.len",
)


@dataclass
class PacketStats:
    packet_count: int = 0
    total_bytes: int = 0
    min_len: Optional[int] = None
    max_len: Optional[int] = None
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    def update(self, length: int, timestamp: Optional[float]) -> None:
        self.packet_count += 1
        self.total_bytes += length
        if self.min_len is None or length < self.min_len:
            self.min_len = length
        if self.max_len is None or length > self.max_len:
            self.max_len = length
        if timestamp is not None:
            if self.first_ts is None or timestamp < self.first_ts:
                self.first_ts = timestamp
            if self.last_ts is None or timestamp > self.last_ts:
                self.last_ts = timestamp


@dataclass
class RunningStat:
    count: int = 0
    total: float = 0.0
    min_value: Optional[float] = None
    max_value: Optional[float] = None

    def update(self, value: Optional[float]) -> None:
        if value is None:
            return
        self.count += 1
        self.total += value
        if self.min_value is None or value < self.min_value:
            self.min_value = value
        if self.max_value is None or value > self.max_value:
            self.max_value = value

    def as_dict(self) -> Dict[str, Optional[float]]:
        avg = (self.total / self.count) if self.count else None
        return {
            "count": self.count,
            "average": avg,
            "min": self.min_value,
            "max": self.max_value,
        }


def ensure_tshark_available(executable: str) -> None:
    """Ensure tshark exists early to provide a friendly error."""
    if shutil.which(executable):
        return
    raise SystemExit(
        f"Unable to locate '{executable}'. Install Wireshark/tshark or point to the binary via --tshark-bin."
    )


def _run_tshark(
    capture: Path, fields: Sequence[str], tshark_bin: str
) -> Iterator[Dict[str, str]]:
    """Yield decoded packets as dictionaries keyed by tshark field name."""
    cmd = [
        tshark_bin,
        "-r",
        str(capture),
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in fields:
        cmd.extend(["-e", field])

    # Stream output to avoid loading the whole capture into memory.
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert process.stdout is not None  # nosec - satisfied right above
    reader = csv.reader(process.stdout)
    for row in reader:
        if not row:
            continue
        data = {}
        for idx, field in enumerate(fields):
            if idx < len(row) and row[idx]:
                data[field] = row[idx]
        yield data

    # Drain stderr so a full pipe does not deadlock wait()
    stderr = process.stderr.read() if process.stderr else ""
    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(
            f"tshark exited with status {return_code} while processing {capture}\n{stderr.strip()}"
        )


def _parse_float(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _parse_int(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _split_multi_value(value: Optional[str]) -> Iterable[str]:
    if not value:
        return ()
    return (item.strip() for item in value.split(",") if item.strip())


def _format_timestamp(epoch: Optional[float]) -> Optional[str]:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _counter_to_list(counter: Counter, limit: Optional[int] = None, value_key: str = "value") -> List[Dict[str, object]]:
    most_common = counter.most_common(limit if limit is not None else None)
    return [{value_key: key, "packets": count} for key, count in most_common]


def _histogram_to_distribution(histogram: Counter, total_packets: int, bin_size: int) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    if bin_size <= 0:
        bin_size = 1
    for bucket in sorted(histogram):
        start = bucket * bin_size
        end = start + bin_size - 1
        count = histogram[bucket]
        percentage = (count / total_packets * 100) if total_packets else 0.0
        results.append(
            {
                "range": f"{start}-{end}",
                "start": start,
                "end": end,
                "packets": count,
                "percentage": percentage,
            }
        )
    return results


def analyze_capture(
    capture: Path, tshark_bin: str, limit: int = 10, hist_bin: int = 100
) -> Dict[str, object]:
    stats = PacketStats()
    protocol_counter: Counter = Counter()
    layer_counter: Counter = Counter()
    src_counter: Counter = Counter()
    dst_counter: Counter = Counter()
    port_counter: Counter = Counter()
    conversation_counter: Counter = Counter()
    http_host_counter: Counter = Counter()
    http_request_counter: Counter = Counter()
    dns_query_counter: Counter = Counter()
    dns_answer_counter: Counter = Counter()
    tls_sni_counter: Counter = Counter()
    arp_counter: Counter = Counter()
    arp_opcode_counter: Counter = Counter()
    interface_counter: Counter = Counter()
    interface_bytes: Counter = Counter()
    tcp_flag_counter: Counter = Counter()
    tcp_retransmissions = 0
    tcp_payload_bytes = 0
    icmp_counter: Counter = Counter()
    http_status_counter: Counter = Counter()
    ttl_counter: Counter = Counter()
    hop_limit_counter: Counter = Counter()
    ip_header_len_counter: Counter = Counter()
    packet_length_histogram: Counter = Counter()
    inter_arrival = RunningStat()
    prev_timestamp: Optional[float] = None
    per_second_packets: Counter = Counter()
    per_second_bytes: Counter = Counter()
    udp_packet_count = 0
    udp_total_bytes = 0
    udp_length_histogram: Counter = Counter()
    udp_port_counter: Counter = Counter()
    tcp_connections: set = set()
    tcp_syn_packets = 0
    tcp_synack_packets = 0
    tcp_fin_packets = 0
    tcp_rst_packets = 0
    tcp_rtt_stats = RunningStat()
    tcp_bytes_in_flight_stats = RunningStat()
    quic_packet_types: Counter = Counter()
    arp_request_count = 0
    arp_reply_count = 0
    arp_requesters: Counter = Counter()
    arp_targets: Counter = Counter()
    arp_responders: Counter = Counter()
    arp_events: List[Dict[str, object]] = []
    last_arp_request_ts: Optional[float] = None
    arp_request_intervals = RunningStat()
    dns_response_time_stats = RunningStat()
    dns_response_times: List[float] = []

    for packet in _run_tshark(capture, TSHARK_FIELDS, tshark_bin):
        timestamp = _parse_float(packet.get("frame.time_epoch"))
        length = _parse_int(packet.get("frame.len")) or 0
        stats.update(length, timestamp)
        if hist_bin > 0:
            bucket = length // hist_bin
        else:
            bucket = length
        packet_length_histogram[bucket] += 1
        if prev_timestamp is not None and timestamp is not None:
            delta = max(0.0, timestamp - prev_timestamp)
            inter_arrival.update(delta)
        if timestamp is not None:
            prev_timestamp = timestamp
            second = int(timestamp)
            per_second_packets[second] += 1
            per_second_bytes[second] += length

        protocol = packet.get("_ws.col.Protocol") or ""
        if protocol:
            protocol_counter[protocol] += 1

        layers = packet.get("frame.protocols")
        if layers:
            for layer in layers.split(":"):
                if layer:
                    layer_counter[layer] += 1

        src_ip = packet.get("ip.src") or packet.get("ipv6.src") or packet.get("arp.src.proto_ipv4")
        dst_ip = packet.get("ip.dst") or packet.get("ipv6.dst") or packet.get("arp.dst.proto_ipv4")

        if src_ip:
            src_counter[src_ip] += 1
        if dst_ip:
            dst_counter[dst_ip] += 1

        tcp_src = packet.get("tcp.srcport")
        tcp_dst = packet.get("tcp.dstport")
        udp_src = packet.get("udp.srcport")
        udp_dst = packet.get("udp.dstport")

        l4_proto = None
        src_port = None
        dst_port = None

        if tcp_src or tcp_dst:
            l4_proto = "TCP"
            src_port = tcp_src
            dst_port = tcp_dst
        elif udp_src or udp_dst:
            l4_proto = "UDP"
            src_port = udp_src
            dst_port = udp_dst

        if l4_proto and dst_port:
            port_counter[(l4_proto, dst_port)] += 1

        if src_ip and dst_ip:
            key = (l4_proto or protocol or "UNKNOWN", src_ip, src_port or "-", dst_ip, dst_port or "-")
            conversation_counter[key] += 1
            if l4_proto == "TCP" and src_port and dst_port:
                conn_key = (src_ip, src_port, dst_ip, dst_port)
                rev_key = (dst_ip, dst_port, src_ip, src_port)
                tcp_connections.add(conn_key if conn_key <= rev_key else rev_key)

        http_host = packet.get("http.host")
        if http_host:
            http_host_counter[http_host.lower()] += 1

        http_method = packet.get("http.request.method")
        http_uri = packet.get("http.request.full_uri") or http_host
        if http_uri:
            http_request_counter[(http_method or "UNKNOWN", http_uri)] += 1

        http_status = packet.get("http.response.code")
        if http_status:
            http_status_counter[http_status] += 1

        dns_query = packet.get("dns.qry.name")
        if dns_query:
            dns_query_counter[dns_query.lower()] += 1

        for answer in _split_multi_value(packet.get("dns.a")):
            dns_answer_counter[("A", answer)] += 1
        for answer in _split_multi_value(packet.get("dns.aaaa")):
            dns_answer_counter[("AAAA", answer)] += 1

        for sni in _split_multi_value(packet.get("tls.handshake.extensions_server_name")):
            tls_sni_counter[sni.lower()] += 1

        if packet.get("arp.src.proto_ipv4") or packet.get("arp.dst.proto_ipv4"):
            key = (
                packet.get("arp.src.proto_ipv4") or "-",
                packet.get("arp.dst.proto_ipv4") or "-",
            )
            arp_counter[key] += 1

        interface_id = packet.get("frame.interface_id")
        if interface_id:
            interface_counter[interface_id] += 1
            interface_bytes[interface_id] += length

        ttl = _parse_int(packet.get("ip.ttl"))
        if ttl is not None:
            ttl_counter[ttl] += 1

        hop_limit = _parse_int(packet.get("ipv6.hlim"))
        if hop_limit is not None:
            hop_limit_counter[hop_limit] += 1

        ip_hdr_len = _parse_int(packet.get("ip.hdr_len"))
        if ip_hdr_len is not None:
            ip_header_len_counter[ip_hdr_len] += 1

        icmp_type = packet.get("icmp.type")
        if icmp_type:
            icmp_code = packet.get("icmp.code") or "0"
            icmp_counter[(icmp_type, icmp_code)] += 1

        tcp_len = _parse_int(packet.get("tcp.len"))
        if tcp_len:
            tcp_payload_bytes += tcp_len

        if packet.get("tcp.analysis.retransmission"):
            tcp_retransmissions += 1

        syn_flag = packet.get("tcp.flags.syn") in ("1", "True")
        ack_flag = packet.get("tcp.flags.ack") in ("1", "True")
        fin_flag = packet.get("tcp.flags.fin") in ("1", "True")
        rst_flag = packet.get("tcp.flags.reset") in ("1", "True")

        if syn_flag:
            tcp_flag_counter["SYN"] += 1
            tcp_syn_packets += 1
        if ack_flag:
            tcp_flag_counter["ACK"] += 1
        if fin_flag:
            tcp_flag_counter["FIN"] += 1
            tcp_fin_packets += 1
        if rst_flag:
            tcp_flag_counter["RST"] += 1
            tcp_rst_packets += 1
        if syn_flag and ack_flag:
            tcp_synack_packets += 1

        tcp_rtt_stats.update(_parse_float(packet.get("tcp.analysis.ack_rtt")))
        tcp_bytes_in_flight_stats.update(_parse_float(packet.get("tcp.analysis.bytes_in_flight")))

        udp_len_value = _parse_int(packet.get("udp.length"))
        if l4_proto == "UDP":
            udp_packet_count += 1
            udp_total_bytes += length
            length_for_hist = udp_len_value if udp_len_value is not None else length
            bucket = length_for_hist // hist_bin if hist_bin > 0 else length_for_hist
            udp_length_histogram[bucket] += 1
            if udp_dst:
                udp_port_counter[udp_dst] += 1
            elif udp_src:
                udp_port_counter[udp_src] += 1

        quic_header_form_value = _parse_int(packet.get("quic.header_form"))
        quic_long_type_value = _parse_int(packet.get("quic.long.packet_type"))
        quic_label = None
        if quic_header_form_value is not None:
            if quic_header_form_value:
                quic_label = {
                    0: "Initial",
                    1: "0-RTT",
                    2: "Handshake",
                    3: "Retry",
                }.get(quic_long_type_value, f"Long-{quic_long_type_value}" if quic_long_type_value is not None else "Long")
            else:
                quic_label = "Short"
        elif quic_long_type_value is not None:
            quic_label = {
                0: "Initial",
                1: "0-RTT",
                2: "Handshake",
                3: "Retry",
            }.get(quic_long_type_value, f"Long-{quic_long_type_value}")
        if quic_label:
            quic_packet_types[quic_label] += 1

        dns_time = _parse_float(packet.get("dns.time"))
        if dns_time is not None:
            dns_response_time_stats.update(dns_time)
            dns_response_times.append(dns_time)

        arp_opcode = packet.get("arp.opcode")
        arp_opcode = packet.get("arp.opcode")
        if arp_opcode:
            arp_opcode_counter[arp_opcode] += 1
            if arp_opcode == "1":
                arp_request_count += 1
                if src_ip:
                    arp_requesters[src_ip] += 1
                if dst_ip:
                    arp_targets[dst_ip] += 1
                if timestamp is not None:
                    arp_events.append(
                        {"timestamp": timestamp, "opcode": "request"}
                    )
                    if last_arp_request_ts is not None:
                        arp_request_intervals.update(max(0.0, timestamp - last_arp_request_ts))
                    last_arp_request_ts = timestamp
            elif arp_opcode == "2":
                arp_reply_count += 1
                if src_ip:
                    arp_responders[src_ip] += 1
                if timestamp is not None:
                    arp_events.append(
                        {"timestamp": timestamp, "opcode": "reply"}
                    )


    duration = (
        stats.last_ts - stats.first_ts if stats.first_ts is not None and stats.last_ts is not None else None
    )
    avg_len = (stats.total_bytes / stats.packet_count) if stats.packet_count else None
    packets_per_second = (stats.packet_count / duration) if duration and duration > 0 else None
    bits_per_second = ((stats.total_bytes * 8) / duration) if duration and duration > 0 else None
    per_second_series: List[Dict[str, object]] = []
    if per_second_packets:
        start_second = min(per_second_packets)
        end_second = max(per_second_packets)
        base = start_second
        for second in range(start_second, end_second + 1):
            per_second_series.append(
                {
                    "second_epoch": second,
                    "offset_seconds": second - base,
                    "packets": per_second_packets.get(second, 0),
                    "bytes": per_second_bytes.get(second, 0),
                }
            )
    arp_timeline: List[Dict[str, object]] = []
    base_ts = stats.first_ts
    for event in arp_events:
        timestamp = event.get("timestamp")
        arp_timeline.append(
            {
                "timestamp": timestamp,
                "offset_seconds": (timestamp - base_ts) if (timestamp is not None and base_ts is not None) else None,
                "opcode": event.get("opcode"),
            }
        )
    protocol_percentages_full = [
        {
            "value": proto,
            "packets": count,
            "percentage": (count / stats.packet_count * 100) if stats.packet_count else 0.0,
        }
        for proto, count in protocol_counter.most_common()
    ]

    analysis: Dict[str, object] = {
        "file": str(capture),
        "file_size_bytes": capture.stat().st_size if capture.exists() else None,
        "packet_count": stats.packet_count,
        "total_bytes": stats.total_bytes,
        "time_start_utc": _format_timestamp(stats.first_ts),
        "time_end_utc": _format_timestamp(stats.last_ts),
        "duration_seconds": duration,
        "min_packet_size_bytes": stats.min_len,
        "max_packet_size_bytes": stats.max_len,
        "average_packet_size_bytes": avg_len,
        "packets_per_second": packets_per_second,
        "throughput_bps": bits_per_second,
        "protocol_breakdown": _counter_to_list(protocol_counter, limit),
        "protocol_breakdown_full": _counter_to_list(protocol_counter, None),
        "protocol_percentages": [
            {
                "value": proto,
                "packets": count,
                "percentage": (count / stats.packet_count * 100) if stats.packet_count else 0.0,
            }
            for proto, count in protocol_counter.most_common(limit)
        ],
        "protocol_percentages_full": protocol_percentages_full,
        "layer_breakdown": _counter_to_list(layer_counter, limit),
        "top_sources": _counter_to_list(src_counter, limit, value_key="ip"),
        "top_destinations": _counter_to_list(dst_counter, limit, value_key="ip"),
        "top_destination_ports": [
            {"protocol": proto, "port": port, "packets": count}
            for (proto, port), count in port_counter.most_common(limit)
        ],
        "top_conversations": [
            {
                "protocol": proto,
                "src": src,
                "src_port": src_port,
                "dst": dst,
                "dst_port": dst_port,
                "packets": count,
            }
            for (proto, src, src_port, dst, dst_port), count in conversation_counter.most_common(limit)
        ],
        "http_hosts": _counter_to_list(http_host_counter, limit, value_key="host"),
        "http_requests": [
            {"method": method, "target": target, "packets": count}
            for (method, target), count in http_request_counter.most_common(limit)
        ],
        "dns_queries": _counter_to_list(dns_query_counter, limit, value_key="query"),
        "dns_answers": [
            {"record_type": record_type, "value": value, "packets": count}
            for (record_type, value), count in dns_answer_counter.most_common(limit)
        ],
        "tls_server_names": _counter_to_list(tls_sni_counter, limit, value_key="server_name"),
        "arp_activity": [
            {"src_ip": src, "dst_ip": dst, "packets": count} for (src, dst), count in arp_counter.most_common(limit)
        ],
        "arp_opcodes": _counter_to_list(arp_opcode_counter, limit, value_key="opcode"),
        "icmp_messages": [
            {"type": type_code[0], "code": type_code[1], "packets": count}
            for type_code, count in icmp_counter.most_common(limit)
        ],
        "http_status_codes": _counter_to_list(http_status_counter, limit, value_key="status"),
        "interfaces": [
            {
                "interface_id": interface_id,
                "packets": packets,
                "bytes": interface_bytes.get(interface_id, 0),
                "percentage": (packets / stats.packet_count * 100) if stats.packet_count else 0.0,
            }
            for interface_id, packets in interface_counter.most_common(limit)
        ],
        "packet_length_distribution": _histogram_to_distribution(
            packet_length_histogram, stats.packet_count, hist_bin
        ),
        "udp_length_distribution": _histogram_to_distribution(udp_length_histogram, udp_packet_count, hist_bin),
        "ttl_distribution": _counter_to_list(ttl_counter, limit, value_key="ttl"),
        "hop_limit_distribution": _counter_to_list(hop_limit_counter, limit, value_key="hop_limit"),
        "ip_header_length_distribution": _counter_to_list(
            ip_header_len_counter, limit, value_key="header_length_bytes"
        ),
        "tcp_flags": _counter_to_list(tcp_flag_counter, limit, value_key="flag"),
        "tcp_retransmissions": tcp_retransmissions,
        "tcp_payload_bytes": tcp_payload_bytes,
        "tcp_connection_count": len(tcp_connections),
        "tcp_syn_packets": tcp_syn_packets,
        "tcp_synack_packets": tcp_synack_packets,
        "tcp_fin_packets": tcp_fin_packets,
        "tcp_rst_packets": tcp_rst_packets,
        "tcp_rtt_stats": tcp_rtt_stats.as_dict(),
        "tcp_bytes_in_flight_stats": tcp_bytes_in_flight_stats.as_dict(),
        "udp_packet_count": udp_packet_count,
        "udp_total_bytes": udp_total_bytes,
        "udp_top_ports": _counter_to_list(udp_port_counter, limit, value_key="port"),
        "quic_packet_types": _counter_to_list(quic_packet_types, None, value_key="packet_type"),
        "arp_summary": {
            "request_count": arp_request_count,
            "reply_count": arp_reply_count,
            "request_interval_stats": arp_request_intervals.as_dict(),
            "top_requesters": _counter_to_list(arp_requesters, limit, value_key="ip"),
            "top_targets": _counter_to_list(arp_targets, limit, value_key="ip"),
            "top_responders": _counter_to_list(arp_responders, limit, value_key="ip"),
        },
        "arp_events": arp_timeline,
        "packet_interarrival_stats": inter_arrival.as_dict(),
        "per_second_traffic": per_second_series,
        "dns_response_time_stats": dns_response_time_stats.as_dict(),
        "dns_response_times": dns_response_times,
    }

    return analysis


def collect_captures(paths: Sequence[Path], scan_dir: Optional[Path]) -> List[Path]:
    captures: List[Path] = []
    for path in paths:
        if path.exists() and path.is_file():
            captures.append(path)
        else:
            raise SystemExit(f"Capture '{path}' was not found.")

    if scan_dir:
        for ext in ("*.pcap", "*.pcapng", "*.pcap.gz"):
            for candidate in sorted(scan_dir.glob(ext)):
                if candidate not in captures:
                    captures.append(candidate)

    if not captures:
        raise SystemExit("Provide at least one capture file or a directory to scan.")
    return captures


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze packet captures via tshark.")
    parser.add_argument(
        "captures",
        nargs="*",
        type=Path,
        help="Explicit capture files to analyze (pcap/pcapng).",
    )
    parser.add_argument(
        "--scan-dir",
        type=Path,
        help="Optional directory to scan for *.pcap* files.",
    )
    parser.add_argument(
        "--tshark-bin",
        default="tshark",
        help="Path to the tshark executable (default: %(default)s).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Limit for the number of top entries to report (default: %(default)s).",
    )
    parser.add_argument(
        "--hist-bin",
        type=int,
        default=100,
        help="Bin size (in bytes) for packet length distribution (default: %(default)s).",
    )
    parser.add_argument(
        "--json",
        type=Path,
        help="Optional path to write the aggregated analysis as JSON.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output when --json is provided.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ensure_tshark_available(args.tshark_bin)
    captures = collect_captures(args.captures, args.scan_dir)

    summaries = []
    for capture in captures:
        print(f"Analyzing {capture} ...", file=sys.stderr)
        summary = analyze_capture(capture, args.tshark_bin, args.top, args.hist_bin)
        summaries.append(summary)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        with args.json.open("w", encoding="utf-8") as handle:
            json.dump(summaries, handle, indent=2 if args.pretty else None)
        print(f"Wrote JSON output to {args.json}", file=sys.stderr)

    # Emit a compact human readable view for quick inspection.
    for summary in summaries:
        print(f"\n=== {summary['file']} ===")
        print(f"Packets: {summary['packet_count']:,}  Bytes: {summary['total_bytes']:,}")
        duration = summary.get("duration_seconds")
        if duration:
            print(f"Duration: {duration:.4f}s  Throughput: {summary.get('throughput_bps', 0):.2f} bps")
        print("Top protocols:")
        for entry in summary["protocol_breakdown"]:
            print(f"  - {entry['value']}: {entry['packets']}")
        print("Top talkers (src -> dst):")
        for convo in summary["top_conversations"][:5]:
            print(
                f"  - {convo['protocol']} {convo['src']}:{convo['src_port']} -> "
                f"{convo['dst']}:{convo['dst_port']} ({convo['packets']} pkt)"
            )
        if summary["packet_length_distribution"]:
            print("Packet length distribution (sample bins):")
            for bucket in summary["packet_length_distribution"][:5]:
                print(
                    f"  - {bucket['range']} bytes: {bucket['packets']} pkt "
                    f"({bucket['percentage']:.2f}%)"
                )
        if summary["tcp_flags"]:
            print("TCP flag occurrences:")
            for flag_entry in summary["tcp_flags"]:
                print(f"  - {flag_entry['flag']}: {flag_entry['packets']}")
        if summary["http_status_codes"]:
            print("HTTP status codes observed:")
            for status_entry in summary["http_status_codes"]:
                print(f"  - {status_entry['status']}: {status_entry['packets']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
