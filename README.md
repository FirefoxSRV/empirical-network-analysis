# Packet Tracer Analysis

Packet Tracer Analysis is a lightweight toolkit for exploring packet capture (pcap/pcapng) files with Wireshark's `tshark` engine. The included analyzer streams packets directly from disk, extracts dozens of protocol-level signals, and emits both a machine-readable JSON report and a concise human summary so you can quickly understand what was happening on the wire.

## Highlights
- Summaries every capture with packet counters, byte totals, time span, throughput, and packet-length distributions.
- Breaks down traffic by protocol, OSI layers, top talkers, destination ports, and full conversations (src/dst pairs).
- Captures application-layer context such as HTTP hosts/requests/status codes, DNS queries/answers/response times, TLS SNI, QUIC packet types, and ARP request/reply timelines.
- Tracks transport statistics including TCP flag counts, retransmissions, RTT/bytes-in-flight stats, UDP length histograms, and per-second traffic bursts.
- Emits structured JSON that can feed notebooks (see `notebooks/analysis.ipynb`) or downstream dashboards, while still printing a quick CLI recap.

## Repository layout
```
Packet_Tracer_Analysis/
├── README.md                - You are here.
├── src/                     - Python sources (entry point: packet_analyzer.py).
├── data/
│   └── captures/            - Local packet captures (gitignored; .gitkeep keeps the tree).
├── artifacts/               - Generated analysis outputs (JSON/CSV/plots, gitignored).
├── notebooks/               - Exploratory notebooks consuming analyzer output.
├── docs/                    - Long-form notes (e.g. research_summary.json).
```
Place new packet captures under `data/captures/` and keep derived analysis artifacts in `artifacts/` so they do not clutter the repo history.

## Requirements
- Python 3.9+ (only standard library modules are used).
- Wireshark's CLI (`tshark`) available on your `PATH`.
  - macOS (Homebrew): `brew install wireshark` (then accept the `tshark` permissions prompt).
  - Linux (Debian/Ubuntu): `sudo apt install tshark`.
  - Verify with `tshark -v` before running the analyzer.

## Quick start
```bash
# 1) Optional: isolate dependencies
python3 -m venv .venv
source .venv/bin/activate

# 2) Nothing to pip install; the project uses only the stdlib.

# 3) Drop captures into data/captures/ (already gitignored)
ls data/captures

# 4) Run the analyzer
python src/packet_analyzer.py data/captures/idle.pcapng --json artifacts/idle.json --pretty
```
The command above will stream the capture, write a prettified JSON summary to `artifacts/idle.json`, and print a condensed textual digest to stdout.

### Scanning directories & limiting output
- Analyze every capture in a directory:
  ```bash
  python src/packet_analyzer.py --scan-dir data/captures --json artifacts/batch.json
  ```
- Control how many “top N” entries you see (defaults to 10): `--top 5`.
- Change the packet-length histogram bin size: `--hist-bin 64` (useful for zooming in on MTU-sized frames).
- Use the `--pretty` flag to pretty-print JSON output for manual review.

### Output anatomy
Each element in the emitted JSON array represents one capture and contains:
- `packet_count`, `total_bytes`, `duration_seconds`, throughput, packet-length statistics, and inter-arrival time stats.
- Protocol and layer breakdowns, top talkers, destination ports, and conversations.
- HTTP/DNS/TLS/QUIC/ARP/ICMP observations plus TCP/UDP deep dives (flags, retransmissions, RTT, UDP size histograms, etc.).
- Time-series friendly structures: per-second packet/byte counts, ARP event timeline, DNS response time samples, UDP length distributions.

Refer to `notebooks/analysis.ipynb` for examples of how to visualize these structures.

## Working with notebooks
1. Launch Jupyter: `jupyter notebook notebooks/analysis.ipynb` (inside your virtual environment if you created one).
2. Point the notebook at JSON exports in `artifacts/` to plot trends or compare captures.
3. Keep heavy notebook outputs out of Git by relying on the existing `.gitignore` rules (`.ipynb_checkpoints/` is already ignored).

## Extending the analyzer
- Add new tshark fields by editing `TSHARK_FIELDS` in `src/packet_analyzer.py` and updating the processing loop in `analyze_capture`.
- Create helper scripts in `src/` if you need automation for scheduled capture scans.
- Document research findings or methodology updates in `docs/` so future contributors can follow along.

## Troubleshooting
- **`Unable to locate 'tshark'`** – ensure Wireshark is installed and the binary is accessible (`which tshark`).
- **Permission denied on macOS** – the first run may prompt for packet capture permissions; accept via System Settings → Security & Privacy.
- **Large captures** – the analyzer streams packets and should handle multi-GB traces, but consider filtering with `tshark` beforehand if you only need specific flows.

Happy packet hunting!
