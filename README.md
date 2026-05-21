# Java Network Packet Sniffer

A command-line network packet sniffer built with **Java + Pcap4J**.  
Captures live packets from any network interface and decodes layers 2–7.

---

## Features

| Feature | Detail |
|---|---|
| **Live capture** | Captures packets in real time from any NIC |
| **Promiscuous mode** | Sees all traffic on the segment, not just your host |
| **Protocol decoding** | Ethernet → IPv4/IPv6 → TCP/UDP/ICMP/ARP |
| **App-layer detection** | Identifies HTTP, HTTPS/TLS, DNS, SSH, FTP, SMTP, DHCP, and more |
| **BPF filters** | Uses standard Berkeley Packet Filter expressions |
| **Save to file** | Writes `.pcap` files readable in Wireshark |
| **Live statistics** | Packets/sec, bytes/sec, total counts on exit |
| **Hex dump** | Shows first 64 bytes of HTTP payloads |
| **Color-coded output** | TCP=Cyan, UDP=Yellow, ICMP=Green, ARP=Magenta, HTTP=White, TLS=Blue |

---

## Prerequisites

### 1. Install Java 11+
```bash
java -version   # Should show 11 or higher
```

### 2. Install Maven
```bash
mvn -version
```

### 3. Install libpcap (the native capture library)

| OS | Command |
|---|---|
| **Ubuntu/Debian** | `sudo apt install libpcap-dev` |
| **Fedora/RHEL** | `sudo dnf install libpcap-devel` |
| **macOS** | Built-in (Homebrew: `brew install libpcap`) |
| **Windows** | Install [Npcap](https://npcap.com/#download) (choose "WinPcap compatible" mode) |

---

## Build

```bash
cd packet-sniffer
mvn clean package -q
```

This produces:  
`target/packet-sniffer-1.0.0-jar-with-dependencies.jar`

---

## Run

> **Linux/macOS:** You need root (or `CAP_NET_RAW` capability) to capture packets.

```bash
# List interfaces and pick one interactively
sudo java -jar target/packet-sniffer-1.0.0-jar-with-dependencies.jar

# Capture on a specific interface
sudo java -jar target/packet-sniffer-1.0.0-jar-with-dependencies.jar -i eth0

# Capture only 50 packets then stop
sudo java -jar target/packet-sniffer-1.0.0-jar-with-dependencies.jar -i eth0 -c 50

# Capture only TCP port 80 traffic (HTTP)
sudo java -jar target/packet-sniffer-1.0.0-jar-with-dependencies.jar -i eth0 -f "tcp port 80"

# Save to Wireshark-compatible file
sudo java -jar target/packet-sniffer-1.0.0-jar-with-dependencies.jar -i eth0 --save capture.pcap

# Combine: capture DNS traffic and save it
sudo java -jar target/packet-sniffer-1.0.0-jar-with-dependencies.jar -i eth0 -f "udp port 53" --save dns.pcap
```

### Windows (PowerShell as Administrator)
```powershell
java -jar target\packet-sniffer-1.0.0-jar-with-dependencies.jar -i "\Device\NPF_{GUID}"
```

---

## BPF Filter Examples

BPF (Berkeley Packet Filter) is the industry-standard filter language:

| Goal | Filter |
|---|---|
| Only TCP | `tcp` |
| Only UDP | `udp` |
| Specific port | `port 443` |
| HTTP traffic | `tcp port 80` |
| From a host | `src host 192.168.1.1` |
| To a host | `dst host 8.8.8.8` |
| ICMP only | `icmp` |
| Exclude ARP | `not arp` |
| DNS queries | `udp port 53` |
| Non-local traffic | `not net 192.168.0.0/16` |

---

## Project Structure

```
packet-sniffer/
├── pom.xml                          ← Maven build config + Pcap4J dependencies
└── src/main/java/com/sniffer/
    ├── Main.java                    ← Entry point, CLI parsing, interface listing
    ├── PacketSniffer.java           ← Pcap4J capture loop, dump-to-file, statistics
    ├── PacketAnalyzer.java          ← Protocol decoder (L2→L3→L4→L7)
    ├── PacketInfo.java              ← Data class for decoded packet fields
    └── SnifferUI.java               ← Terminal display with ANSI colors + hex dump
```

---

## Sample Output

```
  SNIFFER Java Network Packet Sniffer v1.0.0

[*] Capturing on: eth0
[*] Filter       : tcp port 80
[*] Max packets  : unlimited
[*] Press Ctrl+C to stop.

No.    Proto    App        Source                 Dest                   Len     Info
─────────────────────────────────────────────────────────────────────────────────────────────────
1      TCP      HTTP       192.168.1.10:54231     93.184.216.34:80       74      192.168.1.10:5…
2      TCP      HTTP       93.184.216.34:80       192.168.1.10:54231     1460    93.184.216.34:…
  0000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  HTTP/1.1 200 OK.
  0010  0a 43 6f 6e 74 65 6e 74  2d 54 79 70 65 3a 20 74  .Content-Type: t
3      TCP      HTTP       192.168.1.10:54231     93.184.216.34:80       54      192.168.1.10:5…
^C

┌──────────────────────────────────────┐
│           CAPTURE STATISTICS          │
├──────────────────────────────────────┤
│  Total Packets:                   3  │
│  Total Bytes:                1.6 KB  │
│  Duration:                       4s  │
│  Avg Packets/sec:               1/s  │
│  Avg Throughput:              400 B/s│
└──────────────────────────────────────┘
```

---

## How It Works (for your project report)

1. **Pcap4J** calls the native `libpcap` C library via JNA (Java Native Access).
2. The OS kernel copies matching packets from the NIC driver into a ring buffer.
3. `PacketSniffer.java` opens the handle in **promiscuous mode** so the NIC accepts all frames, not just those addressed to this host.
4. An optional **BPF filter** is compiled and pushed into the kernel, so only matching packets are copied to userspace — this is very efficient.
5. `PacketAnalyzer.java` walks the packet's layer tree using Pcap4J's type-safe packet classes, extracting headers at each layer.
6. Application protocols are identified by **well-known port numbers** and **payload fingerprinting** (e.g., checking for `GET `, `HTTP/`, TLS record type `0x16`, SSH banner `SSH-`).
7. Captured packets can optionally be written to a `.pcap` file using `PcapDumper`, which is compatible with Wireshark for post-analysis.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `No network interfaces found` | Install libpcap/Npcap; run with sudo |
| `Permission denied` | Use `sudo` on Linux/macOS; run as Admin on Windows |
| `Native library not found` | Re-install libpcap or Npcap; check `LD_LIBRARY_PATH` |
| No packets captured | Check your BPF filter; try `ping 8.8.8.8` in another terminal |
| Windows interface name | Use the full `\Device\NPF_{GUID}` name shown in the interface list |
