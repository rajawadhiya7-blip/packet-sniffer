package com.sniffer;

/**
 * PacketInfo is a simple data class holding decoded information
 * from a captured network packet. It is passed from PacketAnalyzer
 * to SnifferUI for display.
 */
public class PacketInfo {

    // ── Capture metadata ────────────────────────────────────────
    public int    number;       // Packet sequence number
    public int    length;       // Total packet length in bytes

    // ── Layer 2: Ethernet ────────────────────────────────────────
    public String srcMac;       // Source MAC address
    public String dstMac;       // Destination MAC address
    public String etherType;    // e.g. "IPv4", "IPv6", "ARP"

    // ── Layer 3: Network ─────────────────────────────────────────
    public String srcIp;        // Source IP address
    public String dstIp;        // Destination IP address
    public String protocol;     // e.g. "TCP", "UDP", "ICMP", "ARP"
    public int    ttl;          // IP Time-to-Live
    public int    ipHeaderLen;  // IP header length in bytes

    // ── Layer 4: Transport ───────────────────────────────────────
    public int    srcPort;      // Source port (TCP/UDP)
    public int    dstPort;      // Destination port (TCP/UDP)
    public String tcpFlags;     // TCP flags: SYN, ACK, FIN, RST, PSH, URG
    public int    windowSize;   // TCP window size
    public int    payloadLen;   // Application payload length in bytes

    // ── Layer 7: Application (best-effort) ───────────────────────
    public String appProtocol;  // Guessed application protocol (HTTP, DNS, TLS, etc.)
    public String summary;      // Human-readable one-line description

    // ── Hex dump (first bytes of payload) ────────────────────────
    public byte[] rawPayload;   // First N bytes of application payload

    // ── ARP-specific ─────────────────────────────────────────────
    public String arpOperation; // "Request" or "Reply"
    public String arpSenderIp;
    public String arpTargetIp;
    public String arpSenderMac;

    // ── ICMP-specific ─────────────────────────────────────────────
    public String icmpType;     // e.g. "Echo Request", "Echo Reply", "Unreachable"
    public int    icmpCode;

    @Override
    public String toString() {
        return String.format("Packet #%d [%s] %s:%d → %s:%d (%s) %d bytes",
            number, protocol, srcIp, srcPort, dstIp, dstPort, appProtocol, length);
    }
}
