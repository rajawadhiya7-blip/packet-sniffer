package com.sniffer;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;

/**
 * PacketAnalyzer decodes raw Pcap4J packets layer by layer:
 *
 *  Layer 2 → EthernetPacket  (MAC addresses, EtherType)
 *  Layer 3 → IpV4Packet / IpV6Packet / ArpPacket
 *  Layer 4 → TcpPacket / UdpPacket / IcmpV4CommonPacket
 *  Layer 7 → Heuristic detection: HTTP, DNS, TLS, DHCP, FTP, SMTP, SSH
 */
public class PacketAnalyzer {

    // Known TCP/UDP port → application protocol mappings
    private static final java.util.Map<Integer, String> PORT_PROTOCOLS = new java.util.HashMap<>();
    static {
        PORT_PROTOCOLS.put(20,   "FTP-DATA");
        PORT_PROTOCOLS.put(21,   "FTP");
        PORT_PROTOCOLS.put(22,   "SSH");
        PORT_PROTOCOLS.put(23,   "TELNET");
        PORT_PROTOCOLS.put(25,   "SMTP");
        PORT_PROTOCOLS.put(53,   "DNS");
        PORT_PROTOCOLS.put(67,   "DHCP");
        PORT_PROTOCOLS.put(68,   "DHCP");
        PORT_PROTOCOLS.put(80,   "HTTP");
        PORT_PROTOCOLS.put(110,  "POP3");
        PORT_PROTOCOLS.put(143,  "IMAP");
        PORT_PROTOCOLS.put(443,  "HTTPS/TLS");
        PORT_PROTOCOLS.put(587,  "SMTP-TLS");
        PORT_PROTOCOLS.put(993,  "IMAPS");
        PORT_PROTOCOLS.put(995,  "POP3S");
        PORT_PROTOCOLS.put(3306, "MySQL");
        PORT_PROTOCOLS.put(5432, "PostgreSQL");
        PORT_PROTOCOLS.put(6379, "Redis");
        PORT_PROTOCOLS.put(8080, "HTTP-ALT");
        PORT_PROTOCOLS.put(8443, "HTTPS-ALT");
        PORT_PROTOCOLS.put(27017,"MongoDB");
    }

    /**
     * Analyzes a packet and returns a populated PacketInfo.
     *
     * @param packet The raw Pcap4J packet
     * @param number The sequence number of this packet in the capture
     * @return A PacketInfo with all decoded fields
     */
    public PacketInfo analyze(Packet packet, int number) {
        PacketInfo info = new PacketInfo();
        info.number   = number;
        info.length   = packet.length();
        info.protocol = "UNKNOWN";
        info.srcIp    = "?";
        info.dstIp    = "?";
        info.appProtocol = "?";

        // ── Layer 2: Ethernet ────────────────────────────────────────────
        EthernetPacket eth = packet.get(EthernetPacket.class);
        if (eth != null) {
            EthernetPacket.EthernetHeader eh = eth.getHeader();
            info.srcMac   = formatMac(eh.getSrcAddr().getAddress());
            info.dstMac   = formatMac(eh.getDstAddr().getAddress());
            info.etherType = eh.getType().name();

            // ── Layer 3: IPv4 ────────────────────────────────────────────
            IpV4Packet ipv4 = packet.get(IpV4Packet.class);
            if (ipv4 != null) {
                IpV4Packet.IpV4Header h = ipv4.getHeader();
                info.srcIp      = h.getSrcAddr().getHostAddress();
                info.dstIp      = h.getDstAddr().getHostAddress();
                info.ttl        = h.getTtl() & 0xFF;
                info.ipHeaderLen = h.getIhlAsInt() * 4;

                analyzeTransport(packet, info);

            // ── Layer 3: IPv6 ────────────────────────────────────────────
            } else {
                IpV6Packet ipv6 = packet.get(IpV6Packet.class);
                if (ipv6 != null) {
                    IpV6Packet.IpV6Header h6 = ipv6.getHeader();
                    info.srcIp = h6.getSrcAddr().getHostAddress();
                    info.dstIp = h6.getDstAddr().getHostAddress();
                    analyzeTransport(packet, info);

                // ── Layer 3: ARP ─────────────────────────────────────────
                } else {
                    ArpPacket arp = packet.get(ArpPacket.class);
                    if (arp != null) analyzeArp(arp, info);
                }
            }
        } else {
            // Non-Ethernet (e.g. loopback/raw IP)
            IpV4Packet raw = packet.get(IpV4Packet.class);
            if (raw != null) {
                info.srcIp = raw.getHeader().getSrcAddr().getHostAddress();
                info.dstIp = raw.getHeader().getDstAddr().getHostAddress();
                analyzeTransport(packet, info);
            }
        }

        buildSummary(info);
        return info;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Transport layer (TCP / UDP / ICMP)
    // ──────────────────────────────────────────────────────────────────────────

    private void analyzeTransport(Packet packet, PacketInfo info) {

        // TCP
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp != null) {
            TcpPacket.TcpHeader h = tcp.getHeader();
            info.protocol   = "TCP";
            info.srcPort    = h.getSrcPort().valueAsInt();
            info.dstPort    = h.getDstPort().valueAsInt();
            info.windowSize = h.getWindow();
            info.tcpFlags   = decodeTcpFlags(h);

            byte[] payload = tcp.getPayload() != null ? tcp.getPayload().getRawData() : new byte[0];
            info.payloadLen  = payload.length;
            info.rawPayload  = firstBytes(payload, 64);
            info.appProtocol = guessAppProtocol(info.srcPort, info.dstPort, payload);
            return;
        }

        // UDP
        UdpPacket udp = packet.get(UdpPacket.class);
        if (udp != null) {
            UdpPacket.UdpHeader h = udp.getHeader();
            info.protocol   = "UDP";
            info.srcPort    = h.getSrcPort().valueAsInt();
            info.dstPort    = h.getDstPort().valueAsInt();

            byte[] payload = udp.getPayload() != null ? udp.getPayload().getRawData() : new byte[0];
            info.payloadLen  = payload.length;
            info.rawPayload  = firstBytes(payload, 64);
            info.appProtocol = guessAppProtocol(info.srcPort, info.dstPort, payload);
            return;
        }

        // ICMPv4
        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
        if (icmp != null) {
            info.protocol    = "ICMP";
            info.appProtocol = "ICMP";
            IcmpV4CommonPacket.IcmpV4CommonHeader h = icmp.getHeader();
            info.icmpType = decodeIcmpType(h.getType().value() & 0xFF);
            info.icmpCode = h.getCode().value() & 0xFF;
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ARP
    // ──────────────────────────────────────────────────────────────────────────

    private void analyzeArp(ArpPacket arp, PacketInfo info) {
        info.protocol    = "ARP";
        info.appProtocol = "ARP";
        ArpPacket.ArpHeader h = arp.getHeader();

        info.arpOperation = h.getOperation() == ArpOperation.REQUEST ? "Request" : "Reply";
        info.arpSenderIp  = h.getSrcProtocolAddr().getHostAddress();
        info.arpTargetIp  = h.getDstProtocolAddr().getHostAddress();
        info.arpSenderMac = formatMac(h.getSrcHardwareAddr().getAddress());
        info.srcIp        = info.arpSenderIp;
        info.dstIp        = info.arpTargetIp;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Application layer heuristics
    // ──────────────────────────────────────────────────────────────────────────

    private String guessAppProtocol(int srcPort, int dstPort, byte[] payload) {
        // 1. Check known ports
        String byPort = PORT_PROTOCOLS.get(dstPort);
        if (byPort == null) byPort = PORT_PROTOCOLS.get(srcPort);
        if (byPort != null) return byPort;

        // 2. Payload sniffing
        if (payload.length >= 4) {
            String start = new String(payload, 0, Math.min(8, payload.length),
                                      java.nio.charset.StandardCharsets.ISO_8859_1);

            // HTTP methods
            if (start.startsWith("GET ")   || start.startsWith("POST ") ||
                start.startsWith("PUT ")   || start.startsWith("HEAD ") ||
                start.startsWith("DELETE ") || start.startsWith("HTTP/")) {
                return "HTTP";
            }

            // TLS Client/Server Hello
            if (payload[0] == 0x16 && payload[1] == 0x03) return "TLS";

            // DNS (heuristic: short UDP, query/response flag in byte 2)
            if (payload.length >= 12 && (srcPort == 53 || dstPort == 53)) return "DNS";

            // SSH banner
            if (start.startsWith("SSH-")) return "SSH";

            // FTP banner
            if (start.startsWith("220 ") || start.startsWith("230 ")) return "FTP";

            // SMTP banner/command
            if (start.startsWith("EHLO") || start.startsWith("HELO") ||
                start.startsWith("220 ") && (srcPort == 25 || dstPort == 25)) return "SMTP";
        }

        return "DATA";
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Summary line builder
    // ──────────────────────────────────────────────────────────────────────────

    private void buildSummary(PacketInfo info) {
        switch (info.protocol) {
            case "TCP":
                info.summary = String.format("%s:%d → %s:%d [%s] win=%d payload=%dB",
                    info.srcIp, info.srcPort,
                    info.dstIp, info.dstPort,
                    info.tcpFlags, info.windowSize, info.payloadLen);
                break;
            case "UDP":
                info.summary = String.format("%s:%d → %s:%d payload=%dB",
                    info.srcIp, info.srcPort, info.dstIp, info.dstPort, info.payloadLen);
                break;
            case "ICMP":
                info.summary = String.format("%s → %s [%s code=%d]",
                    info.srcIp, info.dstIp, info.icmpType, info.icmpCode);
                break;
            case "ARP":
                info.summary = String.format("ARP %s: who has %s? Tell %s",
                    info.arpOperation, info.arpTargetIp, info.arpSenderIp);
                break;
            default:
                info.summary = info.srcIp + " → " + info.dstIp;
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private String decodeTcpFlags(TcpPacket.TcpHeader h) {
        StringBuilder sb = new StringBuilder();
        if (h.getSyn()) sb.append("SYN ");
        if (h.getAck()) sb.append("ACK ");
        if (h.getFin()) sb.append("FIN ");
        if (h.getRst()) sb.append("RST ");
        if (h.getPsh()) sb.append("PSH ");
        if (h.getUrg()) sb.append("URG ");
        return sb.length() > 0 ? sb.toString().trim() : "NONE";
    }

    private String decodeIcmpType(int type) {
        switch (type) {
            case 0:  return "Echo Reply";
            case 3:  return "Destination Unreachable";
            case 4:  return "Source Quench";
            case 5:  return "Redirect";
            case 8:  return "Echo Request";
            case 11: return "Time Exceeded";
            case 12: return "Parameter Problem";
            case 13: return "Timestamp";
            case 14: return "Timestamp Reply";
            default: return "Type(" + type + ")";
        }
    }

    private String formatMac(byte[] addr) {
        if (addr == null || addr.length < 6) return "??:??:??:??:??:??";
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    }

    private byte[] firstBytes(byte[] src, int n) {
        if (src == null || src.length == 0) return new byte[0];
        int len = Math.min(src.length, n);
        byte[] out = new byte[len];
        System.arraycopy(src, 0, out, 0, len);
        return out;
    }
}
