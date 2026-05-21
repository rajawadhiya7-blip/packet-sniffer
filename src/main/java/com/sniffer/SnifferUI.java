package com.sniffer;

/**
 * SnifferUI handles all terminal output.
 *
 * Uses ANSI escape codes to color-code packets by protocol:
 *   TCP   → Cyan
 *   UDP   → Yellow
 *   ICMP  → Green
 *   ARP   → Magenta
 *   TLS   → Blue
 *   HTTP  → Bold White
 *   Other → Default
 *
 * Also provides a hex dump utility for raw payload bytes.
 */
public class SnifferUI {

    // ANSI color codes
    private static final String RESET   = "\u001B[0m";
    private static final String BOLD    = "\u001B[1m";
    private static final String RED     = "\u001B[31m";
    private static final String GREEN   = "\u001B[32m";
    private static final String YELLOW  = "\u001B[33m";
    private static final String BLUE    = "\u001B[34m";
    private static final String MAGENTA = "\u001B[35m";
    private static final String CYAN    = "\u001B[36m";
    private static final String WHITE   = "\u001B[37m";
    private static final String DIM     = "\u001B[2m";

    // Column widths
    private static final int COL_NUM     = 6;
    private static final int COL_PROTO   = 8;
    private static final int COL_APP     = 10;
    private static final int COL_SRC     = 22;
    private static final int COL_DST     = 22;
    private static final int COL_LEN     = 7;
    private static final int COL_INFO    = 36;

    /**
     * Prints the column header row.
     */
    public static void printHeader() {
        System.out.println(BOLD +
            pad("No.",    COL_NUM)  + " " +
            pad("Proto",  COL_PROTO) + " " +
            pad("App",    COL_APP)   + " " +
            pad("Source", COL_SRC)   + " " +
            pad("Dest",   COL_DST)   + " " +
            pad("Len",    COL_LEN)   + " " +
            pad("Info",   COL_INFO)  +
            RESET);
        System.out.println(DIM + "─".repeat(
            COL_NUM + COL_PROTO + COL_APP + COL_SRC + COL_DST + COL_LEN + COL_INFO + 7
        ) + RESET);
    }

    /**
     * Prints a single packet row.
     *
     * @param info Decoded packet information
     */
    public static void printPacket(PacketInfo info) {
        String color  = protocolColor(info.protocol, info.appProtocol);
        String srcStr = buildAddress(info.srcIp, info.srcPort, info.protocol);
        String dstStr = buildAddress(info.dstIp, info.dstPort, info.protocol);
        String proto  = info.protocol;
        String app    = info.appProtocol != null ? info.appProtocol : "";

        System.out.println(
            color +
            pad(String.valueOf(info.number), COL_NUM) + " " +
            pad(proto,   COL_PROTO) + " " +
            pad(app,     COL_APP)   + " " +
            pad(srcStr,  COL_SRC)   + " " +
            pad(dstStr,  COL_DST)   + " " +
            pad(String.valueOf(info.length), COL_LEN) + " " +
            pad(truncate(info.summary, COL_INFO), COL_INFO) +
            RESET
        );

        // For HTTP traffic, show a hex dump of the first payload bytes
        if ("HTTP".equals(app) && info.rawPayload != null && info.rawPayload.length > 0) {
            System.out.println(DIM + hexDump(info.rawPayload) + RESET);
        }
    }

    /**
     * Produces a Wireshark-style hex dump of a byte array.
     *
     * Example output:
     *   0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..
     */
    public static String hexDump(byte[] data) {
        if (data == null || data.length == 0) return "";
        StringBuilder sb = new StringBuilder();
        int rows = (data.length + 15) / 16;
        for (int row = 0; row < rows; row++) {
            int offset = row * 16;
            sb.append(String.format("  %04x  ", offset));

            // Hex bytes
            for (int i = 0; i < 16; i++) {
                if (offset + i < data.length) {
                    sb.append(String.format("%02x ", data[offset + i]));
                } else {
                    sb.append("   ");
                }
                if (i == 7) sb.append(" ");
            }
            sb.append(" ");

            // ASCII printable
            for (int i = 0; i < 16 && offset + i < data.length; i++) {
                char c = (char) (data[offset + i] & 0xFF);
                sb.append(isPrintable(c) ? c : '.');
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private static String buildAddress(String ip, int port, String protocol) {
        if (ip == null || ip.equals("?")) return "?";
        boolean hasPort = ("TCP".equals(protocol) || "UDP".equals(protocol)) && port > 0;
        return hasPort ? ip + ":" + port : ip;
    }

    private static String protocolColor(String proto, String app) {
        if ("TLS".equals(app) || "HTTPS/TLS".equals(app)) return BLUE;
        if ("HTTP".equals(app))   return BOLD + WHITE;
        if ("DNS".equals(app))    return GREEN;
        switch (proto) {
            case "TCP":  return CYAN;
            case "UDP":  return YELLOW;
            case "ICMP": return GREEN;
            case "ARP":  return MAGENTA;
            default:     return WHITE;
        }
    }

    /** Left-pads or truncates a string to exactly `width` characters. */
    private static String pad(String s, int width) {
        if (s == null) s = "";
        if (s.length() > width) return s.substring(0, width);
        return s + " ".repeat(width - s.length());
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max - 1) + "…" : s;
    }

    private static boolean isPrintable(char c) {
        return c >= 32 && c < 127;
    }
}
