package com.sniffer;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;

/**
 * Main entry point for the Java Packet Sniffer.
 *
 * Usage:
 *   java -jar sniffer.jar                      → list interfaces, then auto-select
 *   java -jar sniffer.jar -i eth0              → capture on eth0
 *   java -jar sniffer.jar -i eth0 -c 100       → capture 100 packets then stop
 *   java -jar sniffer.jar -i eth0 -f "tcp"     → capture only TCP packets
 *   java -jar sniffer.jar -i eth0 --save out.pcap → also save to file
 */
public class Main {

    public static void main(String[] args) {
        printBanner();

        // Parse CLI arguments
        String interfaceName = null;
        int maxPackets       = 0;   // 0 = unlimited
        String bpfFilter     = "";  // BPF filter expression
        String saveFile      = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-i": case "--interface":
                    if (i + 1 < args.length) interfaceName = args[++i];
                    break;
                case "-c": case "--count":
                    if (i + 1 < args.length) maxPackets = Integer.parseInt(args[++i]);
                    break;
                case "-f": case "--filter":
                    if (i + 1 < args.length) bpfFilter = args[++i];
                    break;
                case "--save":
                    if (i + 1 < args.length) saveFile = args[++i];
                    break;
                case "-h": case "--help":
                    printHelp();
                    return;
                default:
                    System.out.println("[WARN] Unknown argument: " + args[i]);
            }
        }

        // List available network interfaces
        List<PcapNetworkInterface> interfaces = listInterfaces();
        if (interfaces == null || interfaces.isEmpty()) {
            System.err.println("[ERROR] No network interfaces found. " +
                               "Make sure libpcap/Npcap is installed and you have permissions.");
            System.exit(1);
        }

        // Select interface
        PcapNetworkInterface selectedIface = selectInterface(interfaces, interfaceName);
        if (selectedIface == null) {
            System.err.println("[ERROR] Interface not found: " + interfaceName);
            System.exit(1);
        }

        // Start sniffer
        PacketSniffer sniffer = new PacketSniffer(selectedIface, maxPackets, bpfFilter, saveFile);
        sniffer.start();
    }

    /**
     * Fetches and prints all available network interfaces.
     */
    private static List<PcapNetworkInterface> listInterfaces() {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            System.out.println("\n┌─────────────────────────────────────────────────────────────┐");
            System.out.println("│                  AVAILABLE NETWORK INTERFACES                │");
            System.out.println("├────┬────────────────────────────┬────────────────────────────┤");
            System.out.printf("│ %-2s │ %-26s │ %-26s │%n", "#", "Name", "Description");
            System.out.println("├────┼────────────────────────────┼────────────────────────────┤");

            for (int i = 0; i < interfaces.size(); i++) {
                PcapNetworkInterface iface = interfaces.get(i);
                String name = truncate(iface.getName(), 26);
                String desc = iface.getDescription() != null
                              ? truncate(iface.getDescription(), 26)
                              : "N/A";
                System.out.printf("│ %-2d │ %-26s │ %-26s │%n", i, name, desc);
            }

            System.out.println("└────┴────────────────────────────┴────────────────────────────┘");
            return interfaces;
        } catch (Exception e) {
            System.err.println("[ERROR] Failed to list interfaces: " + e.getMessage());
            return null;
        }
    }

    /**
     * Selects a network interface by name, or prompts user to pick one.
     */
    private static PcapNetworkInterface selectInterface(
            List<PcapNetworkInterface> interfaces, String name) {

        if (name != null) {
            // Match by exact name
            for (PcapNetworkInterface iface : interfaces) {
                if (iface.getName().equalsIgnoreCase(name)) return iface;
            }
            return null;
        }

        // Auto-select: prompt user
        System.out.print("\nEnter interface number (or name) to capture on: ");
        java.util.Scanner sc = new java.util.Scanner(System.in);
        String input = sc.nextLine().trim();

        try {
            int idx = Integer.parseInt(input);
            if (idx >= 0 && idx < interfaces.size()) {
                return interfaces.get(idx);
            }
        } catch (NumberFormatException e) {
            // Try matching by name
            for (PcapNetworkInterface iface : interfaces) {
                if (iface.getName().equalsIgnoreCase(input)) return iface;
            }
        }

        return null;
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() > maxLen ? s.substring(0, maxLen - 1) + "…" : s;
    }

    private static void printBanner() {
        System.out.println();
        System.out.println("  ██████  ███    ██ ██ ███████ ███████ ███████ ██████  ");
        System.out.println("  ██      ████   ██ ██ ██      ██      ██      ██   ██ ");
        System.out.println("  ███████ ██ ██  ██ ██ █████   █████   █████   ██████  ");
        System.out.println("       ██ ██  ██ ██ ██ ██      ██      ██      ██   ██ ");
        System.out.println("  ██████  ██   ████ ██ ██      ██      ███████ ██   ██ ");
        System.out.println();
        System.out.println("         Java Network Packet Sniffer  v1.0.0");
        System.out.println("         Built with Pcap4J  |  Minor Project");
        System.out.println();
    }

    private static void printHelp() {
        System.out.println("Usage: java -jar sniffer.jar [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -i, --interface <name>   Network interface to capture on");
        System.out.println("  -c, --count <n>          Stop after capturing n packets (default: unlimited)");
        System.out.println("  -f, --filter <bpf>       BPF filter expression (e.g. \"tcp\", \"port 80\")");
        System.out.println("      --save <file>         Save captured packets to .pcap file");
        System.out.println("  -h, --help               Show this help");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar sniffer.jar -i eth0");
        System.out.println("  java -jar sniffer.jar -i eth0 -c 50 -f \"tcp port 443\"");
        System.out.println("  java -jar sniffer.jar -i eth0 --save capture.pcap");
    }
}
