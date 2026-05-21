package com.sniffer;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * PacketSniffer — captures packets from a live network interface using Pcap4J.
 *
 * Features:
 *  - Promiscuous mode capture
 *  - Optional BPF filter (e.g. "tcp", "port 80", "host 192.168.1.1")
 *  - Optional dump to .pcap file for analysis in Wireshark
 *  - Live statistics (packets/sec, bytes/sec)
 *  - Graceful Ctrl+C shutdown
 */
public class PacketSniffer {

    // Pcap4J constants
    private static final int SNAPSHOT_LENGTH = 65536;   // Max bytes to capture per packet
    private static final int READ_TIMEOUT_MS  = 10;     // Read timeout in milliseconds

    private final PcapNetworkInterface networkInterface;
    private final int                  maxPackets;
    private final String               bpfFilter;
    private final String               saveFilePath;

    // Statistics
    private final AtomicInteger totalPackets = new AtomicInteger(0);
    private final AtomicLong    totalBytes   = new AtomicLong(0);
    private long                startTime;

    // The packet analyzer for protocol decoding
    private final PacketAnalyzer analyzer = new PacketAnalyzer();

    public PacketSniffer(PcapNetworkInterface iface, int maxPackets,
                         String bpfFilter, String saveFilePath) {
        this.networkInterface = iface;
        this.maxPackets       = maxPackets;
        this.bpfFilter        = (bpfFilter == null) ? "" : bpfFilter.trim();
        this.saveFilePath     = saveFilePath;
    }

    /**
     * Opens a Pcap handle and starts the capture loop.
     */
    public void start() {
        System.out.println("\n[*] Capturing on: " + networkInterface.getName());
        if (!bpfFilter.isEmpty()) {
            System.out.println("[*] Filter       : " + bpfFilter);
        }
        if (saveFilePath != null) {
            System.out.println("[*] Saving to    : " + saveFilePath);
        }
        System.out.println("[*] Max packets  : " + (maxPackets == 0 ? "unlimited" : maxPackets));
        System.out.println("[*] Press Ctrl+C to stop.\n");

        // Column headers
        SnifferUI.printHeader();

        PcapHandle handle = null;
        PcapDumper dumper = null;

        try {
            // Open the interface in promiscuous mode
            handle = networkInterface.openLive(
                SNAPSHOT_LENGTH,
                PromiscuousMode.PROMISCUOUS,
                READ_TIMEOUT_MS
            );

            // Apply BPF filter if specified
            if (!bpfFilter.isEmpty()) {
                handle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
            }

            // Open dump file if requested
            if (saveFilePath != null) {
                dumper = handle.dumpOpen(saveFilePath);
            }

            // Register shutdown hook for Ctrl+C
            final PcapHandle   finalHandle = handle;
            final PcapDumper   finalDumper = dumper;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\n\n[*] Shutting down...");
                printStats();
                try { if (finalDumper != null) finalDumper.close(); } catch (Exception ignored) {}
                try { if (finalHandle.isOpen()) finalHandle.breakLoop(); } catch (Exception ignored) {}
                try { finalHandle.close(); } catch (Exception ignored) {}
            }));

            startTime = System.currentTimeMillis();

            // ─── Main capture loop ───────────────────────────────────────────
            PacketListener listener = buildListener(handle, dumper);
            int captureCount = (maxPackets == 0) ? Integer.MAX_VALUE : maxPackets;
            handle.loop(captureCount, listener);
            // loop() returns when count is reached or breakLoop() is called

        } catch (PcapNativeException e) {
            System.err.println("\n[ERROR] Pcap error: " + e.getMessage());
            System.err.println("  → Make sure libpcap/Npcap is installed.");
            System.err.println("  → On Linux/macOS, run with sudo or give CAP_NET_RAW capability.");
        } catch (NotOpenException e) {
            System.err.println("\n[ERROR] Handle not open: " + e.getMessage());
        } catch (InterruptedException e) {
            // Normal Ctrl+C path — shutdown hook handles cleanup
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            System.err.println("\n[ERROR] File error: " + e.getMessage());
        } finally {
            if (dumper != null) { try { dumper.close(); } catch (Exception ignored) {} }
            if (handle != null && handle.isOpen()) {
                handle.close();
                printStats();
            }
        }
    }

    /**
     * Builds the PacketListener callback used by Pcap4J's capture loop.
     */
    private PacketListener buildListener(PcapHandle handle, PcapDumper dumper) {
        return packet -> {
            int num   = totalPackets.incrementAndGet();
            int bytes = packet.length();
            totalBytes.addAndGet(bytes);

            // Decode and display the packet
            PacketInfo info = analyzer.analyze(packet, num);
            SnifferUI.printPacket(info);

            // Optionally dump to file
            if (dumper != null) {
                try {
                    dumper.dump(packet, handle.getTimestamp());
                } catch (Exception e) {
                    System.err.println("[WARN] Failed to write packet to file: " + e.getMessage());
                }
            }
        };
    }

    /**
     * Prints final capture statistics.
     */
    private void printStats() {
        long elapsed = (System.currentTimeMillis() - startTime) / 1000;
        if (elapsed == 0) elapsed = 1; // avoid division by zero
        int    packets = totalPackets.get();
        long   bytes   = totalBytes.get();

        System.out.println("\n┌──────────────────────────────────────┐");
        System.out.println("│           CAPTURE STATISTICS          │");
        System.out.println("├──────────────────────────────────────┤");
        System.out.printf("│  %-20s %15d  │%n", "Total Packets:",    packets);
        System.out.printf("│  %-20s %15s  │%n", "Total Bytes:",      formatBytes(bytes));
        System.out.printf("│  %-20s %13ds  │%n", "Duration:",        elapsed);
        System.out.printf("│  %-20s %13d/s │%n", "Avg Packets/sec:", packets / elapsed);
        System.out.printf("│  %-20s %12s/s  │%n", "Avg Throughput:",  formatBytes(bytes / elapsed));
        System.out.println("└──────────────────────────────────────┘");
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024)             return bytes + " B";
        if (bytes < 1024 * 1024)      return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }
}
