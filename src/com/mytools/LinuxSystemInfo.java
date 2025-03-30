package com.mytools;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class LinuxSystemInfo {

    public static void main(String[] args) {
        Map<String, String> systemInfo = new HashMap<>();

        // Pixel Art and Author Information
        displayAuthorInfo();

        // Basic System Information
        systemInfo.put("OS Name", System.getProperty("os.name"));
        systemInfo.put("OS Version", System.getProperty("os.version"));
        systemInfo.put("OS Architecture", System.getProperty("os.arch"));
        systemInfo.put("Java Version", System.getProperty("java.version"));
        systemInfo.put("Java Vendor", System.getProperty("java.vendor"));

        // Hardware Information (Linux-specific commands)
        try {
            systemInfo.put("CPU Model", executeCommand("lscpu | grep 'Model name:' | cut -d':' -f2 | tr -d ' '"));
            systemInfo.put("CPU Cores", executeCommand("nproc"));
            systemInfo.put("Memory (Total)", executeCommand("free -h | awk '/Mem:/ {print $2}'"));
            systemInfo.put("Disk Space (Total)", executeCommand("df -h / | awk '/\\/dev\\// {print $2}'"));
            systemInfo.put("Kernel Version", executeCommand("uname -r"));
            systemInfo.put("Uptime", executeCommand("uptime -p"));
        } catch (IOException | InterruptedException e) {
            System.err.println("Error retrieving hardware information: " + e.getMessage());
        }

        // Network Information
        try {
            getNetworkInfo(systemInfo);
        } catch (SocketException e) {
            System.err.println("Error retrieving network information: " + e.getMessage());
        }

        // Display Information
        System.out.println("--- System Information ---");
        systemInfo.forEach((key, value) -> System.out.println(key + ": " + value));
    }

    private static void displayAuthorInfo() {
        System.out.println("      .--.      ");
        System.out.println("     |o_o |     ");
        System.out.println("     |:_/ |     ");
        System.out.println("    //   \\ \\    ");
        System.out.println("   (|     |)    ");
        System.out.println("  /'\\_   _/`\\  ");
        System.out.println("  \\___)=(___/   ");
        System.out.println("  Author: 0xWulf");
        System.out.println("  Email: 0xwulf@proton.me");
        System.out.println("  ----------------------------");
    }

    private static String executeCommand(String command) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", command});
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append(System.lineSeparator());
        }
        process.waitFor();
        return output.toString().trim();
    }

    private static void getNetworkInfo(Map<String, String> systemInfo) throws SocketException {
        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
        while (networkInterfaces.hasMoreElements()) {
            NetworkInterface networkInterface = networkInterfaces.nextElement();
            if (!networkInterface.isVirtual() && networkInterface.isUp()) {
                Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress inetAddress = inetAddresses.nextElement();
                    if (!inetAddress.isLoopbackAddress()) {
                        systemInfo.put("Network Interface (" + networkInterface.getName() + ")", networkInterface.getDisplayName());
                        systemInfo.put("IP Address (" + networkInterface.getName() + ")", inetAddress.getHostAddress());
                        try {
                            systemInfo.put("MAC Address (" + networkInterface.getName() + ")", executeCommand("ip link show " + networkInterface.getName() + " | awk '/link\\/ether/ {print $2}'"));
                        } catch (IOException | InterruptedException e) {
                            systemInfo.put("MAC Address (" + networkInterface.getName() + ")", "Unavailable");
                        }
                    }
                }
            }
        }
    }
}