package com.mytools;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class LinuxSystemInfo {

    public static void main(String[] args) {
        Map<String, String> systemInfo = new HashMap<>();

        // Wolf Pixel Art and Author Information
        displayAuthorInfo();

        System.out.println("\n--- COLLECTING SYSTEM INFORMATION ---");
        
        // Basic System Information
        collectBasicSystemInfo(systemInfo);
        
        // Hardware Information (Linux-specific commands)
        collectHardwareInfo(systemInfo);
        
        // Advanced Hardware Details
        collectAdvancedHardwareInfo(systemInfo);
        
        // Network Information
        collectNetworkInfo(systemInfo);
        
        // System Load Information
        collectSystemLoadInfo(systemInfo);
        
        // System Services Status
        collectSystemServicesInfo(systemInfo);

        // Display Information in Categories
        displaySystemInfo(systemInfo);
    }

    private static void displayAuthorInfo() {
    	System.out.println("  --------------------------------------");
        System.out.println("  Enhanced Linux System Info Tool v2.0");
        System.out.println("  Author: 0xWulf");
        System.out.println("  Email: 0xwulf@proton.me");
        System.out.println("  Date: " + new java.util.Date());
        System.out.println("  --------------------------------------");
    }

    private static void collectBasicSystemInfo(Map<String, String> systemInfo) {
        try {
            systemInfo.put("OS Name", System.getProperty("os.name"));
            systemInfo.put("OS Version", System.getProperty("os.version"));
            systemInfo.put("OS Architecture", System.getProperty("os.arch"));
            systemInfo.put("Java Version", System.getProperty("java.version"));
            systemInfo.put("Java Vendor", System.getProperty("java.vendor"));
            systemInfo.put("User Name", System.getProperty("user.name"));
            systemInfo.put("User Home", System.getProperty("user.home"));
            systemInfo.put("CPU Cores", executeCommand("nproc"));
            systemInfo.put("Kernel Version", executeCommand("uname -r"));
            systemInfo.put("Hostname", executeCommand("hostname"));
            systemInfo.put("Distribution", executeCommand("cat /etc/os-release | grep PRETTY_NAME | cut -d '\"' -f 2"));
            systemInfo.put("Uptime", executeCommand("uptime -p"));
            systemInfo.put("Current Shell", System.getenv("SHELL"));
            
            // Check if running in a virtual environment
            String virt = executeCommand("systemd-detect-virt 2>/dev/null || echo 'Unknown'");
            if (virt != null && !virt.trim().isEmpty() && !virt.trim().equals("Unknown") && !virt.trim().equals("none")) {
                systemInfo.put("Virtualization", virt.trim());
            }
            
        } catch (Exception e) {
            System.err.println("Error collecting basic system information: " + e.getMessage());
        }
    }

    private static void collectHardwareInfo(Map<String, String> systemInfo) {
        try {
            // CPU Information
            systemInfo.put("CPU Model", executeCommand("lscpu | grep 'Model name:' | cut -d':' -f2 | tr -s ' ' | sed 's/^\\s*//'"));
            systemInfo.put("CPU Architecture", executeCommand("lscpu | grep 'Architecture:' | cut -d':' -f2 | tr -s ' ' | sed 's/^\\s*//'"));
            systemInfo.put("CPU MHz", executeCommand("lscpu | grep 'CPU MHz:' | cut -d':' -f2 | tr -s ' ' | sed 's/^\\s*//'"));
            
            // Memory Information
            systemInfo.put("Memory Total", executeCommand("free -h | awk '/Mem:/ {print $2}'"));
            systemInfo.put("Memory Used", executeCommand("free -h | awk '/Mem:/ {print $3}'"));
            systemInfo.put("Memory Free", executeCommand("free -h | awk '/Mem:/ {print $4}'"));
            systemInfo.put("Swap Total", executeCommand("free -h | awk '/Swap:/ {print $2}'"));
            systemInfo.put("Swap Used", executeCommand("free -h | awk '/Swap:/ {print $3}'"));
            
            // Disk Information
            systemInfo.put("Root Partition Size", executeCommand("df -h / | awk '/\\// {print $2}'"));
            systemInfo.put("Root Partition Used", executeCommand("df -h / | awk '/\\// {print $3}'"));
            systemInfo.put("Root Partition Free", executeCommand("df -h / | awk '/\\// {print $4}'"));
            systemInfo.put("Root Partition Usage", executeCommand("df -h / | awk '/\\// {print $5}'"));
            
            // All mount points summary
            systemInfo.put("Mount Points", executeCommand("df -h | grep '^/dev/' | awk '{print $6 \": \" $2 \" (\" $5 \" used)\"}' | tr '\\n' '; '"));
            
        } catch (Exception e) {
            System.err.println("Error collecting hardware information: " + e.getMessage());
        }
    }
    
    private static void collectAdvancedHardwareInfo(Map<String, String> systemInfo) {
        try {
            // GPU Information (if available)
            if (commandExists("lspci")) {
                String gpuInfo = executeCommand("lspci | grep -i 'vga\\|3d\\|2d' | cut -d':' -f3");
                if (gpuInfo != null && !gpuInfo.trim().isEmpty()) {
                    systemInfo.put("GPU", gpuInfo.trim());
                }
            }
            
            // CPU Temperature (if available)
            if (commandExists("sensors")) {
                String cpuTemp = executeCommand("sensors | grep -i 'core\\|temp' | head -n 1 | awk '{print $3}'");
                if (cpuTemp != null && !cpuTemp.trim().isEmpty()) {
                    systemInfo.put("CPU Temperature", cpuTemp.trim());
                }
            }
            
            // Battery Information (if available)
            if (commandExists("acpi")) {
                String batteryInfo = executeCommand("acpi -b 2>/dev/null");
                if (batteryInfo != null && !batteryInfo.trim().isEmpty() && !batteryInfo.contains("No support")) {
                    systemInfo.put("Battery Status", batteryInfo.trim());
                }
            }
            
            // BIOS Information
            if (commandExists("dmidecode")) {
                String biosVendor = executeCommand("sudo dmidecode -t bios | grep 'Vendor' | cut -d':' -f2 | sed 's/^\\s*//'");
                String biosVersion = executeCommand("sudo dmidecode -t bios | grep 'Version' | head -1 | cut -d':' -f2 | sed 's/^\\s*//'");
                String biosDate = executeCommand("sudo dmidecode -t bios | grep 'Release Date' | cut -d':' -f2 | sed 's/^\\s*//'");
                
                if (biosVendor != null && !biosVendor.trim().isEmpty() && !biosVendor.contains("denied")) {
                    systemInfo.put("BIOS Vendor", biosVendor.trim());
                    systemInfo.put("BIOS Version", biosVersion.trim());
                    systemInfo.put("BIOS Date", biosDate.trim());
                }
            }
            
            // System model information
            if (commandExists("dmidecode")) {
                String systemModel = executeCommand("sudo dmidecode -t system | grep 'Product Name' | cut -d':' -f2 | sed 's/^\\s*//'");
                String systemManufacturer = executeCommand("sudo dmidecode -t system | grep 'Manufacturer' | cut -d':' -f2 | sed 's/^\\s*//'");
                
                if (systemModel != null && !systemModel.trim().isEmpty() && !systemModel.contains("denied")) {
                    systemInfo.put("System Model", systemModel.trim());
                    systemInfo.put("System Manufacturer", systemManufacturer.trim());
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error collecting advanced hardware information: " + e.getMessage());
        }
    }
    
    private static void collectNetworkInfo(Map<String, String> systemInfo) {
        try {
            // Local Network Interfaces
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            StringBuilder networkDetails = new StringBuilder();
            
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();
                if (!networkInterface.isVirtual() && networkInterface.isUp() && !networkInterface.isLoopback()) {
                    String interfaceName = networkInterface.getName();
                    networkDetails.append(interfaceName).append(": ");
                    
                    // IP Addresses
                    Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
                    while (inetAddresses.hasMoreElements()) {
                        InetAddress inetAddress = inetAddresses.nextElement();
                        if (!inetAddress.isLoopbackAddress()) {
                            networkDetails.append(inetAddress.getHostAddress()).append(", ");
                        }
                    }
                    
                    // MAC Address
                    try {
                        String macAddress = executeCommand("ip link show " + interfaceName + " | grep 'link/ether' | awk '{print $2}'");
                        if (macAddress != null && !macAddress.trim().isEmpty()) {
                            networkDetails.append("MAC: ").append(macAddress.trim());
                        }
                    } catch (Exception e) {
                        networkDetails.append("MAC: Unavailable");
                    }
                    
                    networkDetails.append("; ");
                }
            }
            
            if (networkDetails.length() > 0) {
                systemInfo.put("Network Interfaces", networkDetails.toString());
            }
            
            // Public IP (if internet connection available)
            try {
                String publicIP = executeCommand("curl -s ifconfig.me");
                if (publicIP != null && !publicIP.trim().isEmpty()) {
                    systemInfo.put("Public IP", publicIP.trim());
                }
            } catch (Exception e) {
                // Internet might not be available, silently ignore
            }
            
            // Default Gateway
            try {
                String defaultGateway = executeCommand("ip route | grep default | awk '{print $3}'");
                if (defaultGateway != null && !defaultGateway.trim().isEmpty()) {
                    systemInfo.put("Default Gateway", defaultGateway.trim());
                }
            } catch (Exception e) {
                // Ignore gateway retrieval failures
            }
            
            // DNS Servers
            try {
                String dnsServers = executeCommand("cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | tr '\\n' ', '");
                if (dnsServers != null && !dnsServers.trim().isEmpty()) {
                    systemInfo.put("DNS Servers", dnsServers.trim());
                }
            } catch (Exception e) {
                // Ignore DNS retrieval failures
            }
            
            // Network Statistics for active interfaces
            try {
                String activeInterface = executeCommand("ip route | grep default | awk '{print $5}'");
                if (activeInterface != null && !activeInterface.trim().isEmpty()) {
                    String rxBytes = executeCommand("cat /sys/class/net/" + activeInterface.trim() + "/statistics/rx_bytes");
                    String txBytes = executeCommand("cat /sys/class/net/" + activeInterface.trim() + "/statistics/tx_bytes");
                    
                    if (rxBytes != null && txBytes != null) {
                        double rxMB = Double.parseDouble(rxBytes.trim()) / (1024 * 1024);
                        double txMB = Double.parseDouble(txBytes.trim()) / (1024 * 1024);
                        systemInfo.put("Network Received", String.format("%.2f MB", rxMB));
                        systemInfo.put("Network Transmitted", String.format("%.2f MB", txMB));
                    }
                }
            } catch (Exception e) {
                // Ignore network statistics retrieval failures
            }
            
        } catch (SocketException e) {
            System.err.println("Error retrieving network information: " + e.getMessage());
        }
    }
    
    private static void collectSystemLoadInfo(Map<String, String> systemInfo) {
        try {
            // Current System Load
            String loadAvg = executeCommand("cat /proc/loadavg | awk '{print $1 \" \" $2 \" \" $3}'");
            if (loadAvg != null && !loadAvg.trim().isEmpty()) {
                String[] loads = loadAvg.trim().split(" ");
                if (loads.length >= 3) {
                    systemInfo.put("Load Average (1m)", loads[0]);
                    systemInfo.put("Load Average (5m)", loads[1]);
                    systemInfo.put("Load Average (15m)", loads[2]);
                }
            }
            
            // Top CPU-consuming processes
            String topCpuProcesses = executeCommand("ps aux --sort=-%cpu | head -6 | tail -5 | awk '{print $11 \" (\" $2 \") CPU: \" $3 \"%\"}' | tr '\\n' '; '");
            if (topCpuProcesses != null && !topCpuProcesses.trim().isEmpty()) {
                systemInfo.put("Top CPU Processes", topCpuProcesses.trim());
            }
            
            // Top memory-consuming processes
            String topMemProcesses = executeCommand("ps aux --sort=-%mem | head -6 | tail -5 | awk '{print $11 \" (\" $2 \") MEM: \" $4 \"%\"}' | tr '\\n' '; '");
            if (topMemProcesses != null && !topMemProcesses.trim().isEmpty()) {
                systemInfo.put("Top Memory Processes", topMemProcesses.trim());
            }
            
            // CPU Usage percentage
            String cpuUsage = executeCommand("top -bn1 | grep '%Cpu' | awk '{print $2 + $4 \"%\"}'");
            if (cpuUsage != null && !cpuUsage.trim().isEmpty()) {
                systemInfo.put("CPU Usage", cpuUsage.trim());
            }
            
        } catch (Exception e) {
            System.err.println("Error collecting system load information: " + e.getMessage());
        }
    }
    
    private static void collectSystemServicesInfo(Map<String, String> systemInfo) {
        try {
            // Check if systemd is being used
            if (commandExists("systemctl")) {
                // Check firewall status
                String firewallStatus = executeCommand("systemctl is-active ufw 2>/dev/null || systemctl is-active firewalld 2>/dev/null || echo 'inactive'");
                systemInfo.put("Firewall Status", firewallStatus.trim());
                
                // Check SSH status
                String sshStatus = executeCommand("systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || echo 'inactive'");
                systemInfo.put("SSH Service", sshStatus.trim());
                
                // Check if Docker is running
                String dockerStatus = executeCommand("systemctl is-active docker 2>/dev/null || echo 'inactive'");
                if (!dockerStatus.trim().equals("inactive")) {
                    systemInfo.put("Docker Service", dockerStatus.trim());
                    
                    // List running containers if Docker is active
                    String dockerContainers = executeCommand("docker ps --format '{{.Names}}' 2>/dev/null | tr '\\n' ', ' || echo 'None'");
                    if (!dockerContainers.trim().equals("None")) {
                        systemInfo.put("Running Containers", dockerContainers.trim());
                    }
                }
                
                // Check if database services are running
                String[] dbServices = {"mysql", "postgresql", "mongodb", "redis"};
                for (String service : dbServices) {
                    String status = executeCommand("systemctl is-active " + service + " 2>/dev/null || echo 'inactive'");
                    if (!status.trim().equals("inactive")) {
                        systemInfo.put(service.substring(0, 1).toUpperCase() + service.substring(1) + " Service", status.trim());
                    }
                }
                
                // Check if web server is running
                String[] webServices = {"apache2", "nginx", "httpd"};
                for (String service : webServices) {
                    String status = executeCommand("systemctl is-active " + service + " 2>/dev/null || echo 'inactive'");
                    if (!status.trim().equals("inactive")) {
                        systemInfo.put(service.substring(0, 1).toUpperCase() + service.substring(1) + " Service", status.trim());
                    }
                }
            }
            
            // Last System Boot
            String lastBoot = executeCommand("who -b | awk '{print $3 \" \" $4}'");
            if (lastBoot != null && !lastBoot.trim().isEmpty()) {
                systemInfo.put("Last Boot", lastBoot.trim());
            }
            
            // Last few logins
            String lastLogin = executeCommand("last -n 3 | grep -v 'still logged in' | grep -v 'wtmp begins' | awk '{print $1 \" from \" $3 \" on \" $5 \" \" $6 \" \" $7}' | head -1");
            if (lastLogin != null && !lastLogin.trim().isEmpty()) {
                systemInfo.put("Last Login", lastLogin.trim());
            }
            
        } catch (Exception e) {
            System.err.println("Error collecting system services information: " + e.getMessage());
        }
    }

    private static String executeCommand(String command) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", command});
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append(System.lineSeparator());
        }
        boolean completed = process.waitFor(3, TimeUnit.SECONDS);
        
        if (!completed) {
            process.destroyForcibly();
            return "Command timed out";
        }
        
        return output.toString().trim();
    }
    
    private static boolean commandExists(String command) {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", "command -v " + command});
            return process.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    private static void displaySystemInfo(Map<String, String> systemInfo) {
        System.out.println("\n============ SYSTEM INFORMATION ============");
        
        // Basic OS Information
        System.out.println("\n--- OS INFORMATION ---");
        printIfExists(systemInfo, "OS Name");
        printIfExists(systemInfo, "Distribution");
        printIfExists(systemInfo, "OS Version");
        printIfExists(systemInfo, "OS Architecture");
        printIfExists(systemInfo, "Kernel Version");
        printIfExists(systemInfo, "Hostname");
        printIfExists(systemInfo, "Uptime");
        printIfExists(systemInfo, "Last Boot");
        printIfExists(systemInfo, "User Name");
        printIfExists(systemInfo, "Current Shell");
        printIfExists(systemInfo, "Virtualization");
        
        // Hardware Information
        System.out.println("\n--- HARDWARE INFORMATION ---");
        printIfExists(systemInfo, "System Manufacturer");
        printIfExists(systemInfo, "System Model");
        printIfExists(systemInfo, "BIOS Vendor");
        printIfExists(systemInfo, "BIOS Version");
        printIfExists(systemInfo, "BIOS Date");
        printIfExists(systemInfo, "CPU Model");
        printIfExists(systemInfo, "CPU Architecture");
        printIfExists(systemInfo, "CPU MHz");
        printIfExists(systemInfo, "CPU Cores");
        printIfExists(systemInfo, "CPU Temperature");
        printIfExists(systemInfo, "CPU Usage");
        printIfExists(systemInfo, "GPU");
        printIfExists(systemInfo, "Battery Status");
        
        // Memory Information
        System.out.println("\n--- MEMORY INFORMATION ---");
        printIfExists(systemInfo, "Memory Total");
        printIfExists(systemInfo, "Memory Used");
        printIfExists(systemInfo, "Memory Free");
        printIfExists(systemInfo, "Swap Total");
        printIfExists(systemInfo, "Swap Used");
        
        // Storage Information
        System.out.println("\n--- STORAGE INFORMATION ---");
        printIfExists(systemInfo, "Root Partition Size");
        printIfExists(systemInfo, "Root Partition Used");
        printIfExists(systemInfo, "Root Partition Free");
        printIfExists(systemInfo, "Root Partition Usage");
        printIfExists(systemInfo, "Mount Points");
        
        // Network Information
        System.out.println("\n--- NETWORK INFORMATION ---");
        printIfExists(systemInfo, "Network Interfaces");
        printIfExists(systemInfo, "Public IP");
        printIfExists(systemInfo, "Default Gateway");
        printIfExists(systemInfo, "DNS Servers");
        printIfExists(systemInfo, "Network Received");
        printIfExists(systemInfo, "Network Transmitted");
        
        // System Load
        System.out.println("\n--- SYSTEM LOAD ---");
        printIfExists(systemInfo, "Load Average (1m)");
        printIfExists(systemInfo, "Load Average (5m)");
        printIfExists(systemInfo, "Load Average (15m)");
        printIfExists(systemInfo, "Top CPU Processes");
        printIfExists(systemInfo, "Top Memory Processes");
        
        // Services Information
        System.out.println("\n--- SYSTEM SERVICES ---");
        printIfExists(systemInfo, "Firewall Status");
        printIfExists(systemInfo, "SSH Service");
        printIfExists(systemInfo, "Docker Service");
        printIfExists(systemInfo, "Running Containers");
        printIfExists(systemInfo, "Mysql Service");
        printIfExists(systemInfo, "Postgresql Service");
        printIfExists(systemInfo, "Mongodb Service");
        printIfExists(systemInfo, "Redis Service");
        printIfExists(systemInfo, "Apache2 Service");
        printIfExists(systemInfo, "Nginx Service");
        printIfExists(systemInfo, "Httpd Service");
        printIfExists(systemInfo, "Last Login");
        
        // Java Information
        System.out.println("\n--- JAVA INFORMATION ---");
        printIfExists(systemInfo, "Java Version");
        printIfExists(systemInfo, "Java Vendor");
        
        System.out.println("\n============================================");
    }
    
    private static void printIfExists(Map<String, String> map, String key) {
        if (map.containsKey(key) && map.get(key) != null && !map.get(key).trim().isEmpty()) {
            System.out.println(key + ": " + map.get(key));
        }
    }
}