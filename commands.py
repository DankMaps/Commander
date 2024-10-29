commands = [
    {"command": "HDB info", "description": "Displays information about the running HANA database instances.", "category": "hana"},
    {"command": "HDB version", "description": "Shows the HANA database version and build information.", "category": "hana"},
    {"command": "HDB start", "description": "Start the SAP HANA system (from the system admin user).", "category": "hana"},
    {"command": "HDB stop", "description": "Stop the SAP HANA system (from the system admin user).", "category": "hana"},
    {"command": "hdbsql -i <instance_number> -u <username> -p <password>", "description": "SAP HANA command-line interface for SQL execution.", "category": "hana"},
    {"command": "/usr/sap/<SID>/home/HDBSettings.sh", "description": "View or update configuration settings for HANA.", "category": "hana"},
    {"command": "xs apps", "description": "List of applications deployed in HANA's XS engine.", "category": "hana"},
    {"command": "xs app logs <app-name>", "description": "Check logs for specific XS applications.", "category": "hana"},
    {"command": "free -h", "description": "Display free and used memory in human-readable format.", "category": "hana"},
    {"command": "top", "description": "View the processes and their CPU/memory usage (includes HANA processes).", "category": "hana"},
    {"command": "ps -ef | grep hdb", "description": "View HANA process tree.", "category": "hana"},
    {"command": "df -h", "description": "View disk usage.", "category": "hana"},
    {"command": "ps aux | grep hdb", "description": "Check HANA process list.", "category": "hana"},
    {"command": "sapcontrol -nr <instance_number> -function GetProcessList", "description": "View HANA services (from the Linux terminal).", "category": "hana"},
    {"command": "ifconfig", "description": "Display or configure network interfaces (deprecated, use ip instead).", "category": "network"},
    {"command": "ip a", "description": "Show all IP addresses and network interfaces.", "category": "network"},
    {"command": "ip link set interface up/down", "description": "Enable/disable a network interface.", "category": "network"},
    {"command": "ping hostname", "description": "Send ICMP echo requests to test network connectivity.", "category": "network"},
    {"command": "netstat -tulnp", "description": "Display active network connections.", "category": "network"},
    {"command": "ss -tuln", "description": "Display active connections (preferred over netstat).", "category": "network"},
    {"command": "traceroute hostname", "description": "Display the path packets take to a network host.", "category": "network"},
    {"command": "nslookup hostname", "description": "Query DNS to find IP addresses.", "category": "network"},
    {"command": "dig hostname", "description": "DNS lookup (advanced query).", "category": "network"},
    {"command": "hostnamectl", "description": "Set or display the system hostname.", "category": "network"},
    {"command": "ufw enable/disable", "description": "Enable/disable uncomplicated firewall.", "category": "network"},
    {"command": "ufw allow/deny port", "description": "Allow/deny a specific port through the firewall.", "category": "network"},
    {"command": "scp source destination", "description": "Secure copy files between hosts.", "category": "network"},
    {"command": "ssh user@hostname", "description": "Log into a remote server using SSH.", "category": "network"},
    {"command": "iptables -L", "description": "List current iptables firewall rules.", "category": "network"},
    {"command": "nmcli device status", "description": "Display network status using NetworkManager.", "category": "network"},
    {"command": "mtr hostname", "description": "Combines ping and traceroute to provide real-time packet loss and latency.", "category": "network"},
    {"command": "iftop -i interface", "description": "Display real-time network bandwidth usage per interface.", "category": "network"},
    {"command": "nload", "description": "Visualize incoming and outgoing network traffic in real time.", "category": "network"},
    {"command": "bmon", "description": "Provides a graphical overview of network bandwidth usage.", "category": "network"},
    {"command": "vnstat", "description": "Tracks network traffic usage over time and provides historical data.", "category": "network"},
    {"command": "vnstat -l", "description": "Displays real-time traffic usage.", "category": "network"},
    {"command": "nethogs", "description": "Monitors bandwidth usage per process.", "category": "network"},
    {"command": "tcpdump -i interface", "description": "Captures and analyzes packets on a specific interface.", "category": "network"},
    {"command": "tshark -i interface", "description": "Command-line version of Wireshark for packet capture and analysis.", "category": "network"},
    {"command": "curl -I url", "description": "Transfer data from or to a URL to check HTTP response.", "category": "network"},
    {"command": "wget --spider url", "description": "Fetch files or check HTTP connectivity to a URL.", "category": "network"},
    {"command": "ethtool interface", "description": "Display or change Ethernet device settings.", "category": "network"},
    {"command": "arp -a", "description": "View the system's ARP cache.", "category": "network"},
    {"command": "route -n", "description": "Display or modify IP routing tables.", "category": "network"},
    {"command": "whois domain", "description": "Lookup registration information for a domain or IP.", "category": "network"},
    {"command": "firewalld-cmd --list-all", "description": "View current firewall rules (RHEL/CentOS).", "category": "network"},
    {"command": "nmap -sP network_range", "description": "Scan a network to discover hosts.", "category": "network"},
    {"command": "nc -zv hostname port", "description": "Check if a specific port is open on a host.", "category": "network"},
    {"command": "ip link show", "description": "Show network interfaces.", "category": "network"},
    {"command": "ip route add", "description": "Add a new route.", "category": "network"},
    {"command": "ip rule add", "description": "Add a new routing rule.", "category": "network"},
    {"command": "iptables -A INPUT -p tcp --dport 22 -j ACCEPT", "description": "Allow SSH access via iptables.", "category": "network"},
    {"command": "bridge link show", "description": "Show bridge links.", "category": "network"},
    {"command": "bridge fdb show", "description": "Show bridge forwarding database (MACs learned by bridge).", "category": "network"},
    {"command": "tc qdisc add dev eth0 root handle 1: htb default 10", "description": "Set up a traffic control queue.", "category": "network"},
    {"command": "tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip dport 80 0xffff flowid 1:10", "description": "Add a traffic control filter.", "category": "network"},
    {"command": "firewall-cmd --permanent --add-port=8080/tcp", "description": "Open port 8080 permanently using firewall-cmd.", "category": "network"},
    {"command": "firewall-cmd --reload", "description": "Reload firewall rules using firewall-cmd.", "category": "network"},
    {"command": "nft add table inet mytable", "description": "Create a new nftables table.", "category": "network"},
    {"command": "nft add chain inet mytable mychain { type filter hook input priority 0 \\; }", "description": "Add a chain to nftables.", "category": "network"},
    {"command": "nft add rule inet mytable mychain tcp dport 22 accept", "description": "Allow SSH traffic in nftables.", "category": "network"},
    {"command": "dhclient -v eth0", "description": "Request an IP from DHCP server.", "category": "network"},
    {"command": "sudo systemctl restart isc-dhcp-server", "description": "Restart the DHCP server.", "category": "network"},
    {"command": "named -g", "description": "Start BIND in the foreground for debugging.", "category": "network"},
    {"command": "rndc reload", "description": "Reload BIND configuration.", "category": "network"},
    {"command": "systemctl start vsftpd", "description": "Start the FTP server using vsftpd.", "category": "network"},
    {"command": "openvpn --config client.ovpn", "description": "Start VPN connection using OpenVPN.", "category": "network"},
    {"command": "fail2ban-client status sshd", "description": "Show status of SSH jail in fail2ban.", "category": "network"},
    {"command": "fail2ban-client set sshd unbanip <ip-address>", "description": "Manually unban an IP in fail2ban.", "category": "network"},
    {"command": "ssh-keygen -t rsa -b 4096", "description": "Generate an RSA key pair.", "category": "network"},
    {"command": "scp file user@remote_host:/path", "description": "Copy file via SSH.", "category": "network"},
    {"command": "rsync -avz /local/dir user@remote_host:/remote/dir", "description": "Synchronize directories over SSH.", "category": "network"},
    {"command": "mtr google.com", "description": "Run MTR diagnostic for real-time network diagnostics.", "category": "network"},
    {"command": "iperf3 -s", "description": "Run iperf3 as server for bandwidth testing.", "category": "network"},
    {"command": "iperf3 -c <server_ip>", "description": "Run iperf3 as client to test bandwidth.", "category": "network"},
    {"command": "arping -I eth0 192.168.1.1", "description": "Ping a host using ARP.", "category": "network"},
    {"command": "strace -p $(pgrep -f sshd)", "description": "Trace SSH daemon using strace.", "category": "network"},
    {"command": "lsof -i :80", "description": "Show processes using port 80.", "category": "network"},
    {"command": "ss -atunp", "description": "Show all TCP/UDP sockets with process names.", "category": "network"},
    # ... [other existing categories and commands] ...
    {"command": "apt update", "description": "Update the list of available packages.", "category": "package"},
    {"command": "apt upgrade", "description": "Upgrade all installed packages.", "category": "package"},
    {"command": "apt install package", "description": "Install a new package.", "category": "package"},
    {"command": "apt remove package", "description": "Remove a package.", "category": "package"},
    {"command": "apt autoremove", "description": "Remove unnecessary packages.", "category": "package"},
    {"command": "dpkg -i package.deb", "description": "Install a package from a .deb file.", "category": "package"},
    {"command": "dpkg -l", "description": "List all installed packages.", "category": "package"},
    {"command": "snap install package", "description": "Install a package using Snap.", "category": "package"},
    {"command": "snap list", "description": "List installed Snap packages.", "category": "package"},
    {"command": "snap remove package", "description": "Remove a Snap package.", "category": "package"},
    {"command": "free -h", "description": "Display free and used memory.", "category": "monitoring"},
    {"command": "uptime", "description": "Show how long the system has been running.", "category": "monitoring"},
    {"command": "dmesg", "description": "Display kernel messages.", "category": "monitoring"},
    {"command": "iostat", "description": "Report CPU and input/output statistics.", "category": "monitoring"},
    {"command": "vmstat", "description": "Report system performance.", "category": "monitoring"},
    {"command": "lsof", "description": "List open files.", "category": "monitoring"},
    {"command": "df -h", "description": "Report file system disk space usage.", "category": "monitoring"},
    {"command": "iotop", "description": "Monitor I/O usage by processes.", "category": "monitoring"}
]
