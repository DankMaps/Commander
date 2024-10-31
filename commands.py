commands = [
    # SAP HANA Commands
    {"command": "HDB info", "description": "Displays information about the running HANA database instances.", "category": "hana"},
    {"command": "HDB version", "description": "Shows the HANA database version and build information.", "category": "hana"},
    {"command": "HDB start", "description": "Start the SAP HANA system (from the system admin user).", "category": "hana"},
    {"command": "HDB stop", "description": "Stop the SAP HANA system (from the system admin user).", "category": "hana"},
    {"command": "hdbsql -i <instance_number> -u <username> -p <password>", "description": "SAP HANA command-line interface for SQL execution.", "category": "hana"},
    {"command": "/usr/sap/<SID>/home/HDBSettings.sh", "description": "View or update configuration settings for HANA.", "category": "hana"},
    {"command": "xs apps", "description": "List of applications deployed in HANA's XS engine.", "category": "hana"},
    {"command": "xs app logs <app-name>", "description": "Check logs for specific XS applications.", "category": "hana"},
    {"command": "ps -ef | grep hdb", "description": "View HANA process tree.", "category": "hana"},
    {"command": "ps aux | grep hdb", "description": "Check HANA process list.", "category": "hana"},
    {"command": "sapcontrol -nr <instance_number> -function GetProcessList", "description": "View HANA services (from the Linux terminal).", "category": "hana"},

    # Network Commands
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
    {"command": "rsync -avz /local/dir user@remote_host:/remote/dir", "description": "Synchronize directories over SSH.", "category": "network"},
    {"command": "mtr google.com", "description": "Run MTR diagnostic for real-time network diagnostics.", "category": "network"},
    {"command": "iperf3 -s", "description": "Run iperf3 as server for bandwidth testing.", "category": "network"},
    {"command": "iperf3 -c <server_ip>", "description": "Run iperf3 as client to test bandwidth.", "category": "network"},
    {"command": "arping -I eth0 192.168.1.1", "description": "Ping a host using ARP.", "category": "network"},
    {"command": "strace -p $(pgrep -f sshd)", "description": "Trace SSH daemon using strace.", "category": "network"},
    {"command": "lsof -i :80", "description": "Show processes using port 80.", "category": "network"},
    {"command": "ss -atunp", "description": "Show all TCP/UDP sockets with process names.", "category": "network"},

    # Package Management Commands
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

    # Monitoring Commands
    {"command": "free -h", "description": "Display free and used memory in human-readable format.", "category": "monitoring"},
    {"command": "uptime", "description": "Show how long the system has been running.", "category": "monitoring"},
    {"command": "dmesg", "description": "Display kernel messages.", "category": "monitoring"},
    {"command": "iostat", "description": "Report CPU and input/output statistics.", "category": "monitoring"},
    {"command": "vmstat", "description": "Report system performance.", "category": "monitoring"},
    {"command": "lsof", "description": "List open files.", "category": "monitoring"},
    {"command": "iotop", "description": "Monitor I/O usage by processes.", "category": "monitoring"},

    # File Management Commands
    {"command": "ls", "description": "List directory contents.", "category": "file"},
    {"command": "cp source destination", "description": "Copy files or directories.", "category": "file"},
    {"command": "mv source destination", "description": "Move or rename files and directories.", "category": "file"},
    {"command": "rm file", "description": "Remove files.", "category": "file"},
    {"command": "rm -r directory", "description": "Remove directories recursively.", "category": "file"},
    {"command": "chmod permissions file", "description": "Change file permissions.", "category": "file"},
    {"command": "chown user:group file", "description": "Change file owner and group.", "category": "file"},
    {"command": "find /path -name filename", "description": "Find files by name.", "category": "file"},
    {"command": "du -sh /path", "description": "Display the size of a directory or file.", "category": "file"},
    {"command": "touch filename", "description": "Create an empty file or update file timestamps.", "category": "file"},
    {"command": "ln -s target linkname", "description": "Create a symbolic link.", "category": "file"},
    {"command": "cat file", "description": "Display the contents of a file.", "category": "file"},
    {"command": "less file", "description": "View file contents one page at a time.", "category": "file"},
    {"command": "tar -cvf archive.tar files", "description": "Create a tar archive.", "category": "file"},
    {"command": "tar -xvf archive.tar", "description": "Extract a tar archive.", "category": "file"},
    {"command": "gzip file", "description": "Compress files with gzip.", "category": "file"},
    {"command": "gunzip file.gz", "description": "Decompress gzip files.", "category": "file"},
    {"command": "rsync -av source destination", "description": "Synchronize files and directories between two locations.", "category": "file"},

    # User Management Commands
    {"command": "adduser username", "description": "Create a new user.", "category": "users"},
    {"command": "deluser username", "description": "Remove a user account.", "category": "users"},
    {"command": "usermod -aG group username", "description": "Add a user to a group.", "category": "users"},
    {"command": "passwd username", "description": "Change user password.", "category": "users"},
    {"command": "whoami", "description": "Display the current user.", "category": "users"},
    {"command": "id username", "description": "Display user ID and group ID information.", "category": "users"},
    {"command": "groups username", "description": "Show group memberships for a user.", "category": "users"},
    {"command": "su username", "description": "Switch to another user account.", "category": "users"},
    {"command": "chage -l username", "description": "Display password aging information.", "category": "users"},
    {"command": "last", "description": "Show the last login of users.", "category": "users"},
    {"command": "w", "description": "Display who is logged in and their activity.", "category": "users"},
    {"command": "userdel -r username", "description": "Delete a user and their home directory.", "category": "users"},
    {"command": "sudo visudo", "description": "Edit the sudoers file to manage user permissions.", "category": "users"},

    # Process Management Commands
    {"command": "top", "description": "Display real-time processes.", "category": "process"},
    {"command": "htop", "description": "Interactive process viewer (requires installation).", "category": "process"},
    {"command": "ps aux", "description": "Display all running processes.", "category": "process"},
    {"command": "kill PID", "description": "Terminate a process by PID.", "category": "process"},
    {"command": "killall processname", "description": "Terminate all processes by name.", "category": "process"},
    {"command": "pkill processname", "description": "Send signals to processes by name.", "category": "process"},
    {"command": "nice -n priority command", "description": "Run a command with a specified priority.", "category": "process"},
    {"command": "renice priority PID", "description": "Change the priority of a running process.", "category": "process"},
    {"command": "service servicename start/stop/restart/status", "description": "Manage services.", "category": "process"},
    {"command": "systemctl start/stop servicename", "description": "Start/stop a service.", "category": "process"},
    {"command": "systemctl enable/disable servicename", "description": "Enable/disable a service to start at boot.", "category": "process"},
    {"command": "systemctl status servicename", "description": "Check the status of a service.", "category": "process"},
    {"command": "journalctl -xe", "description": "View system logs.", "category": "process"},
    {"command": "pgrep processname", "description": "Get the PID of a process by name.", "category": "process"},
    # Suggested Additional Commands for Troubleshooting, Monitoring, and Management
    # Troubleshooting Commands
    {"command": "dstat", "description": "Versatile resource statistics tool replacing vmstat, iostat, netstat, and ifstat.", "category": "troubleshooting"},
    {"command": "lshw -short", "description": "Lists detailed hardware configuration in a short format.", "category": "troubleshooting"},
    {"command": "strace -p <PID>", "description": "Trace system calls and signals of a specific process.", "category": "troubleshooting"},
    {"command": "lspci", "description": "Lists all PCI devices.", "category": "troubleshooting"},
    {"command": "lsusb", "description": "Lists all USB devices.", "category": "troubleshooting"},
    {"command": "blkid", "description": "Identifies block devices and their attributes.", "category": "troubleshooting"},
    {"command": "ncdu /path", "description": "NCurses Disk Usage for viewing disk usage in a user-friendly interface.", "category": "troubleshooting"},
    
    # Monitoring Commands
    {"command": "sar -u 1 3", "description": "Collects and reports CPU usage statistics at 1-second intervals for 3 times.", "category": "monitoring"},
    {"command": "glances", "description": "An advanced system monitoring tool that provides a comprehensive overview of system metrics.", "category": "monitoring"},
    {"command": "watch -n 5 df -h", "description": "Executes 'df -h' every 5 seconds to monitor disk space usage in real-time.", "category": "monitoring"},
    {"command": "systemd-analyze blame", "description": "Analyzes and displays the time taken by each service during system boot.", "category": "monitoring"},
    {"command": "perf top", "description": "Displays real-time performance profiling of the system.", "category": "monitoring"},
    {"command": "iotop -o", "description": "Displays I/O usage by processes with disk I/O in real-time.", "category": "monitoring"},

    # Management Commands
    {"command": "crontab -e", "description": "Edit the current user's crontab to schedule periodic jobs.", "category": "management"},
    {"command": "ansible all -m ping", "description": "Use Ansible to ping all managed hosts to check connectivity.", "category": "management"},
    {"command": "docker ps -a", "description": "List all Docker containers, including stopped ones.", "category": "management"},
    {"command": "kubectl get pods", "description": "List all pods in the current Kubernetes namespace.", "category": "management"},
    {"command": "git status", "description": "Show the working tree status in a Git repository.", "category": "management"},
    {"command": "tmux new -s session_name", "description": "Create a new tmux session named 'session_name'.", "category": "management"},
    
    # Security Commands
    {"command": "fail2ban-client status", "description": "Show the overall status of the Fail2Ban server.", "category": "security"},
    {"command": "sestatus", "description": "Display the current status of SELinux.", "category": "security"},
    {"command": "auditctl -l", "description": "List all active audit rules.", "category": "security"},
    
    # File System and Storage Commands
    {"command": "mount /dev/sda1 /mnt", "description": "Mount the filesystem on /dev/sda1 to the /mnt directory.", "category": "filesystem"},
    {"command": "umount /mnt", "description": "Unmount the filesystem from the /mnt directory.", "category": "filesystem"},
    {"command": "fdisk /dev/sda", "description": "Start the fdisk utility to manage disk partitions on /dev/sda.", "category": "filesystem"},
    {"command": "parted /dev/sda", "description": "Start the parted utility for advanced disk partitioning on /dev/sda.", "category": "filesystem"},
    {"command": "mkfs.ext4 /dev/sda1", "description": "Create an ext4 filesystem on /dev/sda1.", "category": "filesystem"},
    {"command": "lsblk", "description": "List information about all available or specified block devices.", "category": "filesystem"},
    
    # Logging and Log Management Commands
    {"command": "logrotate /etc/logrotate.conf", "description": "Rotate, compress, and mail system logs based on the configuration.", "category": "logging"},
    {"command": "grep 'error' /var/log/syslog | awk '{print $5}'", "description": "Search for 'error' in syslog and extract the fifth field using awk.", "category": "logging"},
    
    # System Information Commands
    {"command": "uname -a", "description": "Display all system information including kernel version and hardware details.", "category": "system_info"},
    {"command": "lsb_release -a", "description": "Display Linux distribution information.", "category": "system_info"},
    {"command": "hostname", "description": "Show or set the system's hostname.", "category": "system_info"},
    
    # Advanced Networking Tools
    {"command": "bpftrace -e 'kprobe:sys_clone { printf(\"Process cloned\\n\"); }'", "description": "Use BPFTrace to trace the 'sys_clone' kernel probe and print a message when a process is cloned.", "category": "networking"},
    {"command": "ipvsadm -L -n", "description": "List IP Virtual Server configurations numerically.", "category": "networking"},
    {"command": "curl -X POST -d 'param=value' http://example.com", "description": "Send a POST request with data to a specified URL using cURL.", "category": "networking"},
    # In commands.py, ensure these commands use consistent categories:

    # System commands (change category from system_info to system)
    {"command": "uname -a", "description": "Display all system information including kernel version and hardware details.", "category": "system"},
    {"command": "lsb_release -a", "description": "Display Linux distribution information.", "category": "system"},
    {"command": "hostname", "description": "Show or set the system's hostname.", "category": "system"},

    # Management commands remain as is
    {"command": "crontab -e", "description": "Edit the current user's crontab to schedule periodic jobs.", "category": "management"},
    {"command": "ansible all -m ping", "description": "Use Ansible to ping all managed hosts to check connectivity.", "category": "management"},

    # Troubleshooting commands remain as is
    {"command": "dstat", "description": "Versatile resource statistics tool.", "category": "troubleshooting"},
    {"command": "lshw -short", "description": "Lists detailed hardware configuration.", "category": "troubleshooting"},

    # Virtualization Commands
    {"command": "virsh list --all", "description": "List all virtual machines managed by libvirt, including inactive ones.", "category": "virtualization"},
    {"command": "qemu-img create -f qcow2 disk.img 10G", "description": "Create a new QEMU disk image named 'disk.img' with a size of 10GB.", "category": "virtualization"},
    
    # Additional commands to append to the list:
    # Process Management category:
    {"command": "pstree", "description": "Display running processes as a tree structure.", "category": "process"},
    {"command": "fuser -k port/tcp", "description": "Kill process using specified TCP port.", "category": "process"},
    {"command": "schedtool -B pid", "description": "Set CPU scheduling policy.", "category": "process"},
    {"command": "taskset -pc 0-2 pid", "description": "Set CPU affinity for process.", "category": "process"},

    # File Management category:
    {"command": "lsattr", "description": "List file attributes on Linux filesystem.", "category": "file"},
    {"command": "chattr +i file", "description": "Make file immutable.", "category": "file"},
    {"command": "fuser file", "description": "Identify processes using file.", "category": "file"},
    {"command": "dd if=/dev/zero of=file bs=1M count=100", "description": "Create file of specific size.", "category": "file"},

    # Monitoring category:
    {"command": "pidstat", "description": "Report CPU/memory statistics for processes.", "category": "monitoring"},
    {"command": "sysstat", "description": "System performance tools collection.", "category": "monitoring"},
    {"command": "atop", "description": "Advanced system & process monitor.", "category": "monitoring"},
    {"command": "nmon", "description": "Performance monitoring tool.", "category": "monitoring"},

    # Network category:
    {"command": "tc qdisc", "description": "Configure traffic control queuing discipline.", "category": "network"},
    {"command": "ipcalc", "description": "Perform IP subnet calculations.", "category": "network"},
    {"command": "ethtool -S interface", "description": "Show network interface statistics.", "category": "network"},
    {"command": "brctl show", "description": "Show network bridge information.", "category": "network"},

    # Package category:
    {"command": "apt-file search filename", "description": "Search for file in packages.", "category": "package"},
    {"command": "apt-mark hold package", "description": "Prevent package from being upgraded.", "category": "package"},
    {"command": "dpkg-reconfigure package", "description": "Reconfigure installed package.", "category": "package"},
    {"command": "apt-cache policy package", "description": "Display package installation candidate.", "category": "package"},
    

    # System Maintenance
    {"command": "updatedb", "description": "Update the locate database for finding files quickly.", "category": "system"},
    {"command": "sync", "description": "Synchronize cached writes to persistent storage.", "category": "system"},
    {"command": "swapoff -a && swapon -a", "description": "Clear swap space by disabling and re-enabling it.", "category": "system"},
    {"command": "ldconfig", "description": "Update shared library cache.", "category": "system"},
    
    # Diagnostics
    {"command": "smartctl -a /dev/sda", "description": "Show SMART status of hard drive for potential failures.", "category": "diagnostics"},
    {"command": "dmidecode", "description": "Display hardware info from BIOS/EFI.", "category": "diagnostics"},
    {"command": "journalctl -p err", "description": "Show only error messages from system logs.", "category": "diagnostics"},
    {"command": "sosreport", "description": "Collect system configuration and diagnostic information.", "category": "diagnostics"},
    
    # Security
    {"command": "chroot /mnt/system", "description": "Change root directory, useful for system recovery.", "category": "security"},
    {"command": "ausearch -k auth", "description": "Search audit logs for authentication events.", "category": "security"},
    {"command": "PAM_AUTH_UPDATE", "description": "Configure PAM authentication modules.", "category": "security"},
    {"command": "lynis audit system", "description": "Perform security audit of the system.", "category": "security"},
    
    # Storage Management
    {"command": "lvextend -L +10G /dev/vg/lv", "description": "Extend logical volume size.", "category": "storage"},
    {"command": "vgdisplay", "description": "Display volume group information.", "category": "storage"},
    {"command": "xfs_repair /dev/sda1", "description": "Repair XFS filesystem.", "category": "storage"},
    {"command": "tune2fs -l /dev/sda1", "description": "Display/tune ext filesystem parameters.", "category": "storage"},
    
    # Process Control
    {"command": "taskset -c 0,1 process_name", "description": "Set/retrieve CPU affinity of a process.", "category": "process"},
    {"command": "ionice -c 2 -n 0 command", "description": "Run command with best-effort I/O priority.", "category": "process"},
    {"command": "schedtool -B process_id", "description": "Set scheduling policy for a process.", "category": "process"},
    {"command": "chrt --rr 99 command", "description": "Run command with real-time priority.", "category": "process"},

    # Backup and Recovery Commands
    {"command": "tar --create --file=backup.tar --listed-incremental=snapshot.file /path/to/directory", "description": "Create an incremental backup of a directory using tar.", "category": "backup"},
    {"command": "rsnapshot daily", "description": "Run rsnapshot to perform a daily filesystem snapshot based on configuration.", "category": "backup"}
]
