# Smart Home Network Detection & Management System 
## Installation and Setup Guide

This guide will help you install and configure the Smart Home Network Detection & Management System (SHNDMS) on your Laptop2 to protect your Smart TV from network attacks as outlined in your experiment.

## System Requirements

- Laptop2 running Linux (Ubuntu/Debian recommended)
- Python 3.7 or higher
- Network interface with monitoring capabilities
- Administrative (sudo) privileges

## Installation Steps

### 1. Install Required Dependencies
[attack-detection-flowchart.mermaid](..%2F..%2FDownloads%2Fattack-detection-flowchart.mermaid)
```bash
# Update package repositories
sudo apt update

# Install Python and pip if not already installed
sudo apt install -y python3 python3-pip python3-dev

# Install network tools
sudo apt install -y net-tools tcpdump wireshark iptables

# Install Snort IDS (optional but recommended)
sudo apt install -y snort

# Install required Python libraries
pip3 install -r requirements.txt
```

### 2. Create requirements.txt

Create a file named `requirements.txt` with the following contents:

```
pyshark>=0.4.3
scapy>=2.4.5
netifaces>=0.11.0
colorama>=0.4.4
requests>=2.25.1
```

### 3. Download the SHNDMS Software

Download the main Python script to your Laptop2:

```bash
# Create a directory for the application
mkdir -p ~/shndms
cd ~/shndms

# Download the script
# Either clone from a repository or copy the script manually
```

### 4. Configure Network Settings

Edit the configuration in the script to match your network setup:

```python
CONFIG = {
    "smart_tv_ip": "192.168.1.100",  # Change to your Smart TV's IP
    "defender_ip": "192.168.1.102",  # Change to Laptop2's IP
    "attacker_ip": "192.168.1.101",  # Change to Laptop1's IP
    "router_ip": "192.168.1.1",      # Change to your router's IP
    "web_interface_port": 8080,      # Port for web interface
    "interface": "wlan0",            # Change to your network interface
    # Other settings...
}
```

To find your network interface name, run:

```bash
ip addr
```

### 5. Configure Snort (Optional)

If you installed Snort, it needs to be configured:

```bash
# Backup original configuration
sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.bak

# Make sure rules directory exists
sudo mkdir -p /etc/snort/rules

# Create local rules file if not exists
sudo touch /etc/snort/rules/local.rules
```

### 6. Running the System

#### With GUI (Recommended for desktop environments):

```bash
cd ~/shndms
python3 shndms.py
```

#### Without GUI (Headless mode for servers):

```bash
cd ~/shndms
python3 shndms.py --nogui
```

#### Running as a Service (Recommended for continuous operation)

Create a systemd service file:

```bash
sudo nano /etc/systemd/system/shndms.service
```

Add the following content:

```
[Unit]
Description=Smart Home Network Detection & Management System
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/shndms
ExecStart=/usr/bin/python3 /home/YOUR_USERNAME/shndms/shndms.py --nogui
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Replace `YOUR_USERNAME` with your actual username.

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable shndms.service
sudo systemctl start shndms.service
```

## Setting Up the Smart TV Connection

1. Ensure your Smart TV is connected to the same network
2. Verify connectivity with a ping test:
   ```bash
   ping 192.168.1.100  # Use your Smart TV's IP
   ```
3. Upload files to the `/transfers` directory to make them available for sending to the TV

## Accessing the Web Interface

After starting the system, you can access the web interface by opening a browser on any device connected to your network:

```
http://192.168.1.102:8080  # Replace with Laptop2's IP
```

## Security Considerations

1. **Firewall Configuration**: Configure your firewall to allow the web interface port only from trusted devices:
   ```bash
   sudo ufw allow from 192.168.1.0/24 to any port 8080
   ```

2. **Authentication**: The current implementation doesn't include authentication. Consider running behind a secured proxy if exposed beyond your local network.

3. **Regular Updates**: Keep all system components updated:
   ```bash
   sudo apt update && sudo apt upgrade
   ```

## Troubleshooting

1. **Permission Issues**:
   - Ensure the script is running with sufficient privileges for network monitoring
   - If using non-root user, you may need to add capabilities:
     ```bash
     sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/python3.9
     ```

2. **Network Interface Not Found**:
   - Check available interfaces with `ip addr` or `ifconfig`
   - Update the CONFIG["interface"] parameter in the script

3. **Unable to Detect Attacks**:
   - Ensure your network interface supports monitoring mode
   - Try using a different interface (e.g., USB WiFi adapter with monitoring capability)

4. **Service Fails to Start**:
   - Check logs: `sudo journalctl -u shndms.service`
   - Verify paths and permissions in the service file

## Attack Simulations

The system is designed to detect and mitigate the following attacks from your experiment:

1. **Network Sniffing**: Detects unusual ARP traffic that might indicate sniffing
2. **SYN Flood**: Identifies and blocks TCP SYN flood attempts
3. **Slowloris**: Detects and mitigates slow HTTP request attacks
4. **Router Credential Attacks**: Monitors for unusual connection attempts to router

## Extending the System

You can extend the system with additional features:

1. Add more detection rules to Snort
2. Implement machine learning for anomaly detection
3. Add email/SMS alerting for critical attacks
4. Integrate with other smart home security systems
