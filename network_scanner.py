#!/usr/bin/env python3
"""
Network Users Scanner with Pandas Output
Displays connected devices and network information in a nice table format
"""

import pandas as pd
import subprocess
import socket
import platform
import re
import sys
from typing import List, Dict
import argparse

class NetworkScanner:
    def __init__(self):
        self.results = []
        self.has_jinja2 = self.check_jinja2()
    
    def check_jinja2(self) -> bool:
        """Check if jinja2 is available for pandas styling"""
        try:
            import jinja2
            return True
        except ImportError:
            return False
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"
    
    def get_network_range(self) -> str:
        """Determine network range based on local IP"""
        local_ip = self.get_local_ip()
        ip_parts = local_ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    def scan_with_nmap(self) -> List[Dict]:
        """Scan network using nmap"""
        network_range = self.get_network_range()
        
        print(f"🔍 Scanning network: {network_range}")
        print("This may take a few moments...\n")
        
        try:
            # Run nmap scan
            result = subprocess.run(
                ['nmap', '-sn', network_range],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            devices = []
            current_device = {}
            
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    # Save previous device if exists
                    if current_device:
                        devices.append(current_device)
                    
                    # Start new device
                    host_info = line.replace('Nmap scan report for ', '').strip()
                    if '(' in host_info and ')' in host_info:
                        hostname = host_info.split('(')[1].split(')')[0]
                        ip = host_info.split('(')[0].strip()
                    else:
                        parts = host_info.split()
                        if len(parts) > 1:
                            hostname = parts[0]
                            ip = parts[-1]
                        else:
                            hostname = 'Unknown'
                            ip = parts[0]
                    
                    current_device = {
                        'Hostname': hostname,
                        'IP': ip,
                        'MAC': 'Unknown',
                        'Vendor': 'Unknown',
                        'Status': 'Up'
                    }
                
                elif 'MAC Address:' in line:
                    mac_info = line.split('MAC Address: ')[1]
                    mac_parts = mac_info.split(' ')
                    current_device['MAC'] = mac_parts[0]
                    if len(mac_parts) > 1:
                        current_device['Vendor'] = ' '.join(mac_parts[1:]).strip('()')
            
            # Add the last device
            if current_device:
                devices.append(current_device)
            
            return devices
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            print(f"⚠️  Nmap scan failed: {e}")
            print("Trying alternative method...")
            return self.scan_with_ping()
    
    def scan_with_ping(self) -> List[Dict]:
        """Alternative scan using ping for local network"""
        local_ip = self.get_local_ip()
        base_ip = '.'.join(local_ip.split('.')[:-1])
        
        devices = []
        
        # Scan first 20 IPs in the network (adjust as needed)
        for i in range(1, 21):
            ip = f"{base_ip}.{i}"
            try:
                # Ping with 1 packet, timeout 1 second
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                result = subprocess.run(
                    ['ping', param, '1', '-W', '1', ip],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                
                if result.returncode == 0:
                    # Try to get hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = 'Unknown'
                    
                    devices.append({
                        'IP': ip,
                        'Hostname': hostname,
                        'MAC': 'Unknown',
                        'Vendor': 'Unknown',
                        'Status': 'Up'
                    })
                    
            except:
                continue
        
        return devices
    
    def get_current_connections(self) -> List[Dict]:
        """Get current network connections to the system"""
        try:
            result = subprocess.run(
                ['ss', '-tunap'],
                capture_output=True,
                text=True
            )
            
            connections = []
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        local_addr = parts[4] if len(parts) > 4 else 'Unknown'
                        remote_addr = parts[5] if len(parts) > 5 else 'Unknown'
                        
                        connections.append({
                            'Protocol': parts[0],
                            'Local Address': local_addr,
                            'Remote Address': remote_addr,
                            'State': parts[1] if len(parts) > 1 else 'Unknown',
                            'Process': parts[-1] if 'users' in line else 'Unknown'
                        })
            
            return connections
            
        except Exception as e:
            print(f"⚠️  Could not get connections: {e}")
            return []
    
    def format_dataframe(self, df, title="", style_type="default"):
        """Format DataFrame with or without styling"""
        if self.has_jinja2:
            try:
                if style_type == "default":
                    styled = df.style.set_properties(**{
                        'background-color': '#f8f9fa',
                        'color': 'black',
                        'border-color': 'white'
                    }).set_caption(title)
                elif style_type == "connections":
                    styled = df.style.set_properties(**{
                        'background-color': '#f0f8ff',
                        'color': 'black'
                    }).set_caption(title)
                else:  # info style
                    styled = df.style.set_properties(**{
                        'background-color': '#fff3cd',
                        'color': 'black'
                    }).set_caption(title)
                
                return styled
            except Exception:
                # Fallback if styling fails
                return df
        else:
            return df
    
    def display_network_devices(self):
        """Display network devices in a nice pandas table"""
        print("🖧 NETWORK DEVICES SCAN")
        print("=" * 80)
        
        devices = self.scan_with_nmap()
        
        if not devices:
            print("❌ No devices found or scanning failed.")
            print("Please install nmap for better results: sudo apt install nmap")
            return
        
        # Create DataFrame
        df = pd.DataFrame(devices)
        
        # Display the table
        if self.has_jinja2:
            styled_df = self.format_dataframe(df, f"📱 Found {len(devices)} devices on network")
            print(styled_df.to_string())
        else:
            print(f"📱 Found {len(devices)} devices on network")
            print(df.to_string(index=False))
            print("\n💡 Tip: Install jinja2 for better table formatting: pip install jinja2")
        
        # Summary statistics
        print(f"\n📊 Summary:")
        print(f"   • Total devices found: {len(devices)}")
        print(f"   • Your local IP: {self.get_local_ip()}")
        print(f"   • Network range: {self.get_network_range()}")
    
    def display_current_connections(self):
        """Display current network connections"""
        print("\n🔗 CURRENT NETWORK CONNECTIONS")
        print("=" * 80)
        
        connections = self.get_current_connections()
        
        if not connections:
            print("❌ No active connections found or command failed.")
            return
        
        df = pd.DataFrame(connections)
        
        if self.has_jinja2:
            styled_df = self.format_dataframe(df, f"🌐 Active connections: {len(connections)}", "connections")
            print(styled_df.to_string())
        else:
            print(f"🌐 Active connections: {len(connections)}")
            print(df.to_string(index=False))
    
    def display_system_info(self):
        """Display system network information"""
        print("\n💻 SYSTEM NETWORK INFORMATION")
        print("=" * 80)
        
        info_data = []
        
        try:
            # Get hostname
            hostname = socket.gethostname()
            info_data.append({'Property': 'Hostname', 'Value': hostname})
            
            # Get local IP
            local_ip = self.get_local_ip()
            info_data.append({'Property': 'Local IP', 'Value': local_ip})
            
            # Get network interfaces
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
            interfaces = re.findall(r'\d+: (\w+):', result.stdout)
            info_data.append({'Property': 'Network Interfaces', 'Value': ', '.join(interfaces)})
            
            # Get default gateway
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            default_route = [line for line in result.stdout.split('\n') if 'default' in line]
            if default_route:
                info_data.append({'Property': 'Default Gateway', 'Value': default_route[0]})
            
            df = pd.DataFrame(info_data)
            
            if self.has_jinja2:
                styled_df = self.format_dataframe(df, "System Information", "info")
                print(styled_df.to_string())
            else:
                print(df.to_string(index=False))
            
        except Exception as e:
            print(f"❌ Could not get system info: {e}")

def check_dependencies():
    """Check and install required dependencies"""
    try:
        import pandas
    except ImportError:
        print("❌ pandas is required but not installed.")
        print("Installing pandas...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pandas'])
        print("✅ pandas installed successfully!")
    
    try:
        import jinja2
    except ImportError:
        print("💡 jinja2 is not installed. Table styling will be basic.")
        print("For better formatting, install jinja2: pip install jinja2")

def main():
    # Check dependencies first
    check_dependencies()
    
    parser = argparse.ArgumentParser(description='Network Users Scanner with Pandas Output')
    parser.add_argument('--devices', action='store_true', help='Scan network devices only')
    parser.add_argument('--connections', action='store_true', help='Show current connections only')
    parser.add_argument('--info', action='store_true', help='Show system info only')
    parser.add_argument('--simple', action='store_true', help='Use simple output without colors')
    
    args = parser.parse_args()
    
    scanner = NetworkScanner()
    
    if args.devices:
        scanner.display_network_devices()
    elif args.connections:
        scanner.display_current_connections()
    elif args.info:
        scanner.display_system_info()
    else:
        # Show all information
        scanner.display_system_info()
        scanner.display_network_devices()
        scanner.display_current_connections()

if __name__ == "__main__":
    main()