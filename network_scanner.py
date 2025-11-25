import pandas as pd
import subprocess
import socket
import platform
import re
from typing import List, Dict
import argparse

class NetworkScanner:
    def __init__(self):
        self.results = []
    
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
                    current_device = {
                        'Hostname': host_info.split(' ')[0] if '(' not in host_info else host_info.split('(')[1].replace(')', ''),
                        'IP': host_info.split(' ')[-1] if '(' in host_info else host_info,
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
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
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
                        connections.append({
                            'Protocol': parts[0],
                            'Local Address': parts[4],
                            'Remote Address': parts[5],
                            'State': parts[1] if len(parts) > 1 else 'Unknown',
                            'Process': parts[-1] if 'users' in parts else 'Unknown'
                        })
            
            return connections
            
        except Exception as e:
            print(f"⚠️  Could not get connections: {e}")
            return []
    
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
        
        # Style the DataFrame
        styled_df = df.style\
            .set_properties(**{
                'background-color': '#f8f9fa',
                'color': 'black',
                'border-color': 'white'
            })\
            .set_table_styles([
                {'selector': 'th', 'props': [('background-color', '#007acc'), 
                                           ('color', 'white'),
                                           ('font-weight', 'bold'),
                                           ('padding', '8px'),
                                           ('border', '1px solid white')]},
                {'selector': 'td', 'props': [('padding', '6px'),
                                           ('border', '1px solid #ddd')]},
                {'selector': 'tr:hover', 'props': [('background-color', '#ffff99')]}
            ])\
            .hide(axis='index')\
            .set_caption(f"📱 Found {len(devices)} devices on network")
        
        # Display the table
        print(styled_df.to_string())
        
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
        
        styled_df = df.style\
            .set_properties(**{
                'background-color': '#f0f8ff',
                'color': 'black',
                'border-color': 'white'
            })\
            .set_table_styles([
                {'selector': 'th', 'props': [('background-color', '#28a745'), 
                                           ('color', 'white'),
                                           ('font-weight', 'bold')]},
                {'selector': 'tr:hover', 'props': [('background-color', '#e8f4fd')]}
            ])\
            .hide(axis='index')\
            .set_caption(f"🌐 Active connections: {len(connections)}")
        
        print(styled_df.to_string())
    
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
            styled_df = df.style.hide(axis='index').set_properties(**{
                'background-color': '#fff3cd',
                'color': 'black'
            })
            
            print(styled_df.to_string())
            
        except Exception as e:
            print(f"❌ Could not get system info: {e}")

def main():
    parser = argparse.ArgumentParser(description='Network Users Scanner with Pandas Output')
    parser.add_argument('--devices', action='store_true', help='Scan network devices only')
    parser.add_argument('--connections', action='store_true', help='Show current connections only')
    parser.add_argument('--info', action='store_true', help='Show system info only')
    
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
