import pandas as pd
import subprocess
import socket
import re
from typing import List, Dict
import argparse



class NetworkScanner:
    def __init__(self):
        self.results = []
    
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
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
                    if current_device:
                        devices.append(current_device)
                    
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
                        'IP Address': ip,
                        'MAC Address': 'Unknown',
                        'Vendor': 'Unknown',
                        'Status': 'Up'
                    }
                
                elif 'MAC Address:' in line:
                    mac_info = line.split('MAC Address: ')[1]
                    mac_parts = mac_info.split(' ')
                    current_device['MAC Address'] = mac_parts[0]
                    if len(mac_parts) > 1:
                        current_device['Vendor'] = ' '.join(mac_parts[1:]).strip('()')
            
            if current_device:
                devices.append(current_device)
            
            return devices
            
        except Exception as e:
            print(f"⚠️  Nmap scan failed: {e}")
            return []
    

    def display_network_devices(self):
        """Display network devices with proper pandas tables"""
        print("🖧  NETWORK DEVICES SCAN")
        print("=" * 80)
        
        devices = self.scan_with_nmap()
        
        if not devices:
            print("❌ No devices found or scanning failed.")
            print("Please install nmap for better results: sudo apt install nmap")
            return
        
        # Create DataFrame
        df = pd.DataFrame(devices)
        
        # DISPLAY THE ACTUAL PANDAS TABLE
        print(f"📱 Found {len(devices)} devices on network:\n")
        print(df.to_string(index=False))  # This shows the actual pandas table
        print("\n" + "=" * 80)
        
        # Summary
        print(f"\n📊 Summary:")
        print(f"   • Total devices found: {len(devices)}")
        print(f"   • Your local IP: {self.get_local_ip()}")
        print(f"   • Network range: {self.get_network_range()}")
    

    def get_current_connections(self) -> List[Dict]:
        """Get current network connections to the system"""
        try:
            result = subprocess.run(
                ['ss', '-tunap'],
                capture_output=True,
                text=True
            )
            
            connections = []
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        connections.append({
                            'Protocol': parts[0],
                            'Local Address': parts[4],
                            'Remote Address': parts[5],
                            'State': parts[1],
                            'Process': parts[-1] if 'users' in line else 'Unknown'
                        })
            return connections
            
        except Exception as e:
            print(f"⚠️  Could not get connections: {e}")
            return []
    

    def display_current_connections(self):
        """Display current connections with pandas table"""
        print("\n🔗 CURRENT NETWORK CONNECTIONS")
        print("=" * 80)
        
        connections = self.get_current_connections()
        
        if not connections:
            print("❌ No active connections found.")
            return
        
        df = pd.DataFrame(connections)
        
        # DISPLAY THE ACTUAL PANDAS TABLE
        print(f"🌐 Active connections: {len(connections)}\n")
        print(df.to_string(index=False))  # This shows the actual pandas table
        print("\n" + "=" * 80)
    

    def display_system_info(self):
        """Display system information with pandas table"""
        print("\n💻 SYSTEM NETWORK INFORMATION")
        print("=" * 80)
        
        info_data = []
        
        try:
            hostname = socket.gethostname()
            info_data.append({'Property': 'Hostname', 'Value': hostname})
            
            local_ip = self.get_local_ip()
            info_data.append({'Property': 'Local IP', 'Value': local_ip})
            
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
            interfaces = re.findall(r'\d+: (\w+):', result.stdout)
            info_data.append({'Property': 'Network Interfaces', 'Value': ', '.join(interfaces)})
            
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            default_route = [line for line in result.stdout.split('\n') if 'default' in line]
            if default_route:
                info_data.append({'Property': 'Default Gateway', 'Value': default_route[0]})
            
            df = pd.DataFrame(info_data)
            
            # DISPLAY THE ACTUAL PANDAS TABLE
            print("\nSystem Information:\n")
            print(df.to_string(index=False))  # This shows the actual pandas table
            print("\n" + "=" * 80)
            
        except Exception as e:
            print(f"❌ Could not get system info: {e}")


def main():
    parser = argparse.ArgumentParser(description='Network Users Scanner with Pandas Tables')
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
        scanner.display_system_info()
        scanner.display_network_devices()
        scanner.display_current_connections()


if __name__ == "__main__":
    main()