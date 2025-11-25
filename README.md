# Nice Network Scanner
Network Users Scanner with Pandas Output. Displays connected devices and network information in a nice table format.

# Installation and Usage

## Install required packages:
```
sudo apt update
sudo apt install nmap iproute2
pip install pandas
```

## Run the script:
```
python3 network_scanner.py
```

### Scan only network devices:
```
python3 network_scanner.py --devices
```

### Show only current connections:
```
python3 network_scanner.py --connections
```

### Show only system information:
```
python3 network_scanner.py --info
```

## Features
    ✅ Beautiful pandas tables with styling

    ✅ Network device discovery using nmap

    ✅ Current connection monitoring

    ✅ System network information

    ✅ Colorful formatted output

    ✅ Multiple scan options

    ✅ Fallback methods if nmap is not available



## Sample Output

The script will display organized tables showing:

    - All devices on your network with IP, hostname, MAC, and vendor

    - Current network connections to your system

    - System network configuration

The pandas output provides a clean, professional-looking table that's much easier to read than raw command output!
