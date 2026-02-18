# Nice Network Scanner
Network Users Scanner with Pandas Output. Displays connected devices and network information in a nice table format.

<img width="654" height="810" alt="image" src="https://github.com/user-attachments/assets/7724cad3-5fd4-4ae4-9a17-83fe5620e1cb" />

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



***

## 📌 Quantitative Researcher | Algorithmic Trader | Trading Systems Architect

Quantitative researcher and trading systems engineer with end-to-end ownership of systematic strategies — from research and statistical validation to low-latency execution and production deployment.

Core focus areas:
- Systematic strategy design and validation
- Market microstructure analysis (order book dynamics, liquidity, spread behavior)
- Backtesting framework development (tick-level and historical data)
- Execution engine architecture and order lifecycle management
- Real-time market data processing
- Risk-aware system design
- Production-grade trading infrastructure (24/7 environments)

Experience across crypto (CEX, DEX), FX, and exchange-traded markets.

## Technical Stack

- Languages: Python, C++, MQL5
- Execution & Connectivity: REST, WebSocket, FIX
- Infrastructure: Linux, Docker, Redis, PostgreSQL
- Analytics: NumPy, Pandas, custom backtesting frameworks

## Contact

Email: ryu8777@gmail.com

***
