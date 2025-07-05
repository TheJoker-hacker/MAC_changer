# MAC Address Changer Tool

A simple Python tool to scan your local network and spoof (change) your MAC address to enhance privacy and anonymity on Wi-Fi networks.

## Features

- Automatically detects your active network interface  
- Scans your subnet for connected devices  
- Shows device manufacturer and type based on MAC address  
- Allows you to spoof your MAC address to any valid value  
- Option to revert to your original MAC address  
- Optional stealth mode to reduce scan visibility  
- Verbose mode for detailed output

## Requirements

- Python 3  
- Modules: `python-nmap`, `netifaces`, `mac-vendor-lookup`  
- Nmap installed on your system

### Install dependencies

```bash
pip install python-nmap netifaces mac-vendor-lookup
