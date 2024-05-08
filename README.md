# narproxy - Network Address Response Proxy

narproxy is a Python script that acts as a proxy for responding to network address resolution requests (ARP and NDP) on behalf of specified target IP addresses or networks. It is designed for and tested on OPNsense, pfSense, and FreeBSD 13.x systems. It can be used to simulate the presence of devices on a network or to handle address resolution for virtual or containerized environments.  **Specifically, narproxy can be helpful for clients transitioning between LAN and VPN connections on FreeBSD-based routers.**

## Features

*   Responds to ARP and NDP requests for specified target IP addresses or subnets
*   Supports both IPv4 and IPv6 address resolution
*   Can automatically retrieve target IP addresses from WireGuard interfaces
*   Allows excluding specific IP addresses or networks from being proxied
*   Performs periodic cleanup of expired IP address data
*   Supports verbose logging for debugging purposes
*   Designed for OPNsense, pfSense, and FreeBSD 13.x systems

## Requirements

*   Python 3.x
*   Scapy library
*   asyncio library
*   ipaddress library
*   OPNsense, pfSense, or FreeBSD 13.x operating system

## Installation

1.  Clone the repository or download the `narproxy.py` script.
2.  Install the required dependencies:

```bash
pip install scapy asyncio ipaddress 
```
3.  **On FreeBSD-based systems, ensure correct paths for commands like `wg` and `route`. You may need to modify the script accordingly.** 
4.  **Grant the script root privileges to interact with network interfaces and routing.**

## Usage

`python narproxy.py [-p PIDFILE] [-v] if_name mac_addr [-]addr/mask...`

*   `-p PIDFILE`: Specify a PID file to store the process ID.
*   `-v`: Enable verbose logging (-v for INFO, -vv for DEBUG).
*   `if_name`: The network interface to use for listening and responding to requests.
*   `mac_addr`: The MAC address to use for responses (or "auto" to use the interface MAC).
*   `[-]addr/mask...`: One or more target IP addresses, networks, or special targets:
    *   `wg`: All IP addresses from all WireGuard interfaces.
    *   `wg#`: IP addresses from a specific WireGuard interface (e.g., `wg0`).
    *   Prefix an address/network with `-` to exclude it from being proxied.

### Examples 

*   Proxy a single IPv4 address: 

```bash
python narproxy.py em0 00:11:22:33:44:55 192.168.1.100
```

*   Proxy an IPv4 subnet:

```bash
python narproxy.py em0 00:11:22:33:44:55 192.168.1.0/24
```

*   Proxy a single IPv6 address:

```bash
python narproxy.py em0 00:11:22:33:44:55 2001:db8::1 
```

*   Proxy an IPv6 subnet:

```bash
python narproxy.py em0 00:11:22:33:44:55 2001:db8::/64 
```

*   Exclude an IP address from being proxied:

```bash
python narproxy.py em0 00:11:22:33:44:55 192.168.1.0/24 -192.168.1.100 
```

*   Use the interface MAC address automatically:

```python
python narproxy.py em0 auto 192.168.1.0/24
```

*   Enable verbose logging:

```bash
python narproxy.py -v em0 00:11:22:33:44:55 192.168.1.0/24
```

## Compatibility

narproxy is designed for the following systems:

*   OPNsense 2.4.1 
*   pfSense 2.7.2
*   FreeBSD 13.x

While it may work on other Unix-like systems, compatibility is not guaranteed.

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing 

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the GitHub repository.

## Acknowledgements

*   The narproxy script utilizes the Scapy library for packet manipulation and sending/receiving.
*   The asyncio library is used for asynchronous processing and concurrency.
*   The ipaddress library is used for IP address and network manipulation.
