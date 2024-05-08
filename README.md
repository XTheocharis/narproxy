# narproxy - Network Address Response Proxy

`narproxy` is a Python script for OPNsense, pfSense, and FreeBSD 13.x systems. It handles network address resolution requests (ARP and NDP) for specified IP addresses or networks, simulating device presence on a network or managing address resolution for virtual/containerized environments.

## Features

*   Handles ARP and NDP requests for specified IP addresses or subnets
*   Supports IPv4 and IPv6 address resolution
*   Retrieves target IP addresses from WireGuard interfaces automatically
*   Excludes specific IP addresses or networks from proxying
*   Provides verbose logging for debugging

## Requirements

*   Python 3.x
*   Scapy, asyncio, ipaddress libraries
*   OPNsense 2.4.x, pfSense 2.7.x, or FreeBSD 13.x OS

## Installation

1.  Clone the repository or download `narproxy.py`.
2.  Install dependencies with `pip install scapy asyncio ipaddress`.
3.  Verify correct paths for `wg` and `route` commands on FreeBSD-based systems. Modify the script if necessary.
4.  Grant root privileges to the script for network interface and routing interaction.

## Usage

`python narproxy.py [-p PIDFILE] [-v] if_name mac_addr [-]addr/mask...`

*   `-p PIDFILE`: Stores the process ID in a PID file.
*   `-v`: Enables verbose logging (-v for INFO, -vv for DEBUG).
*   `if_name`: Specifies the network interface for listening and responding.
*   `mac_addr`: Sets the MAC address for responses (or "auto" for the interface MAC).
*   `[-]addr/mask...`: Specifies one or more target IP addresses, networks, or special targets:
    *   `wg`: All IP addresses from all WireGuard interfaces.
    *   `wg#`: IP addresses from a specific WireGuard interface (e.g., `wg0`).
    *   Prefix an address/network with `-` to exclude it from proxying.

## Compatibility

`narproxy` is known to be compatible with:

*   OPNsense 2.4.x
*   pfSense 2.7.x
*   FreeBSD 13.x

Compatibility with other systems or versions is not tested.

## License

This project is under the [MIT License](LICENSE).

## Contributing 

Contributions are welcome! Please open an issue or submit a pull request on the GitHub repository for any issues or improvement suggestions.

## Acknowledgements

*   `narproxy` uses the Scapy library for packet manipulation and sending/receiving.
*   The asyncio library enables asynchronous processing and concurrency.
*   The ipaddress library manages IP address and network manipulation.
