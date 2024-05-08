#!/usr/local/bin/python3

"""
NarProxy: Network Address Resolution Proxy

This script acts as a proxy for network address resolution (ARP and IPv6 Neighbor Discovery)
and manages routes for WireGuard interfaces. It responds to ARP and ND requests for specified
IP addresses or networks, ensuring that traffic is routed correctly even when the actual
owner of the IP is not present on the network.

Usage: narproxy.py [-p PIDFILE] [-v] if_name mac_addr [-]addr/mask...

Examples:
  IPv4 IP:      script.py em0 00:11:22:33:44:55 192.168.1.100
  IPv4 subnet:  script.py em0 00:11:22:33:44:55 192.168.1.0/24
  IPv6 IP:      script.py em0 00:11:22:33:44:55 2001:db8::1
  IPv6 subnet:  script.py em0 00:11:22:33:44:55 2001:db8::/64
  Exclude IP:   script.py em0 00:11:22:33:44:55 192.168.1.0/24 -192.168.1.100
  Auto MAC:     script.py em0 auto 192.168.1.0/24
  Verbose:      script.py -v em0 00:11:22:33:44:55 192.168.1.0/24
  
  # WireGuard examples:
  All WG peers: script.py em0 00:11:22:33:44:55 wg
  WG interface: script.py em0 00:11:22:33:44:55 wg0

Options:
  -p, --pidfile PIDFILE: Specify a file to write the process ID (PID) to.
  -v, --verbose: Enable verbose logging (-v for INFO, -vv for DEBUG).

Arguments:
  interface: The network interface to use.
  mac: The MAC address to use for responding to ARP/ND requests (or "auto"
       to use the interface's MAC address).
  targets: A list of target IP addresses, networks, or "wg" (for all
           WireGuard peers) or "wg#" (for peers on a specific WireGuard interface).
  -addr/mask: (Optional) Exclude specific IP addresses or networks from the targets.

Requirements:
  - Python 3
  - scapy
  - ipaddress
"""

import socket
import sys
import os
import signal
import logging
import struct
import argparse
import time
import asyncio
import re
import subprocess
from ipaddress import IPv6Address, ip_network, ip_address
from functools import lru_cache
from typing import List, Tuple, Dict, Union, Optional, Callable

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.l2 import Ether, ARP, srp, sendp
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from scapy.sendrecv import AsyncSniffer
from scapy.arch import get_if_hwaddr
from scapy.interfaces import get_working_ifaces, get_if_list
from scapy.error import Scapy_Exception


class NarProxyError(Exception):
    """Custom exception class for NarProxy-related errors."""

    pass


logging.basicConfig(
    level=logging.CRITICAL, format="%(asctime)s - %(levelname)s - %(message)s"
)


ADDRESS_CHECK_TIMEOUT = 0.7
ADDRESS_CHECK_RETRY_COUNT = 1
CLEANUP_INTERVAL = 300
IP_USAGE_TIMEOUT = 1201
SUBNET_MAX_PRELOAD_SIZE = 65025
BROADCAST_MAC_IPV4 = "ff:ff:ff:ff:ff:ff"
BROADCAST_MAC_IPV6 = "33:33:00:00:00:01"
GARP_IP_ADDRESS = "0.0.0.0"
IPV6_SOLICITED_NODE_PREFIX = "ff02::1:ff00:0/104"
ICMPV6_ND_DAD_SOURCE_ADDR = "::"

MAC_ADDRESS_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
WIREGUARD_INTERFACE_PATTERN = re.compile(r"^wg(\d+)?$")

sent_packets_record: Dict[Tuple[str, str, str], float] = {}
ip_usage_timestamps: Dict[str, Dict[str, Union[float, bool, str]]] = {}
arp_replies_sent: Dict[str, float] = {}
na_replies_sent: Dict[str, float] = {}
last_replied_mac_per_ip: Dict[str, str] = {}
timestamps_lock = asyncio.Lock()
packet_queue: asyncio.Queue = asyncio.Queue()


class NarProxyUtils:
    """Utility functions for NarProxy."""

    @staticmethod
    def execute_command(command: List[str]) -> subprocess.CompletedProcess:
        """Executes a command and returns the result.

        Args:
            command: A list of strings representing the command and its arguments.

        Returns:
            subprocess.CompletedProcess: The result of the command execution.

        Raises:
            NarProxyError: If the command execution fails.
        """
        try:
            return subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as error:
            raise NarProxyError(
                f"Command execution failed: {error}",
                command,
                error.returncode,
                error.stderr,
            ) from error

    @staticmethod
    def is_valid_mac_address(mac_address: str) -> bool:
        """Validates a MAC address format.

        Args:
            mac_address: The MAC address to validate

        Returns:
            bool: True if the MAC address is valid, False otherwise.

        Raises:
            ValueError: If the MAC address format is invalid.
        """
        if mac_address.lower() == "auto":
            return True
        if not MAC_ADDRESS_REGEX.match(mac_address):
            raise ValueError(f"Invalid MAC address format: {mac_address}")
        return True

    @staticmethod
    async def cleanup_expired_ip_data(event_loop: asyncio.AbstractEventLoop) -> None:
        """Cleans up data for expired IP addresses periodically.

        Args:
            event_loop: The asyncio event loop.
        """
        while True:
            current_time = time.time()
            async with timestamps_lock:
                expired_ips = [
                    ip
                    for ip, data in ip_usage_timestamps.items()
                    if current_time - data["timestamp"] > IP_USAGE_TIMEOUT
                ]
                for ip in expired_ips:
                    ip_usage_timestamps.pop(ip, None)
                    arp_replies_sent.pop(ip, None)
                    na_replies_sent.pop(ip, None)
                    last_replied_mac_per_ip.pop(ip, None)

            if expired_ips:
                logging.info("Cleaned up data for expired IPs: %s", expired_ips)

            await asyncio.sleep(CLEANUP_INTERVAL)

    @staticmethod
    def parse_cidr(cidr_notation: str) -> Tuple[str, str]:
        """Parses a CIDR notation string into network and netmask.

        Args:
            cidr_notation: The CIDR notation string (e.g., "192.168.1.0/24").

        Returns:
            Tuple[str, str]: A tuple containing the network address and netmask.

        Raises:
            ValueError: If the CIDR notation is invalid.
        """
        try:
            network, net_bits_str = cidr_notation.split("/")
            net_bits = int(net_bits_str)
            if net_bits < 0 or net_bits > 32:
                raise ValueError("Invalid netmask bits")
            host_bits = 32 - net_bits
            netmask = socket.inet_ntoa(struct.pack("!I", (1 << 32) - (1 << host_bits)))
            return network, netmask
        except ValueError as error:
            raise ValueError("Invalid CIDR notation") from error

    @staticmethod
    def build_packet_filter(
        target_ips: List[str], excluded_ips: List[str], interface_mac_address: str
    ) -> str:
        """Builds a packet filter string based on targets and exclusions.

        Args:
            target_ips: A list of target IP addresses or networks.
            excluded_ips: A list of IP addresses or networks to exclude.
            interface_mac_address: The MAC address of the interface.

        Returns:
            str: The packet filter string.
        """
        target_filters = []
        exclude_filters = []

        for target in target_ips:
            if ":" in target:
                if target.endswith("/128"):
                    ipv6_addr_without_prefix = target.split("/")[0]
                    solicited_node_addr = IPv6Utils.generate_solicited_node_address(
                        ipv6_addr_without_prefix
                    )
                    target_filters.append(f"dst host {solicited_node_addr}")
                elif "/" in target:
                    target_filters.append(f"dst net {target}")
                else:
                    solicited_node_addr = IPv6Utils.generate_solicited_node_address(
                        target
                    )
                    target_filters.append(f"dst host {solicited_node_addr}")
            else:
                if "/" in target:
                    try:
                        network, netmask = NarProxyUtils.parse_cidr(target)
                        target_filters.append(f"dst net {network} mask {netmask}")
                    except ValueError:
                        print(f"Skipping invalid CIDR notation: {target}")
                else:
                    target_filters.append(f"dst host {target}")

        for exclude in excluded_ips:
            if ":" in exclude:
                if exclude.endswith("/128"):
                    ipv6_addr_without_prefix = exclude.split("/")[0]
                    solicited_node_addr = IPv6Utils.generate_solicited_node_address(
                        ipv6_addr_without_prefix
                    )
                    exclude_filters.append(f"dst host {solicited_node_addr}")
                elif "/" in exclude:
                    exclude_filters.append(f"dst net {exclude}")
                else:
                    solicited_node_addr = IPv6Utils.generate_solicited_node_address(
                        exclude
                    )
                    exclude_filters.append(f"dst host {solicited_node_addr}")
            else:
                if "/" in exclude:
                    try:
                        network, netmask = NarProxyUtils.parse_(exclude)
                        exclude_filters.append(f"dst net {network} mask {netmask}")
                    except ValueError:
                        print(f"Skipping invalid CIDR notation: {exclude}")
                else:
                    exclude_filters.append(f"dst host {exclude}")

        target_filter = " or ".join(target_filters)
        exclude_filter = (
            " and not (" + " or ".join(exclude_filters) + ")" if exclude_filters else ""
        )
        interface_mac_filter = f" and not (ether src {interface_mac_address})"

        return f"((arp or icmp6) and ({target_filter}){exclude_filter}{interface_mac_filter})"

    @staticmethod
    def print_usage_instructions() -> None:
        """Prints the usage information for the script."""
        print("Usage: narproxy.py [-p PIDFILE] [-v] if_name mac_addr [-]addr/mask...")
        print("Examples:")
        print("  IPv4 IP:\t script.py em0 00:11:22:33:44:55 192.168.1.100")
        print("  IPv4 subnet:\t script.py em0 00:11:22:33:44:55 192.168.1.0/24")
        print("  IPv6 IP:\t script.py em0 00:11:22:33:44:55 2001:db8::1")
        print("  IPv6 subnet:\t script.py em0 00:11:22:33:44:55 2001:db8::/64")
        print(
            "  Exclude IP:\t script.py em0 00:11:22:33:44:55 192.168.1.0/24 -192.168.1.100"
        )
        print("  Auto MAC:\t script.py em0 auto 192.168.1.0/24")
        print("  Verbose:\t script.py -v em0 00:11:22:33:44:55 192.168.1.0/24")


class RouteManager:
    """Manages routes for IP addresses."""

    @staticmethod
    def execute_route_command(
        action: str, ip_address: str, network_interface: str = None
    ) -> None:
        """Executes a route command (add or delete) for a given IP address.

        Args:
            action: The action to perform ("add" or "delete").
            ip_address: The IP address for which to manage the route.
            network_interface: (Optional) The interface to use when adding the route.
        """
        try:
            ip_version = ip_address(ip_address).version
        except ValueError as error:
            logging.error("Invalid IP address %s: %s", ip_address, error)
            raise NarProxyError(f"Invalid IP address: {ip_address}") from error

        command = ["/sbin/route", "-n", f"-{ip_version}", action, ip_address]
        if action == "add":
            command.extend(["-interface", network_interface])

        logging.debug("Executing command: %s", command)

        try:
            result = NarProxyUtils.execute_command(command)
            logging.debug(
                "Route successfully %sed for IP address %s", action, ip_address
            )
        except NarProxyError as error:
            logging.error(
                "Error %sing route for IP address %s: %s", action, ip_address, error
            )
            raise
        except Exception as error:
            stderr = str(error).strip()
            if "route already in table" in stderr or "not in table" in stderr:
                logging.debug(
                    "Route for IP address %s already handled. Message: %s",
                    ip_address,
                    stderr,
                )
            else:
                logging.error(
                    "Error %sing route for IP address %s: %s", action, ip_address, error
                )
                raise NarProxyError(
                    f"Failed to manage route for IP {ip_address}"
                ) from error

    @staticmethod
    def add_route(ip_address: str, network_interface: str) -> None:
        """Adds a route for the given IP address on the specified interface."""
        logging.debug("Attempting to add route for IP address: %s", ip_address)
        RouteManager.execute_route_command("add", ip_address, network_interface)

    @staticmethod
    def delete_route(ip_address: str) -> None:
        """Deletes the route for the given IP address."""
        logging.debug("Attempting to delete route for IP address: %s", ip_address)
        RouteManager.execute_route_command("delete", ip_address)


class WireGuardManager:
    """Manages interactions with WireGuard."""

    @staticmethod
    def get_target_ips(network_interface: str = "all") -> List[str]:
        """Retrieves allowed IP addresses from WireGuard configuration.

        Args:
            network_interface: (Optional) The WireGuard interface name (default is "all").

        Returns:
            List[str]: The list of allowed IP addresses.
        """
        logging.debug(
            "Retrieving targets from WireGuard output for interface: %s",
            network_interface,
        )
        command = ["wg", "show", network_interface, "allowed-ips"]

        try:
            result = NarProxyUtils.execute_command(command)
            target_ips = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    target_ips.extend(parts[2:])
            logging.info("Targets retrieved: %s", target_ips)
            return target_ips
        except Exception as error:
            logging.error("Error retrieving targets: %s", error)
            raise NarProxyError("Failed to retrieve WireGuard targets")

    @staticmethod
    @lru_cache(maxsize=128)
    def get_interface_for_ip(ip_address: str) -> Optional[str]:
        """Finds the WireGuard interface associated with a given IP address.

        Args:
            ip_address: The IP address to search for.

        Returns:
            Optional[str]: The name of the WireGuard interface if found, otherwise None.
        """
        logging.debug("Searching for interface for IP address: %s", ip_address)
        command = ["wg", "show", "all", "allowed-ips"]

        try:
            result = NarProxyUtils.execute_command(command)
            target_ip = ip_address(ip_address)
            logging.debug("Formatted target IP for comparison: %s", target_ip)
            for line in result.stdout.splitlines():
                parts = line.split()
                logging.debug("Processing line: %s", line)
                if len(parts) >= 3:
                    for network_str in parts[2:]:
                        try:
                            network = ip_network(network_str, strict=False)
                            logging.debug("Comparing against network: %s", network)
                            if target_ip in network:
                                logging.info(
                                    "Interface %s found for IP address %s",
                                    parts[0],
                                    ip_address,
                                )
                                return parts[0]
                        except ValueError:
                            pass
            logging.warning("No interface found for IP address %s", ip_address)
            return None
        except Exception as error:
            logging.error(
                "Error searching for interface for IP address %s: %s", ip_address, error
            )
            raise NarProxyError(f"Failed to find interface for IP {ip_address}")


class NetworkInterfaceManager:
    """Manages network interface operations."""

    @staticmethod
    def validate_interface(network_interface_name: str) -> None:
        """Validates if a network interface exists and is up.

        Args:
            network_interface_name: The name of the interface to validate.

        Raises:
            ValueError: If the interface does not exist or is not up.
        """
        if network_interface_name not in get_if_list():
            raise ValueError(f"Interface {network_interface_name} does not exist.")
        if network_interface_name not in [iface.name for iface in get_working_ifaces()]:
            raise ValueError(f"Interface {network_interface_name} is not up.")

    @staticmethod
    @lru_cache(maxsize=128)
    def get_mac_address(network_interface_name: str) -> str:
        """Retrieves the MAC address of a network interface.

        Args:
            network_interface_name: The name of the interface.

        Returns:
            str: The MAC address of the interface.

        Raises:
            NarProxyError: If the MAC address cannot be retrieved.
        """
        try:
            address = get_if_hwaddr(network_interface_name)
            return address
        except (KeyError, IndexError) as error:
            logging.error(
                "Could not retrieve MAC address for interface %s",
                network_interface_name,
            )
            raise NarProxyError(
                f"Failed to get MAC address for interface {network_interface_name}"
            ) from error


class IPv6Utils:
    """Utility functions for IPv6 operations."""

    @staticmethod
    @lru_cache(maxsize=128)
    def generate_solicited_node_address(ipv6_address: str) -> str:
        """Generates the solicited-node multicast address for an IPv6 address.

        Args:
            ipv6_address: The IPv6 address.

        Returns:
            str: The solicited-node multicast address.
        """
        logging.debug("Generating solicited node address for: %s", ipv6_address)
        ipv6_obj = IPv6Address(ipv6_address)
        last_24_bits = ipv6_obj.packed[-3:]
        solicited_node_prefix_obj = IPv6Address(
            IPV6_SOLICITED_NODE_PREFIX.split("/", maxsplit=1)[0]
        )
        solicited_node_address = solicited_node_prefix_obj + int.from_bytes(
            last_24_bits, byteorder="big"
        )
        return str(solicited_node_address)


class AddressChecker:
    """Performs checks on IP address usage."""

    @staticmethod
    async def check_ip_address_usage(
        network_interface_name: str,
        ip_address: str,
        target_mac_address: str,
        is_ipv6: bool,
        event_loop: asyncio.AbstractEventLoop,
    ) -> Tuple[str, bool, Optional[str]]:
        """Checks if an IP address is currently in use on the network.

        Args:
            network_interface_name: The network interface to use.
            ip_address: The IP address to check.
            target_mac_address: The MAC address of the target device.
            is_ipv6: Whether the IP address is IPv6.
            event_loop: The asyncio event loop.

        Returns:
            Tuple[str, bool, Optional[str]]: A tuple containing:
                - The IP address that was checked.
                - A boolean indicating whether the IP address is in use.
                - The MAC address of the device using the IP (if in use), or None.
        """
        logging.debug(
            "Checking IP address %s for usage on interface %s",
            ip_address,
            network_interface_name,
        )

        if is_ipv6:
            solicited_node = IPv6Utils.generate_solicited_node_address(ip_address)
            ns_probe = (
                Ether(dst=BROADCAST_MAC_IPV6)
                / IPv6(dst=solicited_node)
                / ICMPv6ND_NS(tgt=ip_address)
            )
        else:
            src_mac = NetworkInterfaceManager.get_mac_address(network_interface_name)
            if src_mac is None:
                logging.error(
                    "Failed to get MAC address for interface %s. Exiting.",
                    network_interface_name,
                )
                raise NarProxyError("Failed to get MAC address for interface")
            ether = Ether(src=src_mac, dst=BROADCAST_MAC_IPV4)
            arp_probe = ARP(hwsrc=src_mac, psrc=GARP_IP_ADDRESS, pdst=ip_address)
            ns_probe = ether / arp_probe

        try:
            ans, unans = await event_loop.run_in_executor(
                None,
                lambda: srp(
                    ns_probe,
                    iface=network_interface_name,
                    timeout=ADDRESS_CHECK_TIMEOUT,
                    verbose=False,
                    retry=ADDRESS_CHECK_RETRY_COUNT,
                ),
            )
            if ans:
                in_use = True
                in_use_mac = ans[0][1].hwsrc if not is_ipv6 else ans[0][1][Ether].src
                logging.debug(
                    "IP address %s is in use by MAC %s on the network.",
                    ip_address,
                    in_use_mac,
                )
            else:
                in_use = False
                in_use_mac = None
        except Exception as error:
            logging.error("Error checking IP address %s: %s", ip_address, error)
            raise NarProxyError(
                f"Failed to check IP address usage: {ip_address}"
            ) from error

        return ip_address, in_use, in_use_mac


class PacketSender:
    """Sends packets on the network."""

    @staticmethod
    async def send_packet(
        packet: Ether,
        network_interface_name: str,
        event_loop: asyncio.AbstractEventLoop,
    ) -> Optional[Tuple[str, str, str]]:
        """Sends a packet on the specified interface.

        Args:
            packet: The Scapy packet to send.
            network_interface_name: The network interface to use.
            event_loop: The asyncio event loop.

        Returns:
            Optional[Tuple[str, str, str]]: A tuple containing the source MAC,
                destination MAC, and destination IP of the sent packet, or None if
                the packet type is not ARP or IPv6.
        """
        logging.debug(
            "Attempting to send packet on interface %s", network_interface_name
        )
        try:
            await event_loop.run_in_executor(
                None, lambda: sendp(packet, iface=network_interface_name, verbose=False)
            )
            logging.debug("Packet sent successfully")

            packet_identifier = None
            if ARP in packet:
                packet_identifier = (
                    packet[Ether].src,
                    packet[Ether].dst,
                    packet[ARP].pdst,
                )
                logging.debug("Packet is ARP. Identifier: %s", packet_identifier)
            elif IPv6 in packet:
                packet_identifier = (
                    packet[Ether].src,
                    packet[Ether].dst,
                    packet[IPv6].dst,
                )
                logging.debug("Packet is IPv6. Identifier: %s", packet_identifier)
            return packet_identifier
        except Exception as error:
            logging.error("Error sending packet: %s", error)
            raise NarProxyError("Failed to send packet") from error


class PacketProcessor:
    """Processes incoming network packets and sends appropriate responses."""

    @staticmethod
    async def process_network_request(
        packet: Ether,
        target_mac_address: str,
        wireguard_enabled: bool,
        network_interface_name: str,
        event_loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Processes an ARP or IPv6 Neighbor Solicitation request and sends
        the appropriate ARP or Neighbor Advertisement reply.

        Args:
            packet: The received packet.
            target_mac_address: The MAC address of the target device.
            wireguard_enabled: Whether WireGuard is being used.
            network_interface_name: The network interface to use.
            event_loop: The asyncio event loop.
        """
        try:
            logging.debug("Starting to process packet: %s", packet.summary())
            current_time = time.time()
            if ARP in packet and packet[ARP].op == 1:
                target_ip = packet[ARP].pdst
                is_ipv6 = False
            elif IPv6 in packet and ICMPv6ND_NS in packet:
                target_ip = packet[ICMPv6ND_NS].tgt
                is_ipv6 = True
            else:
                return

            source_mac = NetworkInterfaceManager.get_mac_address(network_interface_name)
            if source_mac is None:
                logging.error(
                    "Failed to get MAC address for interface %s. Skipping response.",
                    network_interface_name,
                )
                return

            ip_addr, in_use, in_use_mac = await AddressChecker.check_ip_address_usage(
                network_interface_name,
                target_ip,
                target_mac_address,
                is_ipv6,
                event_loop,
            )

            last_known_mac = last_replied_mac_per_ip.get(target_ip, None)

            should_broadcast = False
            if in_use and in_use_mac != last_known_mac:
                should_broadcast = True
            elif not in_use and last_known_mac != source_mac:
                should_broadcast = True
            if should_broadcast:
                if in_use:
                    broadcast_mac_address = in_use_mac
                    if last_known_mac == source_mac:
                        logging.info(
                            "Relinquishing responsibility of %s to MAC %s",
                            target_ip,
                            in_use_mac,
                        )
                else:
                    broadcast_mac_address = source_mac
                    logging.info(
                        "Assuming responsibility for %s with MAC %s",
                        target_ip,
                        source_mac,
                    )

                last_replied_mac_per_ip[target_ip] = broadcast_mac_address

                if wireguard_enabled:
                    if broadcast_mac_address == target_mac_address:
                        RouteManager.add_route(
                            target_ip, WireGuardManager.get_interface_for_ip(target_ip)
                        )
                    else:
                        RouteManager.delete_route(target_ip)

                broadcast_mac = (
                    BROADCAST_MAC_IPV4 if not is_ipv6 else BROADCAST_MAC_IPV6
                )
                arp_reply = None
                if is_ipv6:
                    na_reply = (
                        Ether(dst=broadcast_mac, src=source_mac)
                        / IPv6(dst="ff02::1")
                        / ICMPv6ND_NA(tgt=target_ip, R=0, S=1, O=1)
                        / ICMPv6NDOptDstLLAddr(lladdr=broadcast_mac_address)
                    )
                else:
                    arp_reply = Ether(dst=broadcast_mac, src=source_mac) / ARP(
                        op=2,
                        hwsrc=broadcast_mac_address,
                        psrc=target_ip,
                        hwdst=broadcast_mac,
                        pdst="255.255.255.255",
                    )
                await PacketSender.send_packet(
                    na_reply if is_ipv6 else arp_reply,
                    network_interface_name,
                    event_loop,
                )
                logging.info(
                    "Broadcasted %s update for %s with MAC %s",
                    "NA" if is_ipv6 else "ARP",
                    target_ip,
                    broadcast_mac_address,
                )

            if not in_use or in_use_mac == target_mac_address:
                if is_ipv6:
                    na_reply = (
                        Ether(dst=packet[Ether].src, src=source_mac)
                        / IPv6(dst=packet[IPv6].src)
                        / ICMPv6ND_NA(tgt=target_ip, R=0, S=1, O=1)
                        / ICMPv6NDOptDstLLAddr(lladdr=source_mac)
                    )
                    packet_identifier = await PacketSender.send_packet(
                        na_reply, network_interface_name, event_loop
                    )
                    logging.info(
                        "Sent NA reply for %s to %s", target_ip, packet[Ether].src
                    )
                else:
                    arp_reply = Ether(dst=packet[ARP].hwsrc, src=source_mac) / ARP(
                        op=2,
                        hwsrc=source_mac,
                        psrc=target_ip,
                        hwdst=packet[ARP].hwsrc,
                        pdst=target_ip,
                    )
                    packet_identifier = await PacketSender.send_packet(
                        arp_reply, network_interface_name, event_loop
                    )
                    logging.info(
                        "Sent ARP reply for %s to %s", target_ip, packet[ARP].hwsrc
                    )

                if packet_identifier:
                    async with timestamps_lock:
                        sent_packets_record[packet_identifier] = time.time()
                        logging.debug(
                            "Recorded timestamp for packet identifier: %s",
                            packet_identifier,
                        )

                async with timestamps_lock:
                    ip_usage_timestamps[target_ip] = {
                        "timestamp": current_time,
                        "in_use": True,
                        "mac": target_mac_address,
                    }
                    logging.debug(
                        "Updated ip_usage_timestamps for %s with target MAC %s",
                        target_ip,
                        target_mac_address,
                    )
            logging.debug("Packet processing completed for: %s", packet.summary())
        except Exception as error:
            logging.error("Error processing packet %s: %s", packet.summary(), error)

    @staticmethod
    async def process_packets_from_queue(
        network_interface_name: str,
        target_mac_address: str,
        wireguard_targets_specified: bool,
        event_loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Continuously processes packets from the packet queue."""
        logging.debug("Packet processing task started.")
        while True:
            try:
                logging.debug("Waiting to get packet from queue...")
                packet = await packet_queue.get()
                logging.debug("Dequeuing packet for processing: %s", packet.summary())
                try:
                    await PacketProcessor.process_network_request(
                        packet,
                        target_mac_address,
                        wireguard_targets_specified,
                        network_interface_name,
                        event_loop,
                    )
                except Exception as error:
                    logging.error(
                        "Error processing packet %s: %s", packet.summary(), error
                    )
                finally:
                    packet_queue.task_done()
                    logging.debug("Packet processing task marked as done.")
            except asyncio.CancelledError:
                logging.info("Packet processing task was cancelled.")
                break
            except Exception as error:
                logging.error("Unexpected error during packet processing: %s", error)
                continue


class PacketSniffer:
    """Captures network packets."""

    @staticmethod
    async def run_sniffer(
        network_interface_name: str,
        packet_handler: Callable[[Ether, asyncio.AbstractEventLoop], None],
        filter_string: str,
    ) -> None:
        """Starts a packet sniffer on the specified interface with a filter.

        Args:
            network_interface_name: The network interface to sniff on.
            packet_handler: The callback function to handle captured packets.
            filter_string: The BPF filter string to apply to captured packets.
        """
        sniffer = AsyncSniffer(
            iface=network_interface_name,
            prn=packet_handler,
            store=False,
            filter=filter_string,
        )
        sniffer.start()
        logging.info("Packet sniffing started.")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            logging.info("Sniffer task was cancelled.")
        finally:
            sniffer.stop()
            logging.info("Packet sniffing stopped.")

    @staticmethod
    def packet_callback(packet: Ether, event_loop: asyncio.AbstractEventLoop) -> None:
        """Callback function to handle captured packets and enqueue them for processing."""
        try:
            logging.debug("Packet received: %s", packet.summary())
            if (
                packet.haslayer(ICMPv6ND_NS)
                and packet[IPv6].src == ICMPV6_ND_DAD_SOURCE_ADDR
            ):
                logging.debug("IPv6 ND DAD Request detected.")
                eth_layer = packet.getlayer(Ether)
                icmpv6ns_layer = packet.getlayer(ICMPv6ND_NS)
                sender_mac = eth_layer.src
                target_ip = icmpv6ns_layer.tgt
                logging.info(
                    "ICMPv6 ND DAD Request: Sender MAC - %s, Target IP - %s",
                    sender_mac,
                    target_ip,
                )
                asyncio.run_coroutine_threadsafe(packet_queue.put(packet), event_loop)
            else:
                asyncio.run_coroutine_threadsafe(packet_queue.put(packet), event_loop)
            logging.debug("Packet enqueued for processing.")
        except asyncio.QueueFull:
            logging.warning("Packet queue is full. Dropping packet.")
        except Exception as error:
            logging.error("Error processing packet: %s", error)


class TargetProcessor:
    """Processes target specifications from command-line arguments."""

    @staticmethod
    def process_targets(target_arguments: List[str]) -> Tuple[List[str], bool]:
        """Processes target specifications, including WireGuard integration.

        Args:
            target_arguments: A list of target arguments from the command line.

        Returns:
            Tuple[List[str], bool]: A tuple containing:
                - A list of processed target IP addresses or networks.
                - A boolean indicating whether WireGuard targets were specified.
        """
        target_ips = []
        wg_specified = False
        wireguard_enabled = False
        logging.debug("Processing target arguments: %s", target_arguments)

        for arg in target_arguments:
            if WIREGUARD_INTERFACE_PATTERN.match(arg):
                wireguard_enabled = True
                if arg == "wg":
                    if wg_specified:
                        logging.error("The 'wg' target may only be specified once.")
                        raise ValueError("The 'wg' target may only be specified once.")
                    wg_specified = True
                    logging.info("Adding targets from all WireGuard interfaces.")
                    target_ips.extend(WireGuardManager.get_target_ips())
                else:
                    logging.info("Adding targets from WireGuard interface: %s", arg)
                    target_ips.extend(WireGuardManager.get_target_ips(arg))
            else:
                logging.info("Adding non-WireGuard target: %s", arg)
                target_ips.append(arg)

        logging.debug("Final list of processed targets: %s", target_ips)
        return target_ips, wireguard_enabled


async def preload_ip_check(
    network_interface_name: str,
    target_ips: List[str],
    target_mac_address: str,
    event_loop: asyncio.AbstractEventLoop,
) -> None:
    """Performs an initial check of IP address usage for preloading and route management."""
    semaphore = asyncio.Semaphore(20)
    specified_ips = set()
    tasks = []

    async def semaphore_wrapped_task(
        task: asyncio.Task,
    ) -> Tuple[str, bool, Optional[str]]:
        async with semaphore:
            return await task

    for target in target_ips:
        if "/" in target:
            try:
                network = ip_network(target, strict=False)
                num_hosts = (
                    network.num_addresses - 2
                    if network.version == 4
                    else network.num_addresses
                )

                if num_hosts > SUBNET_MAX_PRELOAD_SIZE:
                    logging.info(
                        "Skipping subnet %s with %d possible IPs (exceeds threshold).",
                        target,
                        num_hosts,
                    )
                    continue

                for ip in network.hosts():
                    specified_ips.add(str(ip))
                    tasks.append(
                        semaphore_wrapped_task(
                            AddressChecker.check_ip_address_usage(
                                network_interface_name,
                                str(ip),
                                target_mac_address,
                                is_ipv6=(ip.version == 6),
                                event_loop=event_loop,
                            )
                        )
                    )
            except ValueError as error:
                logging.error("Error processing subnet %s: %s", target, error)
        else:
            specified_ips.add(target)
            is_ipv6 = ":" in target
            tasks.append(
                semaphore_wrapped_task(
                    AddressChecker.check_ip_address_usage(
                        network_interface_name,
                        target,
                        target_mac_address,
                        is_ipv6=is_ipv6,
                        event_loop=event_loop,
                    )
                )
            )

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            logging.error("Task error: %s", result)
        else:
            ip_addr, in_use, in_use_mac = result
            logging.info(
                "IP %s in use status: %s, MAC: %s",
                ip_addr,
                in_use,
                in_use_mac if in_use else "N/A",
            )

            async with timestamps_lock:
                ip_usage_timestamps[ip_addr] = {
                    "timestamp": time.time(),
                    "in_use": in_use,
                    "mac": in_use_mac,
                }
                if in_use:
                    last_replied_mac_per_ip[ip_addr] = in_use_mac

    async with timestamps_lock:
        for ip, data in ip_usage_timestamps.items():
            if ip not in specified_ips:
                continue

            if data["in_use"]:
                try:
                    RouteManager.delete_route(ip)
                    logging.info("Route deleted for IP %s as it's in use.", ip)
                except Exception as error:
                    logging.error("Error deleting route for %s: %s", ip, error)
            else:
                try:
                    RouteManager.add_route(
                        ip, WireGuardManager.get_interface_for_ip(ip)
                    )
                    logging.info("Route added for IP %s as it's not in use.", ip)
                except Exception as error:
                    logging.error("Error adding route for %s: %s", ip, error)

                for ip in list(ip_usage_timestamps.keys()):
                    if ip not in specified_ips or not ip_usage_timestamps[ip].get(
                        "in_use", False
                    ):
                        ip_usage_timestamps.pop(ip, None)
                        arp_replies_sent.pop(ip, None)
                        na_replies_sent.pop(ip, None)
                        last_replied_mac_per_ip.pop(ip, None)


async def main(
    network_interface_name: str,
    target_mac_address: str,
    target_ips: List[str],
    wireguard_targets_specified: bool,
    excluded_ips: List[str],
    event_loop: asyncio.AbstractEventLoop,
) -> None:
    """The main asynchronous function that sets up and runs the NarProxy."""
    for signal_name in ("SIGINT", "SIGTERM"):
        event_loop.add_signal_handler(
            getattr(signal, signal_name),
            lambda: asyncio.create_task(shutdown(event_loop)),
        )
    await preload_ip_check(
        network_interface_name, target_ips, target_mac_address, event_loop
    )

    interface_mac = NetworkInterfaceManager.get_mac_address(network_interface_name)
    filter_str = NarProxyUtils.build_packet_filter(
        target_ips, excluded_ips, interface_mac
    )
    logging.debug("Packet filter string: %s", filter_str)
    logging.info("Starting packet sniffing...")

    sniffer_task = asyncio.create_task(
        PacketSniffer.run_sniffer(
            network_interface_name,
            lambda pkt: PacketSniffer.packet_callback(pkt, event_loop),
            filter_str,
        )
    )

    packet_processor_task = asyncio.create_task(
        PacketProcessor.process_packets_from_queue(
            network_interface_name,
            target_mac_address,
            wireguard_targets_specified,
            event_loop,
        )
    )
    logging.debug("Packet processor task created.")

    cleanup_task = asyncio.create_task(
        NarProxyUtils.cleanup_expired_ip_data(event_loop)
    )
    logging.debug("Cleanup task created.")

    try:
        await asyncio.gather(sniffer_task, packet_processor_task, cleanup_task)
    except asyncio.CancelledError:
        logging.info("Tasks were cancelled. Proceeding to shutdown.")
    finally:
        sniffer_task.cancel()
        packet_processor_task.cancel()
        cleanup_task.cancel()
        logging.info("Cleanup and shutdown logic...")


async def shutdown(event_loop: asyncio.AbstractEventLoop) -> None:
    """Handles the shutdown process, cancelling tasks and stopping the event loop."""
    logging.info("Shutdown initiated.")
    tasks = [
        t
        for t in asyncio.all_tasks(event_loop)
        if t is not asyncio.current_task(event_loop)
    ]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    event_loop.stop()
    logging.info("Shutdown complete.")


if __name__ == "__main__":
    """Parses command-line arguments, sets up logging, and starts the main event loop."""
    parser = argparse.ArgumentParser(description="Script Description")
    parser.add_argument("-p", "--pidfile", help="PID file")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Enable verbose logging (-v for INFO, -vv for DEBUG)",
    )
    parser.add_argument("interface", help="Interface to use")
    parser.add_argument(
        "mac", help='MAC address to use (or "auto" to use the interface MAC)'
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help=(
            "Target IP addresses, networks, wg (for all wg peers), or wg# for wg peers from a specific interface"
        ),
    )
    if len(sys.argv) < 4:
        NarProxyUtils.print_usage_instructions()
        sys.exit(1)
    args = parser.parse_args()

    if args.verbose == 1:
        logging.getLogger().setLevel(logging.INFO)
    elif args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)

    network_interface = args.interface
    try:
        NetworkInterfaceManager.validate_interface(network_interface)
    except ValueError as validation_error:
        logging.error("Error validating interface: %s", validation_error)
        sys.exit(1)

    mac_address = (
        NetworkInterfaceManager.get_mac_address(network_interface)
        if args.mac.lower() == "auto"
        else args.mac
    )
    try:
        NarProxyUtils.is_valid_mac_address(mac_address)
    except ValueError as validation_error:
        logging.error("Error validating MAC address: %s", validation_error)
        sys.exit(1)

    try:
        included_targets, wg_targets_specified = TargetProcessor.process_targets(
            args.targets
        )
    except ValueError as processing_error:
        logging.error("Error processing targets: %s", processing_error)
        sys.exit(1)

    excluded_targets = [target[1:] for target in args.targets if target.startswith("-")]

    logging.debug(
        "Command-line arguments: interface=%s, mac=%s, targets=%s, excludes=%s",
        network_interface,
        args.mac,
        included_targets,
        excluded_targets,
    )

    if args.pidfile:
        with open(args.pidfile, "w", encoding="ascii") as pid_file:
            pid_file.write(str(os.getpid()))

    event_loop = asyncio.get_event_loop()
    for signal_value in [signal.SIGINT, signal.SIGTERM]:
        event_loop.add_signal_handler(
            signal_value, lambda: asyncio.create_task(shutdown(event_loop))
        )

    event_loop.run_until_complete(
        main(
            network_interface,
            mac_address,
            included_targets,
            wg_targets_specified,
            excluded_targets,
            event_loop,
        )
    )
