#!/usr/local/bin/python3

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

logging.basicConfig(
    level=logging.CRITICAL, format="%(asctime)s - %(levelname)s - %(message)s"
)

ADR_CHECK_TIMEOUT = 0.7
ADR_CHECK_RETRY_COUNT = 1
CLEANUP_INTERVAL = 300
IP_USAGE_TIMEOUT = 1201
SUBNET_MAX_PRELOAD_SIZE = 65025
BROADCAST_MAC_IPV4 = "ff:ff:ff:ff:ff:ff"
BROADCAST_MAC_IPV6 = "33:33:00:00:00:01"
GARP_IP_ADDRESS = "0.0.0.0"
IPV6_SOLICITED_NODE_PREFIX = "ff02::1:ff00:0/104"
ICMPV6_ND_DAD_SOURCE_ADDR = "::"

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
WG_PATTERN = re.compile(r"^wg(\d+)?$")

sent_packets_record: Dict[Tuple[str, str, str], float] = {}
ip_usage_timestamps: Dict[str, Dict[str, float]] = {}
arp_replies_sent: Dict[str, float] = {}
na_replies_sent: Dict[str, float] = {}
last_replied_mac_per_ip: Dict[str, str] = {}
timestamps_lock = asyncio.Lock()
packet_queue: asyncio.Queue = asyncio.Queue()


class Utils:
    @staticmethod
    def run_command(command: List[str]) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise Exception(
                f"Command execution failed: {e}",
                command,
                e.returncode,
                e.stderr,
            ) from e

    @staticmethod
    def validate_mac_address(address: str) -> bool:
        if address.lower() == "auto":
            return True
        if not MAC_REGEX.match(address):
            raise ValueError(f"Invalid MAC address format: {address}")
        return True

    @staticmethod
    async def cleanup_expired_ips(loop: asyncio.AbstractEventLoop) -> None:
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
    def parse_cidr(cidr: str) -> Tuple[str, str]:
        try:
            network, net_bits_str = cidr.split("/")
            net_bits = int(net_bits_str)
            if net_bits < 0 or net_bits > 32:
                raise ValueError("Invalid netmask bits")
            host_bits = 32 - net_bits
            netmask = socket.inet_ntoa(struct.pack("!I", (1 << 32) - (1 << host_bits)))
            return network, netmask
        except ValueError as e:
            raise ValueError("Invalid CIDR notation") from e

    @staticmethod
    def build_packet_filter(
        targets: List[str], excl: List[str], interface_mac: str
    ) -> str:
        target_filters = []
        exclude_filters = []

        for target in targets:
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
                        network, netmask = Utils.parse_cidr(target)
                        target_filters.append(f"dst net {network} mask {netmask}")
                    except ValueError:
                        print(f"Skipping invalid CIDR notation: {target}")
                else:
                    target_filters.append(f"dst host {target}")

        for exclude in excl:
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
                        network, netmask = Utils.parse_cidr(exclude)
                        exclude_filters.append(f"dst net {network} mask {netmask}")
                    except ValueError:
                        print(f"Skipping invalid CIDR notation: {exclude}")
                else:
                    exclude_filters.append(f"dst host {exclude}")

        target_filter = " or ".join(target_filters)
        exclude_filter = (
            " and not (" + " or ".join(exclude_filters) + ")" if exclude_filters else ""
        )
        interface_mac_filter = f" and not (ether src {interface_mac})"

        return f"((arp or icmp6) and ({target_filter}){exclude_filter}{interface_mac_filter})"

    @staticmethod
    def print_usage() -> None:
        print("Usage: narproxy.py [-p PIDFILE] [-v] if_name mac_addr [-]addr/mask...")
        print("Examples:")
        print("  IPv4 IP:\t script.py eth0 00:11:22:33:44:55 192.168.1.100")
        print("  IPv4 subnet:\t script.py eth0 00:11:22:33:44:55 192.168.1.0/24")
        print("  IPv6 IP:\t script.py eth0 00:11:22:33:44:55 2001:db8::1")
        print("  IPv6 subnet:\t script.py eth0 00:11:22:33:44:55 2001:db8::/64")
        print(
            "  Exclude IP:\t script.py eth0 00:11:22:33:44:55 192.168.1.0/24 -192.168.1.100"
        )
        print("  Auto MAC:\t script.py eth0 auto 192.168.1.0/24")
        print("  Verbose:\t script.py -v eth0 00:11:22:33:44:55 192.168.1.0/24")


class RouteManager:
    @staticmethod
    def _execute_route_command(
        action: str, ip_addr: str, interface: str = None
    ) -> None:
        try:
            ip_version = ip_address(ip_addr).version
        except ValueError as e:
            logging.error("Invalid IP address %s: %s", ip_addr, e)
            raise

        command = ["/sbin/route", "-n", f"-{ip_version}", action, ip_addr]
        if action == "add":
            command.extend(["-interface", interface])

        logging.debug("Executing command: %s", command)

        try:
            result = Utils.run_command(command)
            logging.debug("Route successfully %sed for IP address %s", action, ip_addr)
        except Exception as e:
            stderr = str(e).strip()
            if "route already in table" in stderr or "not in table" in stderr:
                logging.debug(
                    "Route for IP address %s already handled. Message: %s",
                    ip_addr,
                    stderr,
                )
            else:
                logging.error(
                    "Error %sing route for IP address %s: %s", action, ip_addr, e
                )
                raise

    @staticmethod
    def add_route(ip_addr: str, interface: str) -> None:
        logging.debug("Attempting to add route for IP address: %s", ip_addr)
        RouteManager._execute_route_command("add", ip_addr, interface)

    @staticmethod
    def delete_route(ip_addr: str) -> None:
        logging.debug("Attempting to delete route for IP address: %s", ip_addr)
        RouteManager._execute_route_command("delete", ip_addr)


class WireGuardManager:
    @staticmethod
    def get_targets(interface: str = "all") -> List[str]:
        logging.debug(
            "Retrieving targets from WireGuard output for interface: %s", interface
        )
        command = ["wg", "show", interface, "allowed-ips"]

        try:
            result = Utils.run_command(command)
            targets = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    targets.extend(parts[2:])
            logging.info("Targets retrieved: %s", targets)
            return targets
        except Exception as e:
            logging.error("Error retrieving targets: %s", e)
            raise

    @staticmethod
    @lru_cache(maxsize=128)
    def get_interface_for_ip(ip_addr: str) -> Optional[str]:
        logging.debug("Searching for interface for IP address: %s", ip_addr)
        command = ["wg", "show", "all", "allowed-ips"]

        try:
            result = Utils.run_command(command)
            target_ip = ip_address(ip_addr)
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
                                    ip_addr,
                                )
                                return parts[0]
                        except ValueError:
                            pass
            logging.warning("No interface found for IP address %s", ip_addr)
            return None
        except Exception as e:
            logging.error(
                "Error searching for interface for IP address %s: %s", ip_addr, e
            )
            raise


class InterfaceManager:
    @staticmethod
    def validate_interface(interface: str) -> None:
        if interface not in get_if_list():
            raise ValueError(f"Interface {interface} does not exist.")
        if interface not in [iface.name for iface in get_working_ifaces()]:
            raise ValueError(f"Interface {interface} is not up.")

    @staticmethod
    @lru_cache(maxsize=128)
    def get_mac_address(interface: str) -> str:
        try:
            address = get_if_hwaddr(interface)
            return address
        except (KeyError, IndexError):
            logging.error("Could not retrieve MAC address for interface %s", interface)
            sys.exit(1)


class IPv6Utils:
    @staticmethod
    @lru_cache(maxsize=128)
    def generate_solicited_node_address(ipv6_addr: str) -> str:
        logging.debug("Generating solicited node address for: %s", ipv6_addr)
        ipv6_obj = IPv6Address(ipv6_addr)
        last_24_bits = ipv6_obj.packed[-3:]
        solicited_node_prefix_obj = IPv6Address(
            IPV6_SOLICITED_NODE_PREFIX.split("/")[0]
        )
        solicited_node_address = solicited_node_prefix_obj + int.from_bytes(
            last_24_bits, byteorder="big"
        )
        return str(solicited_node_address)


class AddressChecker:
    @staticmethod
    async def check_ip_address_usage(
        interface: str,
        ip_addr: str,
        target_mac: str,
        is_ipv6: bool,
        loop: asyncio.AbstractEventLoop,
    ) -> Tuple[str, bool, Optional[str]]:
        logging.debug(
            "Checking IP address %s for usage on interface %s", ip_addr, interface
        )
        current_time = time.time()
        in_use = False
        in_use_mac = None
        if is_ipv6:
            solicited_node = IPv6Utils.generate_solicited_node_address(ip_addr)
            ns_probe = (
                Ether(dst=BROADCAST_MAC_IPV6)
                / IPv6(dst=solicited_node)
                / ICMPv6ND_NS(tgt=ip_addr)
            )
        else:
            src_mac = InterfaceManager.get_mac_address(interface)
            if src_mac is None:
                logging.error(
                    "Failed to get MAC address for interface %s. Exiting.", interface
                )
                return ip_addr, False, None
            ether = Ether(src=src_mac, dst=BROADCAST_MAC_IPV4)
            arp_probe = ARP(hwsrc=src_mac, psrc=GARP_IP_ADDRESS, pdst=ip_addr)
            ns_probe = ether / arp_probe

        try:
            ans, unans = await loop.run_in_executor(
                None,
                lambda: srp(
                    ns_probe,
                    iface=interface,
                    timeout=ADR_CHECK_TIMEOUT,
                    verbose=False,
                    retry=ADR_CHECK_RETRY_COUNT,
                ),
            )
            if ans:
                in_use = True
                in_use_mac = ans[0][1].hwsrc if not is_ipv6 else ans[0][1][Ether].src
                logging.debug(
                    "IP address %s is in use by MAC %s on the network.",
                    ip_addr,
                    in_use_mac,
                )
        except Exception as e:
            logging.error("Error checking IP address %s: %s", ip_addr, e)
            return ip_addr, False, None

        return ip_addr, in_use, in_use_mac


class PacketSender:
    @staticmethod
    async def send_packet(
        packet: Ether, interface: str, loop: asyncio.AbstractEventLoop
    ) -> Optional[Tuple[str, str, str]]:
        logging.debug("Attempting to send packet on interface %s", interface)
        try:
            await loop.run_in_executor(
                None, lambda: sendp(packet, iface=interface, verbose=False)
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
        except Exception as e:
            logging.error("Error sending packet: %s", e)
            return None


class PacketProcessor:
    @staticmethod
    async def process_network_request(
        packet: Ether,
        target_mac: str,
        wireguard: bool,
        interface: str,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
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

            src_mac = InterfaceManager.get_mac_address(interface)
            if src_mac is None:
                logging.error(
                    "Failed to get MAC address for interface %s. Skipping response.",
                    interface,
                )
                return

            ip_addr, in_use, in_use_mac = await AddressChecker.check_ip_address_usage(
                interface, target_ip, target_mac, is_ipv6, loop
            )

            last_known_mac = last_replied_mac_per_ip.get(target_ip, None)

            should_broadcast = False
            if in_use and in_use_mac != last_known_mac:
                should_broadcast = True
            elif not in_use and last_known_mac != src_mac:
                should_broadcast = True
            if should_broadcast:
                if in_use:
                    broadcast_mac_address = in_use_mac
                    if last_known_mac == src_mac:
                        logging.info(
                            "Relinquishing responsibility of %s to MAC %s",
                            target_ip,
                            in_use_mac,
                        )
                else:
                    broadcast_mac_address = src_mac
                    logging.info(
                        "Assuming responsibility for %s with MAC %s", target_ip, src_mac
                    )

                last_replied_mac_per_ip[target_ip] = broadcast_mac_address

                if wireguard:
                    if broadcast_mac_address == target_mac:
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
                        Ether(dst=broadcast_mac, src=src_mac)
                        / IPv6(dst="ff02::1")
                        / ICMPv6ND_NA(tgt=target_ip, R=0, S=1, O=1)
                        / ICMPv6NDOptDstLLAddr(lladdr=broadcast_mac_address)
                    )
                else:
                    arp_reply = Ether(dst=broadcast_mac, src=src_mac) / ARP(
                        op=2,
                        hwsrc=broadcast_mac_address,
                        psrc=target_ip,
                        hwdst=broadcast_mac,
                        pdst="255.255.255.255",
                    )
                await PacketSender.send_packet(
                    na_reply if is_ipv6 else arp_reply, interface, loop
                )
                logging.info(
                    "Broadcasted %s update for %s with MAC %s",
                    "NA" if is_ipv6 else "ARP",
                    target_ip,
                    broadcast_mac_address,
                )

            if not in_use or in_use_mac == target_mac:
                if is_ipv6:
                    na_reply = (
                        Ether(dst=packet[Ether].src, src=src_mac)
                        / IPv6(dst=packet[IPv6].src)
                        / ICMPv6ND_NA(tgt=target_ip, R=0, S=1, O=1)
                        / ICMPv6NDOptDstLLAddr(lladdr=src_mac)
                    )
                    packet_identifier = await PacketSender.send_packet(
                        na_reply, interface, loop
                    )
                    logging.info(
                        "Sent NA reply for %s to %s", target_ip, packet[Ether].src
                    )
                else:
                    arp_reply = Ether(dst=packet[ARP].hwsrc, src=src_mac) / ARP(
                        op=2,
                        hwsrc=src_mac,
                        psrc=target_ip,
                        hwdst=packet[ARP].hwsrc,
                        pdst=target_ip,
                    )
                    packet_identifier = await PacketSender.send_packet(
                        arp_reply, interface, loop
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
                        "mac": target_mac,
                    }
                    logging.debug(
                        "Updated ip_usage_timestamps for %s with target MAC %s",
                        target_ip,
                        target_mac,
                    )
            logging.debug("Packet processing completed for: %s", packet.summary())
        except Exception as e:
            logging.error("Error processing packet %s: %s", packet.summary(), e)

    @staticmethod
    async def process_packets_from_queue(
        interface: str,
        target_mac: str,
        wireguard: bool,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        logging.debug("Packet processing task started.")
        while True:
            try:
                logging.debug("Waiting to get packet from queue...")
                packet = await packet_queue.get()
                logging.debug("Dequeuing packet for processing: %s", packet.summary())
                try:
                    await PacketProcessor.process_network_request(
                        packet, target_mac, wireguard, interface, loop
                    )
                except Exception as e:
                    logging.error("Error processing packet %s: %s", packet.summary(), e)
                finally:
                    packet_queue.task_done()
                    logging.debug("Packet processing task marked as done.")
            except asyncio.CancelledError:
                logging.info("Packet processing task was cancelled.")
                break
            except Exception as e:
                logging.error("Unexpected error during packet processing: %s", e)
                continue


class PacketSniffer:
    @staticmethod
    async def run_sniffer(
        interface: str,
        packet_handler: Callable[[Ether, asyncio.AbstractEventLoop], None],
        filter_str: str,
    ) -> None:
        sniffer = AsyncSniffer(
            iface=interface, prn=packet_handler, store=False, filter=filter_str
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
    def packet_callback(packet: Ether, loop: asyncio.AbstractEventLoop) -> None:
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
                asyncio.run_coroutine_threadsafe(packet_queue.put(packet), loop)
            else:
                asyncio.run_coroutine_threadsafe(packet_queue.put(packet), loop)
            logging.debug("Packet enqueued for processing.")
        except asyncio.QueueFull:
            logging.warning("Packet queue is full. Dropping packet.")
        except Exception as e:
            logging.error("Error processing packet: %s", e)


class TargetProcessor:
    @staticmethod
    def process_targets(target_args: List[str]) -> Tuple[List[str], bool]:
        targets = []
        wg_specified = False
        wireguard = False
        logging.debug("Processing target arguments: %s", target_args)

        for arg in target_args:
            if WG_PATTERN.match(arg):
                wireguard = True
                if arg == "wg":
                    if wg_specified:
                        logging.error("The 'wg' target may only be specified once.")
                        raise ValueError("The 'wg' target may only be specified once.")
                    wg_specified = True
                    logging.info("Adding targets from all WireGuard interfaces.")
                    targets.extend(WireGuardManager.get_targets())
                else:
                    logging.info("Adding targets from WireGuard interface: %s", arg)
                    targets.extend(WireGuardManager.get_targets(arg))
            else:
                logging.info("Adding non-WireGuard target: %s", arg)
                targets.append(arg)

        logging.debug("Final list of processed targets: %s", targets)
        return targets, wireguard


async def preload_ip_check(
    interface: str, targets: List[str], target_mac: str, loop: asyncio.AbstractEventLoop
) -> None:
    semaphore = asyncio.Semaphore(20)
    specified_ips = set()
    tasks = []

    async def semaphore_wrapped_task(
        task: asyncio.Task,
    ) -> Tuple[str, bool, Optional[str]]:
        async with semaphore:
            return await task

    for target in targets:
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
                                interface,
                                str(ip),
                                target_mac,
                                is_ipv6=(ip.version == 6),
                                loop=loop,
                            )
                        )
                    )
            except ValueError as e:
                logging.error("Error processing subnet %s: %s", target, e)
        else:
            specified_ips.add(target)
            is_ipv6 = ":" in target
            tasks.append(
                semaphore_wrapped_task(
                    AddressChecker.check_ip_address_usage(
                        interface, target, target_mac, is_ipv6=is_ipv6, loop=loop
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
                except Exception as e:
                    logging.error("Error deleting route for %s: %s", ip, e)
            else:
                try:
                    RouteManager.add_route(
                        ip, WireGuardManager.get_interface_for_ip(ip)
                    )
                    logging.info("Route added for IP %s as it's not in use.", ip)
                except Exception as e:
                    logging.error("Error adding route for %s: %s", ip, e)

                for ip in list(ip_usage_timestamps.keys()):
                    if ip not in specified_ips or not ip_usage_timestamps[ip].get(
                        "in_use", False
                    ):
                        ip_usage_timestamps.pop(ip, None)
                        arp_replies_sent.pop(ip, None)
                        na_replies_sent.pop(ip, None)
                        last_replied_mac_per_ip.pop(ip, None)


async def main(
    interface: str,
    target_mac: str,
    targets: List[str],
    wireguard: bool,
    excl: List[str],
    loop: asyncio.AbstractEventLoop,
) -> None:
    for signal_name in ("SIGINT", "SIGTERM"):
        loop.add_signal_handler(
            getattr(signal, signal_name), lambda: asyncio.create_task(shutdown(loop))
        )
        await preload_ip_check(interface, targets, target_mac, loop)

        interface_mac = InterfaceManager.get_mac_address(interface)
        filter_str = Utils.build_packet_filter(targets, excl, interface_mac)
        logging.debug("Packet filter string: %s", filter_str)
        logging.info("Starting packet sniffing...")

        sniffer_task = asyncio.create_task(
            PacketSniffer.run_sniffer(
                interface,
                lambda pkt: PacketSniffer.packet_callback(pkt, loop),
                filter_str,
            )
        )

    packet_processor_task = asyncio.create_task(
        PacketProcessor.process_packets_from_queue(
            interface, target_mac, wireguard, loop
        )
    )
    logging.debug("Packet processor task created.")

    cleanup_task = asyncio.create_task(Utils.cleanup_expired_ips(loop))
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


async def shutdown(loop: asyncio.AbstractEventLoop) -> None:
    logging.info("Shutdown initiated.")
    tasks = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task(loop)]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    loop.stop()
    logging.info("Shutdown complete.")


if __name__ == "__main__":
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
            "Target IP addresses, networks, wg (for all wg peers), "
            "or wg# for wg peers from a specific interface"
        ),
    )
    if len(sys.argv) < 4:
        Utils.print_usage()
        sys.exit(1)
    args = parser.parse_args()

    if args.verbose == 1:
        logging.getLogger().setLevel(logging.INFO)
    elif args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)

    iface = args.interface
    try:
        InterfaceManager.validate_interface(iface)
    except ValueError as exc:
        logging.error("Error validating interface: %s", exc)
        sys.exit(1)

    mac = (
        InterfaceManager.get_mac_address(iface)
        if args.mac.lower() == "auto"
        else args.mac
    )
    try:
        Utils.validate_mac_address(mac)
    except ValueError as exc:
        logging.error("Error validating MAC address: %s", exc)
        sys.exit(1)

    try:
        includes, wg_targets_specified = TargetProcessor.process_targets(args.targets)
    except ValueError as exc:
        logging.error("Error processing targets: %s", exc)
        sys.exit(1)

    excludes = [target[1:] for target in args.targets if target.startswith("-")]

    logging.debug(
        "Command-line arguments: interface=%s, mac=%s, targets=%s, excludes=%s",
        iface,
        args.mac,
        includes,
        excludes,
    )

    if args.pidfile:
        with open(args.pidfile, "w", encoding="ascii") as f:
            f.write(str(os.getpid()))

    eventloop = asyncio.get_event_loop()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        eventloop.add_signal_handler(
            sig, lambda: asyncio.create_task(shutdown(eventloop))
        )

    eventloop.run_until_complete(
        main(iface, mac, includes, wg_targets_specified, excludes, eventloop)
    )
