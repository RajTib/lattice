"""Convert Scapy packets into normalized :class:`PacketRecord` objects.

Downstream modules never see Scapy objects. Only header fields are read; payload
bytes are never copied or retained.

Classification rules:

* IPv4 / IPv6 packets get the transport protocol from the IP header (``TCP``,
  ``UDP``, ``ICMP``, ``ICMPv6``) or ``IP_PROTO_<n>`` for anything else.
* ARP is reported as ``ARP`` with no IP addresses (those are L2 neighbour
  discovery, not routed traffic).
* Other Ethernet frames are reported as ``ETHERTYPE_0x....``; anything with no
  recognisable header is ``OTHER``. These are *unsupported but counted*.
* Structurally invalid headers (e.g. IPv4 IHL < 5) raise
  :class:`PacketParseError`; callers count and skip those packets.
"""
from __future__ import annotations

import logging
from typing import Any, Iterator, Optional

# Silence Scapy's import-time banner about missing libpcap providers; capture.py
# reports that condition itself with an actionable message.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6, _IPv6ExtHdr  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.packet import NoPayload  # noqa: E402

from .models import PacketRecord  # noqa: E402

log = logging.getLogger(__name__)

_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


class PacketParseError(ValueError):
    """The packet is structurally invalid and cannot be turned into a record."""


def _layers(pkt: Any) -> Iterator[Any]:
    layer = pkt
    while layer is not None and not isinstance(layer, NoPayload):
        yield layer
        layer = layer.payload


def _proto_name(number: int) -> str:
    return _PROTO_NAMES.get(number, f"IP_PROTO_{number}")


def _packet_length(pkt: Any) -> int:
    # PcapReader sets wirelen to the on-the-wire size, which matters when the
    # capture was truncated by a snap length.
    wirelen = getattr(pkt, "wirelen", None)
    if isinstance(wirelen, int) and wirelen > 0:
        return wirelen
    return len(pkt)


def _ports_and_flags(transport: Any) -> tuple[Optional[int], Optional[int], Optional[int]]:
    if isinstance(transport, TCP):
        if transport.dataofs is not None and transport.dataofs < 5:
            raise PacketParseError(f"TCP data offset {transport.dataofs} < 5")
        return int(transport.sport), int(transport.dport), int(transport.flags)
    if isinstance(transport, UDP):
        return int(transport.sport), int(transport.dport), None
    return None, None, None


def parse_packet(pkt: Any) -> PacketRecord:
    """Parse one Scapy packet. Raises :class:`PacketParseError` if it is malformed."""
    try:
        return _parse(pkt)
    except PacketParseError:
        raise
    except Exception as exc:  # Scapy raises many unrelated types on corrupt input.
        log.debug("unparseable packet: %r", exc)
        raise PacketParseError(f"{type(exc).__name__}: {exc}") from exc


def _parse(pkt: Any) -> PacketRecord:
    timestamp = float(pkt.time)
    length = _packet_length(pkt)

    l3: Any = None
    ethertype: Optional[int] = None
    for layer in _layers(pkt):
        if isinstance(layer, Ether):
            ethertype = int(layer.type)
        if isinstance(layer, (IP, IPv6, ARP)):
            l3 = layer
            break

    if isinstance(l3, IP):
        return _parse_ipv4(l3, timestamp, length)
    if isinstance(l3, IPv6):
        return _parse_ipv6(l3, timestamp, length)
    if isinstance(l3, ARP):
        return PacketRecord(timestamp, length, "ARP")
    if ethertype is not None:
        return PacketRecord(timestamp, length, f"ETHERTYPE_0x{ethertype:04x}")
    return PacketRecord(timestamp, length, "OTHER")


def _parse_ipv4(ip: Any, timestamp: float, length: int) -> PacketRecord:
    if ip.version != 4:
        raise PacketParseError(f"IPv4 header with version field {ip.version}")
    # ihl/len are None on packets built in memory (Scapy fills them in on build);
    # packets dissected from the wire always have them set.
    if ip.ihl is not None and ip.ihl < 5:
        raise PacketParseError(f"IPv4 IHL {ip.ihl} < 5")
    if ip.ihl is not None and ip.len is not None and ip.len < ip.ihl * 4:
        raise PacketParseError(f"IPv4 total length {ip.len} shorter than header")
    transport = ip.payload
    src_port, dst_port, flags = (None, None, None)
    # Non-first fragments carry no transport header, so ports/flags stay unavailable.
    if not ip.frag:
        src_port, dst_port, flags = _ports_and_flags(transport)
    return PacketRecord(
        timestamp=timestamp, length=length, protocol=_proto_name(int(ip.proto)),
        src_ip=str(ip.src), dst_ip=str(ip.dst), src_port=src_port, dst_port=dst_port,
        tcp_flags=flags, ip_version=4,
    )


def _parse_ipv6(ip: Any, timestamp: float, length: int) -> PacketRecord:
    if ip.version != 6:
        raise PacketParseError(f"IPv6 header with version field {ip.version}")
    header: Any = ip
    transport = ip.payload
    next_header = int(ip.nh)
    while isinstance(transport, _IPv6ExtHdr):
        header = transport
        next_header = int(header.nh)
        transport = header.payload
    src_port, dst_port, flags = _ports_and_flags(transport)
    return PacketRecord(
        timestamp=timestamp, length=length, protocol=_proto_name(next_header),
        src_ip=str(ip.src), dst_ip=str(ip.dst), src_port=src_port, dst_port=dst_port,
        tcp_flags=flags, ip_version=6,
    )
