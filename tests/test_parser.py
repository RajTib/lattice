"""Packet parsing and PCAP input."""
import pytest
from scapy.layers.inet import ICMP, IP, IPerror, TCP, TCPerror, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6, IPv6ExtHdrHopByHop
from scapy.layers.l2 import ARP
from scapy.packet import Raw

from lattice.capture import CaptureError, iter_pcap_records, load_pcap_records
from lattice.models import IngestStats
from lattice.parser import PacketParseError, parse_packet

from factories import (eth, icmp_packet, ipv6_tcp_packet, stamp, tcp_packet, udp_packet, write_pcap,
                       write_pcapng)


def test_tcp_ipv4_fields():
    pkt = tcp_packet(100.5, "10.0.0.1", "10.0.0.2", 51000, 80, "S", payload=10)
    rec = parse_packet(pkt)
    assert (rec.timestamp, rec.protocol, rec.ip_version) == (100.5, "TCP", 4)
    assert (rec.src_ip, rec.dst_ip, rec.src_port, rec.dst_port) == ("10.0.0.1", "10.0.0.2", 51000, 80)
    assert rec.tcp_flags == 0x02
    assert rec.length == len(pkt)
    assert rec.is_syn_attempt


@pytest.mark.parametrize("flags,syn_attempt", [("S", True), ("SA", False), ("A", False),
                                               ("R", False), ("F", False), ("PA", False)])
def test_syn_attempt_requires_syn_without_ack(flags, syn_attempt):
    assert parse_packet(tcp_packet(0, flags=flags)).is_syn_attempt is syn_attempt


def test_udp_has_ports_but_no_flags():
    rec = parse_packet(udp_packet(1.0, sport=5000, dport=53))
    assert rec.protocol == "UDP"
    assert (rec.src_port, rec.dst_port) == (5000, 53)
    assert rec.tcp_flags is None
    assert not rec.is_syn_attempt


def test_icmp_has_no_ports_or_flags():
    rec = parse_packet(icmp_packet(1.0))
    assert rec.protocol == "ICMP"
    assert rec.src_port is None and rec.dst_port is None and rec.tcp_flags is None


def test_zero_values_are_distinct_from_unavailable():
    null_tcp = parse_packet(tcp_packet(0, sport=0, dport=0, flags=0))
    assert null_tcp.tcp_flags == 0 and null_tcp.src_port == 0 and null_tcp.dst_port == 0
    assert parse_packet(udp_packet(0)).tcp_flags is None
    assert parse_packet(icmp_packet(0)).dst_port is None


def test_ipv6_tcp():
    rec = parse_packet(ipv6_tcp_packet(5.0, dport=8443))
    assert rec.ip_version == 6 and rec.protocol == "TCP"
    assert rec.src_ip == "2001:db8::1" and rec.dst_port == 8443


def test_icmpv6():
    pkt = stamp(eth() /IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest(), 1.0)
    rec = parse_packet(pkt)
    assert rec.protocol == "ICMPv6" and rec.dst_port is None


def test_ipv6_extension_header_is_skipped():
    pkt = stamp(eth() /IPv6() / IPv6ExtHdrHopByHop() / TCP(sport=1, dport=22, flags="S"), 1.0)
    rec = parse_packet(pkt)
    assert rec.protocol == "TCP" and rec.dst_port == 22 and rec.tcp_flags == 0x02


def test_arp_has_no_ip_fields():
    rec = parse_packet(stamp(eth() /ARP(), 1.0))
    assert rec.protocol == "ARP" and rec.src_ip is None and rec.ip_version is None


def test_unknown_ip_protocol_is_identified_not_dropped():
    rec = parse_packet(stamp(eth() /IP(proto=47) / Raw(b"gre"), 1.0))
    assert rec.protocol == "IP_PROTO_47" and rec.src_port is None


def test_unknown_ethertype_is_identified():
    rec = parse_packet(stamp(eth(type=0x88CC) / Raw(b"lldp"), 1.0))
    assert rec.protocol == "ETHERTYPE_0x88cc" and rec.src_ip is None


def test_missing_transport_layer_keeps_protocol_without_ports():
    # IP header says TCP but the segment is cut off before any TCP header.
    pkt = stamp(eth() /IP(proto=6) / Raw(b"\x01"), 1.0)
    rec = parse_packet(pkt)
    assert rec.protocol == "TCP" and rec.src_port is None and rec.tcp_flags is None


def test_non_first_fragment_has_no_ports():
    pkt = stamp(eth() /IP(proto=17, frag=10) / Raw(b"x" * 20), 1.0)
    rec = parse_packet(pkt)
    assert rec.protocol == "UDP" and rec.dst_port is None


def test_icmp_error_does_not_leak_embedded_tcp_ports():
    inner = IPerror(src="10.0.0.2", dst="10.0.0.1", proto=6) / TCPerror(sport=80, dport=51000)
    pkt = stamp(eth() /IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=3, code=3) / inner, 1.0)
    rec = parse_packet(pkt)
    assert rec.protocol == "ICMP" and rec.src_port is None and rec.dst_port is None


def test_wire_length_preferred_over_captured_length():
    pkt = tcp_packet(1.0)
    pkt.wirelen = 1514
    assert parse_packet(pkt).length == 1514


@pytest.mark.parametrize("pkt", [
    stamp(eth() /IP(ihl=2) / TCP(), 1.0),
    stamp(eth() /IP(version=5) / TCP(), 1.0),
    stamp(eth() /IPv6(version=4), 1.0),
    stamp(eth() /IP() / TCP(dataofs=2), 1.0),
])
def test_malformed_headers_raise(pkt):
    with pytest.raises(PacketParseError):
        parse_packet(pkt)


def test_object_without_timestamp_is_malformed():
    with pytest.raises(PacketParseError):
        parse_packet(object())


# -- PCAP input ------------------------------------------------------------

def test_pcap_roundtrip_and_counts(tmp_path):
    path = write_pcap(tmp_path / "a.pcap", [tcp_packet(1.0), udp_packet(2.0), icmp_packet(3.0)])
    stats = IngestStats()
    records = load_pcap_records(path, stats)
    assert [r.protocol for r in records] == ["TCP", "UDP", "ICMP"]
    assert (stats.seen, stats.parsed, stats.malformed, stats.skipped) == (3, 3, 0, 0)


def test_pcapng_roundtrip_preserves_order_fields_and_timestamps(tmp_path):
    path = write_pcapng(tmp_path / "a.pcapng", [
        tcp_packet(10.125001, sport=50001, dport=443),
        udp_packet(10.875999, sport=50002, dport=53),
    ])
    stats = IngestStats()
    records = load_pcap_records(path, stats)
    assert [r.protocol for r in records] == ["TCP", "UDP"]
    assert [r.src_port for r in records] == [50001, 50002]
    assert [r.timestamp for r in records] == pytest.approx([10.125001, 10.875999], abs=1e-6)
    assert (stats.seen, stats.parsed, stats.skipped) == (2, 2, 0)


def test_pcap_records_sorted_by_timestamp_with_stable_ties(tmp_path):
    packets = [tcp_packet(5.0, sport=1), tcp_packet(1.0, sport=2), tcp_packet(5.0, sport=3),
               tcp_packet(3.0, sport=4)]
    path = write_pcap(tmp_path / "unordered.pcap", packets)
    records = load_pcap_records(path, IngestStats())
    assert [r.timestamp for r in records] == [1.0, 3.0, 5.0, 5.0]
    assert [r.src_port for r in records if r.timestamp == 5.0] == [1, 3]  # file order kept


def test_malformed_packets_are_counted_not_hidden(tmp_path):
    bad = stamp(eth() /IP(ihl=2) / TCP(), 2.0)
    path = write_pcap(tmp_path / "mixed.pcap", [tcp_packet(1.0), bad, tcp_packet(3.0)])
    stats = IngestStats()
    records = list(iter_pcap_records(path, stats))
    assert len(records) == 2
    assert stats.seen == 3 and stats.malformed == 1 and stats.skipped == 1


def test_missing_file_raises(tmp_path):
    with pytest.raises(CaptureError, match="not found"):
        list(iter_pcap_records(tmp_path / "nope.pcap", IngestStats()))


@pytest.mark.parametrize("content", [b"", b"this is not a capture file at all"])
def test_non_pcap_file_raises(tmp_path, content):
    path = tmp_path / "bad.pcap"
    path.write_bytes(content)
    with pytest.raises(CaptureError):
        list(iter_pcap_records(path, IngestStats()))


def test_truncated_pcap_returns_complete_packets(tmp_path):
    path = write_pcap(tmp_path / "t.pcap", [tcp_packet(float(i), sport=1000 + i) for i in range(6)])
    path.write_bytes(path.read_bytes()[:-20])  # cut the last record in half
    stats = IngestStats()
    records = list(iter_pcap_records(path, stats))
    # The cut-off record is still returned, but its TCP header is incomplete, so
    # ports are reported as unavailable rather than invented.
    assert len(records) == 6
    assert [r.src_port for r in records[:5]] == list(range(1000, 1005))
    assert records[5].src_port is None and records[5].tcp_flags is None
