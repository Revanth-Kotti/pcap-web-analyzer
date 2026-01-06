from collections import defaultdict, Counter
from typing import Dict, Any, List
from scapy.all import rdpcap, Packet, IP, TCP, UDP, DNS, DNSQR, Raw  # type: ignore

def get_packet_layers(pkt: Packet) -> List[str]:
    """
    Return a list of layer names for a packet, e.g. ["Ethernet", "IP", "TCP", "DNS"].
    """
    layers = []
    layer = pkt
    # Walk through all layers until there is no payload
    while layer:
        layers.append(layer.__class__.__name__)
        layer = layer.payload
        if not isinstance(layer, Packet):
            break
    return layers  # typical pattern shown in Scapy layer‑inspection examples [web:132][web:133][web:134]

def analyze_pcap(path: str) -> Dict[str, Any]:
    packets = rdpcap(path)  # offline PCAP read [web:36][web:143]
    total_packets = len(packets)

    # 1) Per‑layer protocol statistics (all protocols Scapy recognizes)
    layer_counter = Counter()

    # 2) Traditional L3/L4/ DNS / flows / port scans
    proto_l4_counter = Counter()
    flows = defaultdict(int)
    dns_queries = []
    http_requests = []

    for pkt in packets:
        # Count all layers for this packet
        for lname in get_packet_layers(pkt):
            layer_counter[lname] += 1

        # L3 + L4 summaries
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        else:
            src_ip = None
            dst_ip = None

        proto = "OTHER"
        src_port = None
        dst_port = None

        if pkt.haslayer(TCP):
            proto = "TCP"
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport

        if proto in ("TCP", "UDP"):
            proto_l4_counter[proto] += 1

        # Build flow key when we know IPs
        if src_ip and dst_ip:
            key = (src_ip, dst_ip, src_port, dst_port, proto)
            flows[key] += 1

        # DNS queries
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNS][DNSQR].qname
            try:
                name = qname.decode().rstrip(".")
            except Exception:
                name = str(qname)
            dns_queries.append(name)

        # Very simple HTTP request extraction (only unencrypted HTTP, typical ports)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and (dst_port in (80, 8080, 8000)):
            raw_load = bytes(pkt[Raw].load)
            # Basic check for HTTP methods at start of payload
            for method in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS "):
                if raw_load.startswith(method):
                    line = raw_load.split(b"\r\n", 1)[0]
                    try:
                        http_requests.append(line.decode(errors="ignore"))
                    except Exception:
                        pass
                    break

    # Port scan heuristic
    src_to_targets = defaultdict(set)
    src_to_pkt_count = defaultdict(int)
    for (src_ip, dst_ip, src_port, dst_port, proto), count in flows.items():
        if dst_port is None:
            continue
        src_to_targets[src_ip].add((dst_ip, dst_port))
        src_to_pkt_count[src_ip] += count

    suspects = []
    for src_ip, targets in src_to_targets.items():
        unique_ports = len({p for (_, p) in targets})
        total_pkts_src = src_to_pkt_count[src_ip]
        if unique_ports >= 10 and total_pkts_src >= 20:
            suspects.append({
                "src_ip": src_ip,
                "unique_ports": unique_ports,
                "total_pkts": total_pkts_src,
            })

    dns_counts = Counter(dns_queries)

    # Build a high‑level report dictionary that is easy to render in HTML
    report: Dict[str, Any] = {
        "packet_count": total_packets,
        # All protocol layers that Scapy saw, sorted by count
        "layers": sorted(
            [{"name": name, "count": count} for name, count in layer_counter.items()],
            key=lambda x: x["count"],
            reverse=True,
        ),
        # Simple L4 summary (TCP/UDP vs others)
        "l4_protocols": dict(proto_l4_counter),
        # Top flows
        "top_flows": sorted(
            [
                {
                    "src_ip": k[0],
                    "dst_ip": k[1],
                    "src_port": k[2],
                    "dst_port": k[3],
                    "proto": k[4],
                    "count": v,
                }
                for k, v in flows.items()
            ],
            key=lambda x: x["count"],
            reverse=True,
        )[:10],
        "port_scan_suspects": suspects,
        "top_dns": dns_counts.most_common(10),
        "http_requests": http_requests[:20],  # cap for readability
    }

    return report
