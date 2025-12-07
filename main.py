import time
import threading
import ipaddress
import struct
import socket
from tkinter import *
from tkinter import ttk, messagebox
from scapy.all import sniff, sendp, Ether, ARP, conf, get_if_hwaddr, IP, UDP, Raw, ICMP, Padding

# 192.168.01 / 25
# 172.16.0.1 / 30

# RIPv2 timers (seconds) — Cisco defaults: update 30, invalid 180, flush 240 
RIP_UPDATE_INTERVAL = 30
RIP_INVALID_TIMER = 180
RIP_FLUSH_TIMER = 240
RIP_INFINITY = 16

RIP_MULTICAST = "224.0.0.9"
RIP_PORT = 520

import subprocess
import re

def _get_mac_robust(iface_name):
    # Try scapy first
    try:
        mac = get_if_hwaddr(iface_name)
        if mac and mac != "00:00:00:00:00:00":
            return mac
    except Exception:
        pass
    
    # Fallback: parse ifconfig
    try:
        output = subprocess.check_output(["ifconfig", iface_name], stderr=subprocess.DEVNULL).decode()
        # 'ether'
        m = re.search(r"(?:ether|hwaddr)\s+([0-9a-fA-F:]{17})", output)
        if m:
            return m.group(1)
    except Exception:
        pass
        
    return "00:00:00:00:00:00"

class Iface:
    def __init__(self, label, phys_iface):
        self.label = label
        self.phys = phys_iface
        self.virt_ip = None
        self.netmask = None
        self._stop = threading.Event()
        self.sniffer = None
        self.forwarder = None
        # RIP
        self.rip_enabled = False
        self.rip_thread = None
        # Cache MAC address
        self.mac = _get_mac_robust(phys_iface) if phys_iface else "00:00:00:00:00:00"


def get_available_interfaces():
    """Get list of all available network interfaces"""
    ifaces = []
    try:
        # Try using netifaces if available
        import netifaces
        ifaces = netifaces.interfaces()
    except ImportError:
        # Fallback: parse ifconfig output
        try:
            output = subprocess.check_output(["ifconfig", "-l"], stderr=subprocess.DEVNULL).decode()
            ifaces = output.strip().split()
        except Exception:
            # Last resort: try common interface names
            ifaces = ["en0", "en1", "en2", "en3", "en4", "en5", "en6", "en7", "en8", "en9", "en10"]
    
    # Filter out loopback and virtual interfaces
    filtered = []
    for iface in ifaces:
        if iface.startswith("lo"):  # loopback
            continue
        if iface.startswith("gif") or iface.startswith("stf"):  # tunnels
            continue
        if iface.startswith("bridge") or iface.startswith("p2p"):
            continue
        filtered.append(iface)
    
    return sorted(filtered) if filtered else ["en0"]

interfaces = {}
arp_table = {}
routing_table = []  # {'net': IPv4Network, 'iface': str|None, 'next_hop': str|None, 'type': 'static'|'dynamic'|'connected', ...}
arp_lock = threading.Lock()
rt_lock = threading.Lock()
rip_lock = threading.Lock()
arp_ttl = 120  # seconds

# NAT Configuration
nat_enabled = False
nat_lock = threading.Lock()

# Interface types: 'inside' or 'outside'
nat_if_type = {}  # {iface_label: 'inside'|'outside'}

# Static NAT: {inside_local: inside_global}
static_nat_map = {}

# Dynamic NAT pool: list of available global IPs
dynamic_nat_pool = []
dynamic_nat_allocations = {}  # {inside_local: (inside_global, timestamp)}

# PAT translation table: {(inside_ip, inside_port, proto): (outside_ip, outside_port, timestamp)}
pat_table = {}

# Port Forwarding: {(outside_ip, outside_port, proto): (inside_ip, inside_port)}
port_forward_map = {}

# NAT timers (seconds)
NAT_TCP_TIMEOUT = 86400  # 24 hours
NAT_UDP_TIMEOUT = 300    # 5 minutes
NAT_ICMP_TIMEOUT = 60    # 1 minute

# Next available PAT port
next_pat_port = 10000

# Helper utilities 

def arp_update(ip, mac):
    with arp_lock:
        arp_table[ip] = {"mac": mac, "ts": time.time()}


def arp_remove(ip=None):
    with arp_lock:
        if ip is None:
            arp_table.clear()
        elif ip in arp_table:
            del arp_table[ip]


def arp_snapshot():
    with arp_lock:
        return {k: v.copy() for k, v in arp_table.items()}


def _route_equals(a, b):
    return a['net'] == b['net'] and a.get('iface') == b.get('iface') and a.get('next_hop') == b.get('next_hop') and a.get('type') == b.get('type')

def add_static_route(dest: str, mask: str, iface: str = None, next_hop: str = None):
    try:
        net = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
    except Exception:
        return False
    entry = {'net': net, 'iface': iface, 'next_hop': next_hop, 'type': 'static'}
    with rt_lock:
        # Check for existing static route
        for r in routing_table:
            if _route_equals(r, entry):
                return True
        
        # Remove any existing dynamic routes for this network (static > dynamic)
        routing_table[:] = [r for r in routing_table if not (r['net'] == net and r['type'] == 'dynamic')]
        
        routing_table.append(entry)
    return True

def remove_static_route(dest: str, mask: str, iface: str = None, next_hop: str = None):
    try:
        net = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
    except Exception:
        return False
    removed = False
    new_rt = []
    with rt_lock:
        for r in routing_table:
            if r['net'] == net and r['type'] == 'static':
                if (iface is None or r.get('iface') == iface) and (next_hop is None or r.get('next_hop') == next_hop):
                    removed = True
                    continue
            new_rt.append(r)
        routing_table[:] = new_rt
    return removed

def route_lookup(addr: str, requested_nh: str = None, visited=None):
    """
    Recursive lookup that returns a tuple (route_dict, arp_target_ip)
    - route_dict: final route that contains 'iface' (or None if unresolved)
    - arp_target_ip: the IP we should ARP for (first next-hop encountered on the chain, or addr)
    """
    try:
        ip = ipaddress.ip_address(addr)
    except Exception:
        return None, None
    if visited is None:
        visited = set()
    with rt_lock:
        candidates = []
        for r in routing_table:
            try:
                if ip in r['net']:
                    candidates.append((r['net'].prefixlen, r))
            except Exception:
                continue
    if not candidates:
        # fallback: infer connected iface directly (even if connected route not present)
        for obj in interfaces.values():
            if _ip_in_iface_network(addr, obj):
                net = _make_iface_network(obj)
                if net:
                    return ({'net': net, 'iface': obj.label, 'next_hop': None, 'type': 'connected'}, addr)
        return None, None
    
    # Sort candidates by prefix length and then by priority
    def get_priority(route):
        rtype = route.get('type')
        if rtype == 'connected': return 3
        if rtype == 'static': return 2
        if rtype == 'dynamic': return 1
        return 0

    # Sort key: (prefix_len, priority, -metric)
    candidates.sort(key=lambda x: (x[0], get_priority(x[1]), -x[1].get('metric', 0) if x[1].get('type') == 'dynamic' else 0), reverse=True)
    
    _, route = candidates[0]
    if route.get('iface'):
        arp_target = requested_nh or addr
        return route, arp_target
    nh = route.get('next_hop')
    if nh:
        if nh in visited:
            return None, None
        visited.add(nh)
        new_requested = requested_nh or nh
        return route_lookup(nh, requested_nh=new_requested, visited=visited)
    return None, None

def route_snapshot():
    out = []
    with rt_lock:
        for r in routing_table:
            out.append({
                'dest': str(r['net'].network_address),
                'mask': str(r['net'].netmask),
                'prefix': r['net'].prefixlen,
                'iface': r.get('iface') or '',
                'next_hop': r.get('next_hop') or '',
                'type': r.get('type'),
                'metric': r.get('metric', '')
            })
    return out

def _make_iface_network(obj: Iface):
    try:
        return ipaddress.ip_network(f"{obj.virt_ip}/{obj.netmask}", strict=False)
    except Exception:
        return None

def add_connected_route_for_iface(obj: Iface):
    net = _make_iface_network(obj)
    if net is None:
        return
    entry = {'net': net, 'iface': obj.label, 'next_hop': None, 'type': 'connected'}
    with rt_lock:
        for r in routing_table:
            if r.get('type') == 'connected' and r['net'] == net and r.get('iface') == obj.label:
                return
        routing_table.append(entry)

def remove_connected_route_for_iface(obj: Iface):
    net = _make_iface_network(obj)
    if net is None:
        return
    with rt_lock:
        routing_table[:] = [r for r in routing_table if not (r.get('type') == 'connected' and r['net'] == net and r.get('iface') == obj.label)]

def _ip_in_iface_network(target_ip: str, obj: Iface) -> bool:
    if not obj.virt_ip or not obj.netmask:
        return False
    try:
        net = ipaddress.ip_network(f"{obj.virt_ip}/{obj.netmask}", strict=False)
        return ipaddress.ip_address(target_ip) in net
    except Exception:
        return False

# NAT helper functions

def _get_protocol_timeout(proto):
    """Get timeout for protocol"""
    if proto == socket.IPPROTO_TCP:
        return NAT_TCP_TIMEOUT
    elif proto == socket.IPPROTO_UDP:
        return NAT_UDP_TIMEOUT
    else:
        return NAT_ICMP_TIMEOUT

def _allocate_pat_port():
    """Allocate next available PAT port"""
    global next_pat_port
    port = next_pat_port
    next_pat_port += 1
    if next_pat_port > 65535:
        next_pat_port = 10000
    return port

def nat_table_snapshot():
    """Get snapshot of NAT translation tables"""
    result = {
        'static': [],
        'dynamic': [],
        'pat': [],
        'port_forward': []
    }
    
    # Static NAT
    for inside_local, inside_global in static_nat_map.items():
        result['static'].append({
            'inside_local': inside_local,
            'inside_global': inside_global
        })
    
    # Dynamic NAT
    with nat_lock:
        for inside_local, (inside_global, ts) in dynamic_nat_allocations.items():
            result['dynamic'].append({
                'inside_local': inside_local,
                'inside_global': inside_global,
                'age': int(time.time() - ts)
            })
        
        # PAT
        for (inside_ip, inside_port, proto), (outside_ip, outside_port, ts) in pat_table.items():
            proto_name = 'TCP' if proto == socket.IPPROTO_TCP else ('UDP' if proto == socket.IPPROTO_UDP else 'OTHER')
            result['pat'].append({
                'inside': f"{inside_ip}:{inside_port}",
                'outside': f"{outside_ip}:{outside_port}",
                'proto': proto_name,
                'age': int(time.time() - ts)
            })
    
    # Port Forwarding
    for (outside_ip, outside_port, proto), (inside_ip, inside_port) in port_forward_map.items():
        proto_name = 'TCP' if proto == socket.IPPROTO_TCP else ('UDP' if proto == socket.IPPROTO_UDP else 'OTHER')
        result['port_forward'].append({
            'outside': f"{outside_ip}:{outside_port}",
            'inside': f"{inside_ip}:{inside_port}",
            'proto': proto_name
        })
    
    return result

def clear_nat_table():
    """Clear dynamic NAT entries"""
    with nat_lock:
        pat_table.clear()
        dynamic_nat_allocations.clear()

def _translate_inside_to_outside(pkt, in_iface, out_iface):
    """
    Translate packet from inside to outside.
    Returns modified packet or None if translation fails.
    """
    if not nat_enabled:
        return pkt
    
    # Check if this is inside->outside traffic
    if nat_if_type.get(in_iface.label) != 'inside' or nat_if_type.get(out_iface.label) != 'outside':
        return pkt
    
    inside_ip = pkt[IP].src
    new_pkt = pkt.copy()
    
    # Check for Static NAT first
    if inside_ip in static_nat_map:
        new_pkt[IP].src = static_nat_map[inside_ip]
        del new_pkt[IP].chksum
        if new_pkt.haslayer("TCP"): del new_pkt["TCP"].chksum
        if new_pkt.haslayer("UDP"): del new_pkt["UDP"].chksum
        return new_pkt
    
    # Check for Dynamic NAT
    with nat_lock:
        if inside_ip in dynamic_nat_allocations:
            global_ip, ts = dynamic_nat_allocations[inside_ip]
            new_pkt[IP].src = global_ip
            dynamic_nat_allocations[inside_ip] = (global_ip, time.time())
            del new_pkt[IP].chksum
            if new_pkt.haslayer("TCP"): del new_pkt["TCP"].chksum
            if new_pkt.haslayer("UDP"): del new_pkt["UDP"].chksum
            return new_pkt
        
        # Allocate from pool
        if dynamic_nat_pool:
            for candidate_ip in dynamic_nat_pool:
                # Check if this IP is already allocated to someone else
                already_used = False
                for local, (glob, ts) in dynamic_nat_allocations.items():
                    if glob == candidate_ip and local != inside_ip:
                        already_used = True
                        break
                if not already_used:
                    dynamic_nat_allocations[inside_ip] = (candidate_ip, time.time())
                    new_pkt[IP].src = candidate_ip
                    del new_pkt[IP].chksum
                    if new_pkt.haslayer("TCP"): del new_pkt["TCP"].chksum
                    if new_pkt.haslayer("UDP"): del new_pkt["UDP"].chksum
                    return new_pkt
    
    # PAT - translate using outside interface IP + port
    outside_ip = out_iface.virt_ip
    if not outside_ip:
        return pkt
    
    proto = pkt[IP].proto
    
    # Handle TCP/UDP
    if pkt.haslayer('TCP'):
        inside_port = pkt['TCP'].sport
        key = (inside_ip, inside_port, socket.IPPROTO_TCP)
        
        with nat_lock:
            if key in pat_table:
                _, outside_port, _ = pat_table[key]
            else:
                outside_port = _allocate_pat_port()
            pat_table[key] = (outside_ip, outside_port, time.time())
        
        new_pkt[IP].src = outside_ip
        new_pkt['TCP'].sport = outside_port
        del new_pkt[IP].chksum
        del new_pkt['TCP'].chksum
        return new_pkt
    
    elif pkt.haslayer('UDP'):
        inside_port = pkt['UDP'].sport
        key = (inside_ip, inside_port, socket.IPPROTO_UDP)
        
        with nat_lock:
            if key in pat_table:
                _, outside_port, _ = pat_table[key]
            else:
                outside_port = _allocate_pat_port()
            pat_table[key] = (outside_ip, outside_port, time.time())
        
        new_pkt[IP].src = outside_ip
        new_pkt['UDP'].sport = outside_port
        del new_pkt[IP].chksum
        del new_pkt['UDP'].chksum
        return new_pkt
    
    # Handle ICMP Echo Request (ping) - use ICMP ID as the "port" for PAT
    elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # Echo Request
        inside_icmp_id = pkt[ICMP].id
        key = (inside_ip, inside_icmp_id, socket.IPPROTO_ICMP)
        
        with nat_lock:
            if key in pat_table:
                _, outside_icmp_id, _ = pat_table[key]
            else:
                # Allocate new ICMP ID
                outside_icmp_id = _allocate_pat_port() & 0xFFFF  # ICMP ID is 16-bit
            pat_table[key] = (outside_ip, outside_icmp_id, time.time())
        
        new_pkt[IP].src = outside_ip
        new_pkt[ICMP].id = outside_icmp_id
        del new_pkt[IP].chksum
        del new_pkt[ICMP].chksum
        return new_pkt
    
    return pkt

def _translate_outside_to_inside(pkt, in_iface, out_iface):
    """
    Translate packet from outside to inside (reverse translation).
    Returns modified packet or None if translation fails.
    """
    if not nat_enabled:
        return pkt
    
    # Check if this is outside->inside traffic
    if nat_if_type.get(in_iface.label) != 'outside' or nat_if_type.get(out_iface.label) != 'inside':
        return pkt
    
    dst_ip = pkt[IP].dst
    new_pkt = pkt.copy()
    
    # Check Static NAT (reverse lookup)
    for inside_local, inside_global in static_nat_map.items():
        if dst_ip == inside_global:
            new_pkt[IP].dst = inside_local
            del new_pkt[IP].chksum
            if new_pkt.haslayer("TCP"): del new_pkt["TCP"].chksum
            if new_pkt.haslayer("UDP"): del new_pkt["UDP"].chksum
            return new_pkt
    
    # Check Dynamic NAT (reverse lookup)
    with nat_lock:
        for inside_local, (inside_global, ts) in dynamic_nat_allocations.items():
            if dst_ip == inside_global:
                new_pkt[IP].dst = inside_local
                del new_pkt[IP].chksum
                if new_pkt.haslayer("TCP"): del new_pkt["TCP"].chksum
                if new_pkt.haslayer("UDP"): del new_pkt["UDP"].chksum
                return new_pkt
    
    # Port Forwarding
    if pkt.haslayer('TCP'):
        dst_port = pkt['TCP'].dport
        key = (dst_ip, dst_port, socket.IPPROTO_TCP)
        if key in port_forward_map:
            inside_ip, inside_port = port_forward_map[key]
            new_pkt[IP].dst = inside_ip
            new_pkt['TCP'].dport = inside_port
            del new_pkt[IP].chksum
            del new_pkt['TCP'].chksum
            return new_pkt
    elif pkt.haslayer('UDP'):
        dst_port = pkt['UDP'].dport
        key = (dst_ip, dst_port, socket.IPPROTO_UDP)
        if key in port_forward_map:
            inside_ip, inside_port = port_forward_map[key]
            new_pkt[IP].dst = inside_ip
            new_pkt['UDP'].dport = inside_port
            del new_pkt[IP].chksum
            del new_pkt['UDP'].chksum
            return new_pkt
    
    # PAT reverse lookup
    if pkt.haslayer('TCP'):
        dst_port = pkt['TCP'].dport
        with nat_lock:
            for (inside_ip, inside_port, proto), (outside_ip, outside_port, ts) in pat_table.items():
                if proto == socket.IPPROTO_TCP and outside_ip == dst_ip and outside_port == dst_port:
                    new_pkt[IP].dst = inside_ip
                    new_pkt['TCP'].dport = inside_port
                    pat_table[(inside_ip, inside_port, proto)] = (outside_ip, outside_port, time.time())
                    del new_pkt[IP].chksum
                    del new_pkt['TCP'].chksum
                    return new_pkt
    elif pkt.haslayer('UDP'):
        dst_port = pkt['UDP'].dport
        with nat_lock:
            for (inside_ip, inside_port, proto), (outside_ip, outside_port, ts) in pat_table.items():
                if proto == socket.IPPROTO_UDP and outside_ip == dst_ip and outside_port == dst_port:
                    new_pkt[IP].dst = inside_ip
                    new_pkt['UDP'].dport = inside_port
                    pat_table[(inside_ip, inside_port, proto)] = (outside_ip, outside_port, time.time())
                    del new_pkt[IP].chksum
                    del new_pkt['UDP'].chksum
                    return new_pkt
    
    # ICMP Echo Reply PAT reverse lookup
    elif pkt.haslayer(ICMP) and pkt[ICMP].type == 0:  # Echo Reply
        dst_icmp_id = pkt[ICMP].id
        with nat_lock:
            for (inside_ip, inside_icmp_id, proto), (outside_ip, outside_icmp_id, ts) in pat_table.items():
                if proto == socket.IPPROTO_ICMP and outside_ip == dst_ip and outside_icmp_id == dst_icmp_id:
                    new_pkt[IP].dst = inside_ip
                    new_pkt[ICMP].id = inside_icmp_id
                    pat_table[(inside_ip, inside_icmp_id, proto)] = (outside_ip, outside_icmp_id, time.time())
                    del new_pkt[IP].chksum
                    del new_pkt[ICMP].chksum
                    return new_pkt
    
    return pkt

 

def _rip_build_entry(net: ipaddress.IPv4Network, next_hop: str, metric: int):
    # RIPv2 entry: family(2), route-tag(2), ip(4), mask(4), next-hop(4), metric(4)
    fam = 2  # AF_INET
    route_tag = 0
    ip_addr = int(net.network_address)
    mask = int(net.netmask)
    nh = 0
    if next_hop:
        try:
            nh = int(ipaddress.ip_address(next_hop))
        except Exception:
            nh = 0
    packed = struct.pack("!HHIIII", fam, route_tag, ip_addr, mask, nh, metric)
    return packed

def _rip_parse_entries(payload):
    # payload after first 4 bytes (command/version/zero)
    entries = []
    off = 4
    
    while off + 20 <= len(payload):
        try:
            fam, tag, ip_addr, mask, nh, metric = struct.unpack_from("!HHIIII", payload, off)
            
            # Convert to IPv4Address objects then to string for Python 3.13 compatibility
            ip_obj = ipaddress.ip_address(ip_addr)
            mask_obj = ipaddress.ip_address(mask)
            # Use address/netmask notation
            net = ipaddress.ip_network(f"{ip_obj}/{mask_obj}", strict=False)
            next_hop = str(ipaddress.ip_address(nh)) if nh != 0 else None
            entries.append({'net': net, 'metric': metric, 'next_hop': next_hop})
        except Exception:
            pass
        off += 20
    
    return entries

def _rip_build_packet(entries_bytes: bytes):
    # command = 2 (response), version = 2, zero = 0
    header = struct.pack("!BBH", 2, 2, 0)
    return header + entries_bytes

def _send_rip_update_on_iface(iface: Iface):
    # Build entries taking into account split-horizon with poison reverse
    entries = b""
    with rt_lock:
        for r in routing_table:
            # we advertise connected and dynamic and static (but dynamic and static only as appropriate)
            if r.get('type') not in ('connected', 'dynamic', 'static'):
                continue
            metric = r.get('metric', 1) if r.get('type') == 'dynamic' else 1
            # apply split horizon with poison reverse:
            # if this route was learned from this iface, advertise metric = 16 (unreachable) on this iface
            if r.get('type') == 'dynamic' and r.get('installed_from') == iface.label:
                used_metric = RIP_INFINITY
            else:
                used_metric = metric
            entries += _rip_build_entry(r['net'], r.get('next_hop'), used_metric)
    if not entries:
        return
    rip_payload = _rip_build_packet(entries)
    # Use raw IP/UDP payload to multicast 224.0.0.9
    try:
        pkt = IP(src=iface.virt_ip, dst=RIP_MULTICAST)/UDP(sport=RIP_PORT, dport=RIP_PORT)/Raw(load=rip_payload)
        sendp(Ether(dst="01:00:5e:00:00:09", src=get_if_hwaddr(iface.phys))/pkt, iface=iface.phys, verbose=False)
    except Exception:
        pass

def _process_incoming_rip(pkt, recv_iface_label: str):
    # pkt: scapy packet containing UDP payload with RIPv2 message
    try:
        udp = pkt.getlayer(UDP)
        raw = bytes(udp.payload)
    except Exception:
        return
    if len(raw) < 4:
        return
    cmd, ver, zero = struct.unpack_from("!BBH", raw, 0)
    if ver != 2:
        return
    
    # Handle RIP Request (cmd=1)
    if cmd == 1:
        # Sused žiada o naše routes - pošleme mu full update
        iface = interfaces.get(recv_iface_label)
        if iface:
            try:
                _send_rip_update_on_iface(iface)
            except Exception:
                pass
        return
    
    # Handle RIP Response (cmd=2)
    if cmd != 2:
        return
    
    entries = _rip_parse_entries(raw)
    # neighbor IP: source IP of packet
    src_ip = pkt[IP].src
    
    # Ignore our own packets (echo) - check if src_ip is one of our interfaces
    for iface_obj in interfaces.values():
        if iface_obj.virt_ip and iface_obj.virt_ip == src_ip:
            return  # This is our own packet, ignore it
    
    with rt_lock:
        changed = False
        for ent in entries:
            net = ent['net']
            recv_metric = ent['metric']
            # Ignore routes with metric >= 16 (unreachable)
            if recv_metric >= RIP_INFINITY:
                # If we have learned this route from this neighbor, mark as unreachable / schedule flush
                for r in routing_table:
                    if r['type'] == 'dynamic' and r['net'] == net and r.get('installed_from') == recv_iface_label and r.get('next_hop') == src_ip:
                        # mark unreachable
                        r['metric'] = RIP_INFINITY
                        r['timeout'] = time.time() + RIP_FLUSH_TIMER
                        r['changed'] = True
                        changed = True
                continue
            new_metric = min(RIP_INFINITY, recv_metric + 1)
            # If we have a static or connected route covering same prefix, ignore learned route (prefer static/connected)
            skip = False
            for r in routing_table:
                if r['net'] == net and r['type'] in ('static','connected'):
                    skip = True
                    break
            if skip:
                continue
            # See if we already have an entry for this network from this neighbor
            found = None
            for r in routing_table:
                if r['net'] == net and r.get('type') == 'dynamic' and r.get('next_hop') == src_ip and r.get('installed_from') == recv_iface_label:
                    found = r
                    break
            if found:
                # update metric/timer if changed or improved
                if found.get('metric') != new_metric:
                    found['metric'] = new_metric
                    found['timeout'] = time.time() + RIP_INVALID_TIMER
                    found['changed'] = True
                    changed = True
                else:
                    found['timeout'] = time.time() + RIP_INVALID_TIMER
            else:
                # See if we have an existing route to same net from a different neighbor
                existing_dynamic = None
                for r in routing_table:
                    if r['net'] == net and r.get('type') == 'dynamic':
                        # Found existing dynamic route (from different neighbor since found == None)
                        existing_dynamic = r
                        break
                
                if existing_dynamic:
                    # Compare metrics: only replace if new route is strictly better
                    if new_metric < existing_dynamic.get('metric', RIP_INFINITY):
                        # New route is better, remove old and add new
                        routing_table[:] = [r for r in routing_table if not (r['net'] == net and r['type'] == 'dynamic')]
                        new_entry = {'net': net, 'iface': recv_iface_label, 'next_hop': src_ip, 'type': 'dynamic',
                                     'metric': new_metric, 'timeout': time.time() + RIP_INVALID_TIMER,
                                     'installed_from': recv_iface_label, 'changed': True}
                        routing_table.append(new_entry)
                        changed = True
                    # else: existing route is better or equal, keep it (do nothing)
                else:
                    # No existing dynamic route for this network, add new route
                    new_entry = {'net': net, 'iface': recv_iface_label, 'next_hop': src_ip, 'type': 'dynamic',
                                 'metric': new_metric, 'timeout': time.time() + RIP_INVALID_TIMER,
                                 'installed_from': recv_iface_label, 'changed': True}
                    routing_table.append(new_entry)
                    changed = True
        # optionally trigger an immediate update on change (triggered update)
    if changed:
        # mark changed and trigger send soon (best-effort)
        for iface in interfaces.values():
            if iface.rip_enabled:
                # send immediate split-horizon-aware update
                try:
                    _send_rip_update_on_iface(iface)
                except Exception:
                    pass

# Threads: sniffers, forwarders, RIP sender/listener 

def start_sniffer(iface: Iface):
    """ARP sniffer with PROXY ARP support."""
    def handle(pkt, local_iface=iface):
        if not pkt.haslayer(ARP):
            return
        arp = pkt.getlayer(ARP)
        
        # 1. Ignoruj vlastné pakety
        if arp.hwsrc == local_iface.mac:
            return
            
        # Learn ARP replies
        if arp.op == 2 and arp.psrc and arp.hwsrc:
            arp_update(arp.psrc, arp.hwsrc)
            return
            
        # Handle ARP requests (Who has X?)
        if arp.op == 1:
            target_ip = arp.pdst
            
            should_reply = False
            
            # A) Je to pre mňa? (Moja Virt IP)
            if local_iface.virt_ip and target_ip == local_iface.virt_ip:
                should_reply = True
            
            # B) PROXY ARP: Je to pre niekoho, koho poznám v routovacej tabuľke?
            # Ak to HP hľadá 10.0.0.2 a my vieme, že 10.0.0.2 je za druhým portom,
            # musíme odpovedať našou MAC adresou.
            else:
                # Pozrieme sa do routovacej tabuľky
                route, _ = route_lookup(target_ip)
                if route:
                    # Ak trasa existuje a nesmeruje späť na tento istý interface
                    # (Teda cieľ je niekde inde, za nami)
                    if route.get('iface') != local_iface.label:
                        print(f"{local_iface.label}: Answering for {target_ip} (route exists via {route.get('iface')})")
                        should_reply = True

            if should_reply:
                my_mac = local_iface.mac
                reply = Ether(dst=arp.hwsrc, src=my_mac) / ARP(
                    op=2,
                    hwsrc=my_mac,
                    psrc=target_ip,
                    hwdst=arp.hwsrc,
                    pdst=arp.psrc
                )
                if len(reply) < 60:
                    reply = reply / Padding(load=b'\x00' * (60 - len(reply)))
                
                sendp(reply, iface=local_iface.phys, verbose=False)
                
                if arp.psrc and arp.hwsrc:
                    arp_update(arp.psrc, arp.hwsrc)
                return

    def loop():
        while not iface._stop.is_set():
            try:
                # Filter 'arp' je nutný pre výkon
                sniff(iface=iface.phys, prn=handle, filter="arp", store=False, timeout=1)
            except Exception:
                time.sleep(1)
    t = threading.Thread(target=loop, daemon=True)
    iface.sniffer = t
    t.start()

def start_ip_forwarder(iface: Iface):
    def handle(pkt, in_iface=iface):
        if not pkt.haslayer(IP):
            return
        
        # 1. Loop prevention (podľa Source MAC)
        src_mac = pkt[Ether].src
        if src_mac in [i.mac for i in interfaces.values()]:
            return
            
        ip_layer = pkt.getlayer(IP)
        dst = ip_layer.dst
        
        # 2. Ping na Router (Local)
        for iface_obj in interfaces.values():
            if iface_obj.virt_ip and iface_obj.virt_ip == dst:
                if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                    icmp_id = pkt[ICMP].id
                    icmp_seq = pkt[ICMP].seq
                    payload = pkt[ICMP].payload
                    
                    reply = Ether(dst=src_mac, src=in_iface.mac) / \
                            IP(src=dst, dst=pkt[IP].src, ttl=64) / \
                            ICMP(type=0, code=0, id=icmp_id, seq=icmp_seq) / \
                            payload
                    
                    if len(reply) < 60:
                        reply = reply / Padding(load=b'\x00' * (60 - len(reply)))
                            
                    try:
                        sendp(reply, iface=in_iface.phys, verbose=False)
                        print(f"[PING LOCAL] Reply sent to {pkt[IP].src}")
                    except Exception:
                        pass
                return
        
        # 3. NAT Pre-processing for Outside ->Inside traffic
        # Must translate BEFORE route lookup so we route to the correct inside destination
        nat_translated = False
        translated_dst = dst
        
        if nat_enabled and nat_if_type.get(in_iface.label) == 'outside':
            inside_ifaces = [lbl for lbl, typ in nat_if_type.items() if typ == 'inside']
            if inside_ifaces:
                # Translation with a temporary out_iface (any inside interface)
                # The routing will determine the real out_iface
                temp_out_iface = interfaces.get(inside_ifaces[0])
                if temp_out_iface:
                    translated = _translate_outside_to_inside(pkt, in_iface, temp_out_iface)
                    if translated and translated[IP].dst != dst:
                        pkt = translated
                        translated_dst = pkt[IP].dst
                        nat_translated = True
        
        # 4. Routing Lookup (using possibly translated destination)
        route, arp_target = route_lookup(translated_dst)
        if not route:
            return
            
        out_iface_label = route.get('iface')
        if not out_iface_label or out_iface_label == in_iface.label:
            return
            
        out_iface = interfaces.get(out_iface_label)
        if not out_iface:
            return
        
        # 5. NAT Translation for Inside -> Outside traffic
        # This happens after route lookup (correct for outbound traffic)
        if nat_enabled and not nat_translated:
            if nat_if_type.get(in_iface.label) == 'inside' and nat_if_type.get(out_iface.label) == 'outside':
                translated = _translate_inside_to_outside(pkt, in_iface, out_iface)
                if translated:
                    pkt = translated
        
        # 6. ARP Resolution
        # For NAT-translated packets, we need to ARP for the translated destination
        if nat_translated:
            nh = translated_dst
        else:
            nh = arp_target or dst
            
        with arp_lock:
            arp_entry = arp_table.get(nh)
            
        if arp_entry is None:
            # Ak nemáme MAC, pošleme ARP Request a paket zahodíme (PC1 pošle ďalší)
            send_arp_request(out_iface, nh)
            return
            
        dst_mac = arp_entry['mac']
        out_src_mac = out_iface.mac

        # 7. Processing packet (TTL + Checksums)
        
        # TTL Check
        if pkt[IP].ttl <= 1:
            # Tu by sa mal poslať ICMP Time Exceeded, ale stačí zahodiť
            return

        # Vytvoríme kópiu IP vrstvy
        ip_payload = pkt[IP].copy()
        ip_payload.ttl -= 1
        
        # Recalculate checksums
        del ip_payload.chksum          # IP Checksum
        if hasattr(ip_payload, "len"):
            del ip_payload.len         # IP Length
            
        if ip_payload.haslayer(UDP):
            del ip_payload[UDP].chksum # UDP Checksum
            
        if ip_payload.haslayer("TCP"):
            del ip_payload["TCP"].chksum # TCP Checksum
            
        if ip_payload.haslayer(ICMP):
            del ip_payload[ICMP].chksum

        # Rebuild the packet
        new_pkt = Ether(src=out_src_mac, dst=dst_mac) / ip_payload

        try:
            sendp(new_pkt, iface=out_iface.phys, verbose=False)
            # print(f"[FWD] {pkt[IP].src} -> {dst} via {out_iface.label}")
        except Exception as e:
            print(f"Send error: {e}")

    def loop():
        while not iface._stop.is_set():
            try:
                sniff(iface=iface.phys, prn=handle, filter="ip", store=False, timeout=1)
            except Exception:
                time.sleep(1)
    t = threading.Thread(target=loop, daemon=True)
    iface.forwarder = t
    t.start()
    return t

def stop_sniffer(iface: Iface):
    iface._stop.set()
    if iface.sniffer:
        iface.sniffer.join(timeout=2)
    if iface.forwarder:
        iface.forwarder.join(timeout=2)
    # stop RIP thread
    if iface.rip_thread:
        try:
            iface.rip_thread.join(timeout=2)
        except Exception:
            pass

def send_arp_request(from_iface: Iface, target_ip: str):
    if from_iface.virt_ip is None:
        print(f"[WARN] Interface {from_iface.label} has no IP set, skipping ARP request")
        return
    
    # Use cached MAC
    src_mac = from_iface.mac
    if src_mac == "00:00:00:00:00:00":
         try:
             src_mac = get_if_hwaddr(from_iface.phys)
         except Exception:
             pass

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / ARP(
        op=1,
        hwsrc=src_mac,
        psrc=from_iface.virt_ip,
        hwdst="00:00:00:00:00:00",
        pdst=target_ip
    ) / Padding(load=b'\x00'*18)
    
    try:
        sendp(pkt, iface=from_iface.phys, verbose=False)
    except Exception as e:
        print(f"Error sending ARP request: {e}")

# RIPv2 threads 

def _rip_listener_loop(iface: Iface):
    # sniff UDP port 520 on iface and process RIPv2 packets
    def handle(pkt, local_iface=iface):
        if not pkt.haslayer(UDP):
            return
        udp = pkt.getlayer(UDP)
        # only interested in packets with port 520 on either src or dst
        if udp.sport != RIP_PORT and udp.dport != RIP_PORT:
            return
        try:
            _process_incoming_rip(pkt, local_iface.label)
        except Exception:
            pass
    while not iface._stop.is_set():
        try:
            # Added promisc=1 to capture multicast packets
            sniff(iface=iface.phys, prn=handle, store=False, timeout=1, filter=f"udp and port {RIP_PORT}", promisc=1)
        except Exception as e:
            print(f"[RIP listener:{iface.label}] error: {e}")
            time.sleep(1)

def _rip_periodic_sender():
    while True:
        for iface in list(interfaces.values()):
            if iface.rip_enabled and iface.virt_ip:
                try:
                    _send_rip_update_on_iface(iface)
                except Exception:
                    pass
        time.sleep(RIP_UPDATE_INTERVAL)

# GUI

class App:
    def __init__(self, root):
        self.root = root
        root.title("SWRouter")
        root.geometry("1050x750")  # Set reasonable window size
        
        # Create scrollable container
        main_canvas = Canvas(root)
        scrollbar = Scrollbar(root, orient=VERTICAL, command=main_canvas.yview)
        self.scrollable_frame = Frame(main_canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollbar and canvas
        scrollbar.pack(side=RIGHT, fill=Y)
        main_canvas.pack(side=LEFT, fill=BOTH, expand=True)
        
        # Enable mouse wheel scrolling
        def _on_mousewheel(event):
            main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        main_canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Get available interfaces
        self.available_ifaces = get_available_interfaces()
        print(f"Available interfaces: {self.available_ifaces}")
        
        # Initialize with first two available interfaces (or same if only one)
        default_iface1 = self.available_ifaces[0] if self.available_ifaces else "en0"
        default_iface2 = self.available_ifaces[1] if len(self.available_ifaces) > 1 else default_iface1
        
        # Create interface objects (but don't start sniffers yet - wait for user to select)
        interfaces["port1"] = Iface(label="port1", phys_iface=None)
        interfaces["port2"] = Iface(label="port2", phys_iface=None)
        
        # Start global RIP sender thread
        t = threading.Thread(target=_rip_periodic_sender, daemon=True)
        t.start()

        # Layout - use scrollable_frame instead of root
        self.if_frame = Frame(self.scrollable_frame)
        self.if_frame.pack(fill=X, padx=6, pady=6)
        self.if_widgets = {}

        for idx, label in enumerate(("port1", "port2")):
            f = LabelFrame(self.if_frame, text=label)
            f.pack(side=LEFT, padx=6, pady=6, fill=BOTH, expand=True)
            
            # Physical interface selection dropdown
            Label(f, text="Interface:").grid(row=0, column=0, sticky=W)
            iface_var = StringVar(value="-- Select --")
            iface_menu = OptionMenu(f, iface_var, "-- Select --", *self.available_ifaces,
                                   command=lambda v, L=label: self.change_physical_iface(L))
            iface_menu.config(width=12)
            iface_menu.grid(row=0, column=1, sticky=W)
            
            # MAC address label (will update when interface is selected)
            mac_label = Label(f, text="MAC: --")
            mac_label.grid(row=1, column=0, columnspan=2, sticky=W)
            
            # Virtual IP configuration
            Label(f, text="Virt IP:").grid(row=2, column=0, sticky=W)
            ip_e = Entry(f, width=18)
            ip_e.grid(row=2, column=1)
            Label(f, text="Netmask:").grid(row=3, column=0, sticky=W)
            mask_e = Entry(f, width=18)
            mask_e.grid(row=3, column=1)
            mask_e.insert(0, "255.255.255.0")
            Button(f, text="Apply IP", command=lambda L=label: self.apply_iface(L)).grid(row=4, column=0, columnspan=2, pady=4)
            
            # RIP enable checkbox
            rip_var = IntVar(value=0)
            cb = Checkbutton(f, text="RIP v2", variable=rip_var, command=lambda v=rip_var, L=label: self.toggle_rip(L, v))
            cb.grid(row=5, column=0, columnspan=2)
            
            # Status label
            status_label = Label(f, text="Status: Not connected", fg="gray")
            status_label.grid(row=6, column=0, columnspan=2, sticky=W)
            
            self.if_widgets[label] = {
                "ip": ip_e, 
                "mask": mask_e, 
                "rip_var": rip_var,
                "iface_var": iface_var,
                "mac_label": mac_label,
                "status_label": status_label
            }

        # ARP request button
        arp_frame = LabelFrame(self.scrollable_frame, text="ARP request (who-has)")
        arp_frame.pack(fill=X, padx=6, pady=6)
        Label(arp_frame, text="From:").grid(row=0, column=0, sticky=W)
        self.arp_from = StringVar(value="port1")
        OptionMenu(arp_frame, self.arp_from, "port1", "port2").grid(row=0, column=1)
        Label(arp_frame, text="Target IP:").grid(row=0, column=2, sticky=W)
        self.arp_target = Entry(arp_frame, width=18)
        self.arp_target.grid(row=0, column=3)
        Button(arp_frame, text="Send ARP", command=self.arp_send).grid(row=0, column=4, padx=6)

        # TTL 
        ttl_frame = Frame(self.scrollable_frame)
        ttl_frame.pack(fill=X, padx=6, pady=2)
        Label(ttl_frame, text="ARP TTL (s):").pack(side=LEFT)
        self.ttl_entry = Entry(ttl_frame, width=6)
        self.ttl_entry.pack(side=LEFT, padx=4)
        self.ttl_entry.insert(0, str(arp_ttl))
        Button(ttl_frame, text="Confirm TTL", command=self.confirm_ttl).pack(side=LEFT, padx=4)

        # RIP timers
        rip_timer_frame = LabelFrame(self.scrollable_frame, text="RIP Timers (seconds)")
        rip_timer_frame.pack(fill=X, padx=6, pady=6)
        
        Label(rip_timer_frame, text="Update:").grid(row=0, column=0, sticky=W, padx=4)
        self.rip_update_entry = Entry(rip_timer_frame, width=6)
        self.rip_update_entry.grid(row=0, column=1, padx=2)
        self.rip_update_entry.insert(0, str(RIP_UPDATE_INTERVAL))
        
        Label(rip_timer_frame, text="Invalid:").grid(row=0, column=2, sticky=W, padx=4)
        self.rip_invalid_entry = Entry(rip_timer_frame, width=6)
        self.rip_invalid_entry.grid(row=0, column=3, padx=2)
        self.rip_invalid_entry.insert(0, str(RIP_INVALID_TIMER))
        
        Label(rip_timer_frame, text="Flush:").grid(row=0, column=4, sticky=W, padx=4)
        self.rip_flush_entry = Entry(rip_timer_frame, width=6)
        self.rip_flush_entry.grid(row=0, column=5, padx=2)
        self.rip_flush_entry.insert(0, str(RIP_FLUSH_TIMER))
        
        Button(rip_timer_frame, text="Apply RIP Timers", command=self.apply_rip_timers).grid(row=0, column=6, padx=6)


        # routing GUI init
        self._init_routing_gui()
        
        # ARP table
        arp_table_frame = LabelFrame(self.scrollable_frame, text="ARP Cache")
        arp_table_frame.pack(fill=X, padx=6, pady=3)
        
        table_inner = Frame(arp_table_frame)
        table_inner.pack(fill=X, padx=4, pady=2)
        
        self.tree = ttk.Treeview(table_inner, columns=("ip", "mac", "age"), show="headings", height=3)
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("age", text="Age(s)")
        self.tree.column("ip", width=120)
        self.tree.column("mac", width=140)
        self.tree.column("age", width=60, anchor=CENTER)
        self.tree.pack(fill=X, side=LEFT)
        scrollbar = Scrollbar(table_inner, orient=VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.tree.configure(yscroll=scrollbar.set)
        
        # Button frame for ARP actions
        btn_frame = Frame(arp_table_frame)
        btn_frame.pack(fill=X, padx=4, pady=2)
        Button(btn_frame, text="Clear ARP Cache", command=lambda: self.delete_selected(all=True)).pack(side=LEFT)
        Button(btn_frame, text="Delete Selected", command=lambda: self.delete_selected(all=False)).pack(side=LEFT, padx=6)
        
        # NAT GUI init
        self._init_nat_gui()

        self._running = True
        self.root.after(1000, self.periodic)

    # Handlers
    def change_physical_iface(self, label):
        """Change the physical interface for a port"""
        w = self.if_widgets[label]
        selected = w["iface_var"].get()
        
        if selected == "-- Select --":
            return
        
        obj = interfaces[label]
        
        # Stop existing sniffers/forwarders if running
        if obj.phys is not None:
            obj._stop.set()
            if obj.sniffer:
                try:
                    obj.sniffer.join(timeout=1)
                except:
                    pass
            if obj.forwarder:
                try:
                    obj.forwarder.join(timeout=1)
                except:
                    pass
            if obj.rip_thread:
                try:
                    obj.rip_thread.join(timeout=1)
                except:
                    pass
        
        # Update the interface
        obj.phys = selected
        obj._stop = threading.Event()  # Reset stop event
        obj.mac = _get_mac_robust(selected)
        obj.sniffer = None
        obj.forwarder = None
        obj.rip_thread = None
        
        # Start new sniffers/forwarders
        start_sniffer(obj)
        obj.forwarder = start_ip_forwarder(obj)
        
        # If RIP was enabled, restart RIP listener
        if obj.rip_enabled:
            t = threading.Thread(target=_rip_listener_loop, args=(obj,), daemon=True)
            obj.rip_thread = t
            t.start()
        
        # Update UI
        w["mac_label"].config(text=f"MAC: {obj.mac}")
        w["status_label"].config(text=f"Status: Connected ({selected})", fg="green")
        
        print(f"{label} now using interface: {selected} (MAC: {obj.mac})")

    def apply_iface(self, label):
        w = self.if_widgets[label]
        obj = interfaces[label]
        
        # Check if physical interface is selected
        if obj.phys is None:
            messagebox.showwarning("Warning", f"Please select a physical interface for {label} first")
            return
        
        old_net = _make_iface_network(obj)
        ip = w["ip"].get().strip()
        mask = w["mask"].get().strip()
        obj.virt_ip = ip if ip else None
        obj.netmask = mask if mask else None
        if old_net is not None:
            tmp = Iface(label=obj.label, phys_iface=obj.phys)
            tmp.virt_ip = str(old_net.network_address)
            tmp.netmask = str(old_net.netmask)
            remove_connected_route_for_iface(tmp)
        add_connected_route_for_iface(obj)
        messagebox.showinfo("Applied", f"{label}: {obj.virt_ip}/{obj.netmask} on {obj.phys}")
        try:
            self.update_rt_view()
        except Exception:
            pass

    def toggle_rip(self, label, var):
        v = var.get()
        iface = interfaces[label]
        iface.rip_enabled = bool(v)
        if iface.rip_enabled:
            # start listener thread for this iface
            if iface.rip_thread is None or not iface.rip_thread.is_alive():
                t = threading.Thread(target=_rip_listener_loop, args=(iface,), daemon=True)
                iface.rip_thread = t
                t.start()
            # send immediate update on enabling
            try:
                _send_rip_update_on_iface(iface)
            except Exception:
                pass
        else:
            # disabling RIP: remove dynamic routes learned from this iface
            with rt_lock:
                routing_table[:] = [r for r in routing_table if not (r.get('type') == 'dynamic' and r.get('installed_from') == label)]

    def arp_send(self):
        frm = self.arp_from.get()
        tgt = self.arp_target.get().strip()
        if frm not in interfaces:
            messagebox.showwarning("Invalid", "Invalid interface selected")
            return
        if not tgt:
            messagebox.showwarning("Invalid", "Target IP empty")
            return
        send_arp_request(interfaces[frm], tgt)

    def confirm_ttl(self):
        global arp_ttl
        try:
            arp_ttl = int(self.ttl_entry.get())
        except ValueError:
            arp_ttl = 120
        messagebox.showinfo("ARP TTL", f"ARP TTL updated to {arp_ttl} seconds")

    def apply_rip_timers(self):
        global RIP_UPDATE_INTERVAL, RIP_INVALID_TIMER, RIP_FLUSH_TIMER
        try:
            update = int(self.rip_update_entry.get())
            invalid = int(self.rip_invalid_entry.get())
            flush = int(self.rip_flush_entry.get())
            
            if update <= 0 or invalid <= 0 or flush <= 0:
                messagebox.showwarning("Invalid", "Timers must be positive integers")
                return
            
            if invalid <= update:
                messagebox.showwarning("Invalid", "Invalid timer should be greater than Update timer")
                return
            
            if flush <= invalid:
                messagebox.showwarning("Invalid", "Flush timer should be greater than Invalid timer")
                return
            
            RIP_UPDATE_INTERVAL = update
            RIP_INVALID_TIMER = invalid
            RIP_FLUSH_TIMER = flush
            messagebox.showinfo("RIP Timers", f"RIP timers updated:\nUpdate: {update}s\nInvalid: {invalid}s\nFlush: {flush}s")
        except ValueError:
            messagebox.showwarning("Invalid", "Please enter valid integer values")

    def periodic(self):
        now = time.time()
        with arp_lock:
            expired = [ip for ip, v in arp_table.items() if now - v["ts"] > arp_ttl]
            for ip in expired:
                del arp_table[ip]
        snap = arp_snapshot()
        # Store current selection
        selected = self.tree.selection()
        for r in self.tree.get_children():
            self.tree.delete(r)
        for ip, info in sorted(snap.items()):
            age = int(now - info["ts"])
            self.tree.insert("", "end", iid=ip, values=(ip, info["mac"], str(age)))
        # Restore selection if still valid
        for sel in selected:
            if sel in self.tree.get_children():
                self.tree.selection_add(sel)
        # routing dynamic timers: invalidate/flush dynamic routes
        with rt_lock:
            changed = False
            now = time.time()
            new_rt = []
            for r in routing_table:
                if r.get('type') == 'dynamic':
                    timeout = r.get('timeout', 0)
                    if r.get('metric', RIP_INFINITY) >= RIP_INFINITY and timeout and now >= timeout:
                        # flush expired unreachable route
                        changed = True
                        continue
                    if timeout and now >= timeout:
                        # mark unreachable (set metric to >=16) and set flush timeout
                        r['metric'] = RIP_INFINITY
                        r['timeout'] = now + RIP_FLUSH_TIMER
                        r['changed'] = True
                        new_rt.append(r)
                        changed = True
                        continue
                new_rt.append(r)
            routing_table[:] = new_rt
        if changed:
            # send triggered updates if any
            for iface in interfaces.values():
                if iface.rip_enabled:
                    try:
                        _send_rip_update_on_iface(iface)
                    except Exception:
                        pass
        
        # NAT timeout cleanup
        with nat_lock:
            # Clean up expired PAT entries
            expired_pat = []
            for key, (outside_ip, outside_port, ts) in pat_table.items():
                inside_ip, inside_port, proto = key
                timeout = _get_protocol_timeout(proto)
                if now - ts > timeout:
                    expired_pat.append(key)
            for key in expired_pat:
                del pat_table[key]
            
            # Clean up expired dynamic NAT allocations
            expired_dyn = []
            for inside_local, (inside_global, ts) in dynamic_nat_allocations.items():
                if now - ts > NAT_TCP_TIMEOUT:
                    expired_dyn.append(inside_local)
            for inside_local in expired_dyn:
                del dynamic_nat_allocations[inside_local]
        
        try:
            self.update_rt_view()
            self.update_nat_gui()
        except Exception:
            pass
        if self._running:
            self.root.after(1000, self.periodic)

    def delete_selected(self, all=False):
        if all:
            arp_remove(None)
            for r in self.tree.get_children():
                self.tree.delete(r)
            return
        sel = self.tree.selection()
        if not sel:
            return
        for ip in sel:
            arp_remove(ip)
            try:
                self.tree.delete(ip)
            except:
                pass

    def shutdown(self):
        self._running = False
        for obj in interfaces.values():
            stop_sniffer(obj)

    # Routing GUI and handlers
    def _init_routing_gui(self):
        rt_frame = LabelFrame(self.scrollable_frame, text="Static / Dynamic Routes")
        rt_frame.pack(fill=X, padx=6, pady=6)
        Label(rt_frame, text="Dest:").grid(row=0, column=0, sticky=W)
        self.rt_dest = Entry(rt_frame, width=15); self.rt_dest.grid(row=0, column=1)
        Label(rt_frame, text="Mask:").grid(row=0, column=2, sticky=W)
        self.rt_mask = Entry(rt_frame, width=15); self.rt_mask.grid(row=0, column=3)
        Label(rt_frame, text="Out Iface:").grid(row=0, column=4, sticky=W)
        self.rt_iface = StringVar(value="")
        OptionMenu(rt_frame, self.rt_iface, "", "port1", "port2").grid(row=0, column=5)
        Label(rt_frame, text="Next Hop:").grid(row=0, column=6, sticky=W)
        self.rt_nh = Entry(rt_frame, width=15); self.rt_nh.grid(row=0, column=7)
        Button(rt_frame, text="Add Route", command=self.add_route).grid(row=0, column=8, padx=6)
        Button(rt_frame, text="Remove Route", command=self.remove_route).grid(row=0, column=9, padx=6)

        # Table for displaying routes (includes Dest)
        self.rt_tree = ttk.Treeview(rt_frame, columns=("dest","mask", "iface", "nh", "type", "metric"), show="headings", height=4)
        self.rt_tree.heading("dest", text="Dest")
        self.rt_tree.heading("mask", text="Mask")
        self.rt_tree.heading("iface", text="Iface")
        self.rt_tree.heading("nh", text="NextHop")
        self.rt_tree.heading("type", text="Type")
        self.rt_tree.heading("metric", text="Metric")
        self.rt_tree.column("dest", width=140)
        self.rt_tree.column("mask", width=120)
        self.rt_tree.column("iface", width=80)
        self.rt_tree.column("nh", width=120)
        self.rt_tree.column("type", width=80)
        self.rt_tree.column("metric", width=60)
        self.rt_tree.grid(row=1, column=0, columnspan=10, sticky="ew", pady=4)
        self.update_rt_view()

    def add_route(self):
        dest = self.rt_dest.get().strip()
        mask = self.rt_mask.get().strip()
        iface = self.rt_iface.get().strip()
        nh = self.rt_nh.get().strip() or None
        if not dest or not mask:
            messagebox.showwarning("Invalid", "Destination and mask required")
            return
        if not add_static_route(dest, mask, iface or None, nh):
            messagebox.showerror("Error", "Invalid route")
            return
        messagebox.showinfo("Added", f"Route to {dest}/{mask} added")
        self.update_rt_view()

    def remove_route(self):
        dest = self.rt_dest.get().strip()
        mask = self.rt_mask.get().strip()
        iface = self.rt_iface.get().strip()
        nh = self.rt_nh.get().strip() or None
        if not dest or not mask:
            messagebox.showwarning("Invalid", "Destination and mask required")
            return
        if remove_static_route(dest, mask, iface or None, nh):
            messagebox.showinfo("Removed", f"Route to {dest}/{mask} removed")
        else:
            messagebox.showwarning("Not Found", "Matching route not found")
        self.update_rt_view()

    def update_rt_view(self):
        # Store currently selected routes by their content (dest/mask/iface/nexthop)
        selected_routes = []
        for item_id in self.rt_tree.selection():
            values = self.rt_tree.item(item_id, 'values')
            if values:
                # Store tuple of (dest, mask, iface, next_hop) to uniquely identify route
                selected_routes.append((values[0], values[1], values[2], values[3]))
        
        # Clear and repopulate tree
        for r in self.rt_tree.get_children():
            self.rt_tree.delete(r)
        
        # Insert routes and restore selection
        for r in route_snapshot():
            route_key = (f"{r['dest']}/{r['prefix']}", r["mask"], r["iface"], r["next_hop"])
            item_id = self.rt_tree.insert("", "end", values=(route_key[0], route_key[1], route_key[2], route_key[3], r["type"], r.get('metric','')))
            
            # If this route was previously selected, select it again
            if route_key in selected_routes:
                self.rt_tree.selection_add(item_id)

    # NAT GUI and handlers
    def _init_nat_gui(self):
        """Initialize NAT GUI components"""
        nat_frame = LabelFrame(self.scrollable_frame, text="NAT Configuration")
        nat_frame.pack(fill=BOTH, expand=True, padx=6, pady=6)
        
        # Enable/Disable NAT + Clear button
        control_frame = Frame(nat_frame)
        control_frame.pack(fill=X, padx=6, pady=6)
        self.nat_enabled_var = IntVar(value=0)
        Checkbutton(control_frame, text="Enable NAT", variable=self.nat_enabled_var, 
                    command=self.toggle_nat).pack(side=LEFT)
        Button(control_frame, text="Clear NAT Table", command=self.clear_nat).pack(side=LEFT, padx=6)
        
        # Interface type configuration
        if_type_frame = LabelFrame(nat_frame, text="Interface Types")
        if_type_frame.pack(fill=X, padx=6, pady=6)
        for idx, label in enumerate(["port1", "port2"]):
            Label(if_type_frame, text=f"{label}:").grid(row=0, column=idx*2, sticky=W, padx=4)
            var = StringVar(value="none")
            om = OptionMenu(if_type_frame, var, "none", "inside", "outside", 
                       command=lambda v, L=label, V=var: self.set_if_type(L, V))
            om.grid(row=0, column=idx*2+1, padx=4)
            setattr(self, f"nat_if_type_{label}", var)
        
        # Tabbed interface for different NAT types
        notebook = ttk.Notebook(nat_frame)
        notebook.pack(fill=BOTH, expand=True, padx=6, pady=6)
        
        # Static NAT tab
        static_frame = Frame(notebook)
        notebook.add(static_frame, text="Static NAT")
        Label(static_frame, text="Inside Local:").grid(row=0, column=0, sticky=W, padx=2)
        self.static_inside = Entry(static_frame, width=15)
        self.static_inside.grid(row=0, column=1, padx=2)
        Label(static_frame, text="Inside Global:").grid(row=0, column=2, sticky=W, padx=2)
        self.static_global = Entry(static_frame, width=15)
        self.static_global.grid(row=0, column=3, padx=2)
        Button(static_frame, text="Add", command=self.add_static_nat).grid(row=0, column=4, padx=4)
        Button(static_frame, text="Remove", command=self.remove_static_nat).grid(row=0, column=5)
        
        # Static NAT list
        self.static_tree = ttk.Treeview(static_frame, columns=("inside", "outside"), show="headings", height=4)
        self.static_tree.heading("inside", text="Inside Local")
        self.static_tree.heading("outside", text="Inside Global")
        self.static_tree.grid(row=1, column=0, columnspan=6, sticky="ew", pady=4)
        
        # Dynamic NAT Pool tab
        pool_frame = Frame(notebook)
        notebook.add(pool_frame, text="Dynamic NAT Pool")
        Label(pool_frame, text="Global IP:").grid(row=0, column=0, sticky=W, padx=2)
        self.pool_ip = Entry(pool_frame, width=15)
        self.pool_ip.grid(row=0, column=1, padx=2)
        Button(pool_frame, text="Add to Pool", command=self.add_pool_ip).grid(row=0, column=2, padx=4)
        Button(pool_frame, text="Remove from Pool", command=self.remove_pool_ip).grid(row=0, column=3)
        
        # Pool list
        self.pool_tree = ttk.Treeview(pool_frame, columns=("ip",), show="headings", height=4)
        self.pool_tree.heading("ip", text="Available Global IPs")
        self.pool_tree.grid(row=1, column=0, columnspan=4, sticky="ew", pady=4)
        
        # Port Forwarding tab
        pf_frame = Frame(notebook)
        notebook.add(pf_frame, text="Port Forwarding")
        Label(pf_frame, text="Outside IP:").grid(row=0, column=0, sticky=W, padx=2)
        self.pf_outside_ip = Entry(pf_frame, width=12)
        self.pf_outside_ip.grid(row=0, column=1, padx=2)
        Label(pf_frame, text="Port:").grid(row=0, column=2, sticky=W, padx=2)
        self.pf_outside_port = Entry(pf_frame, width=6)
        self.pf_outside_port.grid(row=0, column=3, padx=2)
        Label(pf_frame, text="→ Inside IP:").grid(row=0, column=4, sticky=W, padx=2)
        self.pf_inside_ip = Entry(pf_frame, width=12)
        self.pf_inside_ip.grid(row=0, column=5, padx=2)
        Label(pf_frame, text="Port:").grid(row=0, column=6, sticky=W, padx=2)
        self.pf_inside_port = Entry(pf_frame, width=6)
        self.pf_inside_port.grid(row=0, column=7, padx=2)
        Label(pf_frame, text="Proto:").grid(row=0, column=8, sticky=W, padx=2)
        self.pf_proto = StringVar(value="TCP")
        OptionMenu(pf_frame, self.pf_proto, "TCP", "UDP").grid(row=0, column=9, padx=2)
        Button(pf_frame, text="Add", command=self.add_port_forward).grid(row=0, column=10, padx=4)
        Button(pf_frame, text="Remove", command=self.remove_port_forward).grid(row=0, column=11)
        
        # Port forwarding list
        self.pf_tree = ttk.Treeview(pf_frame, columns=("outside", "inside", "proto"), show="headings", height=4)
        self.pf_tree.heading("outside", text="Outside")
        self.pf_tree.heading("inside", text="Inside")
        self.pf_tree.heading("proto", text="Protocol")
        self.pf_tree.grid(row=1, column=0, columnspan=12, sticky="ew", pady=4)
        
        # NAT Translation Table tab
        trans_frame = Frame(notebook)
        notebook.add(trans_frame, text="Translation Table")
        
        Label(trans_frame, text="PAT Translations:", font=("", 10, "bold")).pack(anchor=W, pady=2)
        self.pat_tree = ttk.Treeview(trans_frame, columns=("inside", "outside", "proto", "age"), show="headings", height=6)
        self.pat_tree.heading("inside", text="Inside")
        self.pat_tree.heading("outside", text="Outside")
        self.pat_tree.heading("proto", text="Protocol")
        self.pat_tree.heading("age", text="Age (s)")
        self.pat_tree.pack(fill=BOTH, expand=True, pady=2)
        
        Label(trans_frame, text="Dynamic NAT:", font=("", 10, "bold")).pack(anchor=W, pady=2)
        self.dyn_tree = ttk.Treeview(trans_frame, columns=("inside", "outside", "age"), show="headings", height=4)
        self.dyn_tree.heading("inside", text="Inside Local")
        self.dyn_tree.heading("outside", text="Inside Global")
        self.dyn_tree.heading("age", text="Age (s)")
        self.dyn_tree.pack(fill=BOTH, expand=True, pady=2)
        
        # Initial update
        self.update_nat_gui()
    
    def toggle_nat(self):
        global nat_enabled
        nat_enabled = bool(self.nat_enabled_var.get())
        status = "enabled" if nat_enabled else "disabled"
        messagebox.showinfo("NAT", f"NAT {status}")

    def set_if_type(self, label, var):
        val = var.get()
        if val == "none":
            if label in nat_if_type:
                del nat_if_type[label]
        else:
            nat_if_type[label] = val
        messagebox.showinfo("NAT", f"{label} set to {val}")

    def clear_nat(self):
        clear_nat_table()
        messagebox.showinfo("NAT", "NAT translation table cleared")
        self.update_nat_gui()

    def add_static_nat(self):
        inside = self.static_inside.get().strip()
        outside = self.static_global.get().strip()
        if not inside or not outside:
            messagebox.showwarning("Invalid", "Both IPs required")
            return
        static_nat_map[inside] = outside
        messagebox.showinfo("NAT", f"Static NAT added: {inside} → {outside}")
        self.update_nat_gui()

    def remove_static_nat(self):
        inside = self.static_inside.get().strip()
        if inside in static_nat_map:
            del static_nat_map[inside]
            messagebox.showinfo("NAT", f"Static NAT removed for {inside}")
            self.update_nat_gui()
        else:
            messagebox.showwarning("Not Found", "No such static NAT entry")

    def add_pool_ip(self):
        ip = self.pool_ip.get().strip()
        if not ip:
            messagebox.showwarning("Invalid", "IP required")
            return
        if ip not in dynamic_nat_pool:
            dynamic_nat_pool.append(ip)
            messagebox.showinfo("NAT", f"Added {ip} to pool")
            self.update_nat_gui()

    def remove_pool_ip(self):
        ip = self.pool_ip.get().strip()
        if ip in dynamic_nat_pool:
            dynamic_nat_pool.remove(ip)
            messagebox.showinfo("NAT", f"Removed {ip} from pool")
            self.update_nat_gui()
        else:
            messagebox.showwarning("Not Found", "IP not in pool")

    def add_port_forward(self):
        out_ip = self.pf_outside_ip.get().strip()
        out_port = self.pf_outside_port.get().strip()
        in_ip = self.pf_inside_ip.get().strip()
        in_port = self.pf_inside_port.get().strip()
        proto = self.pf_proto.get()
        
        if not all([out_ip, out_port, in_ip, in_port]):
            messagebox.showwarning("Invalid", "All fields required")
            return
        
        try:
            out_port = int(out_port)
            in_port = int(in_port)
            proto_num = socket.IPPROTO_TCP if proto == "TCP" else socket.IPPROTO_UDP
            key = (out_ip, out_port, proto_num)
            port_forward_map[key] = (in_ip, in_port)
            messagebox.showinfo("NAT", f"Port forwarding added: {out_ip}:{out_port} → {in_ip}:{in_port}")
            self.update_nat_gui()
        except ValueError:
            messagebox.showwarning("Invalid", "Invalid port number")

    def remove_port_forward(self):
        out_ip = self.pf_outside_ip.get().strip()
        out_port = self.pf_outside_port.get().strip()
        proto = self.pf_proto.get()
        
        if not all([out_ip, out_port]):
            messagebox.showwarning("Invalid", "Outside IP and port required")
            return
        
        try:
            out_port = int(out_port)
            proto_num = socket.IPPROTO_TCP if proto == "TCP" else socket.IPPROTO_UDP
            key = (out_ip, out_port, proto_num)
            if key in port_forward_map:
                del port_forward_map[key]
                messagebox.showinfo("NAT", "Port forwarding removed")
                self.update_nat_gui()
            else:
                messagebox.showwarning("Not Found", "No such port forwarding rule")
        except ValueError:
            messagebox.showwarning("Invalid", "Invalid port number")

    def update_nat_gui(self):
        """Update all NAT GUI components"""
        snap = nat_table_snapshot()
        
        # Update static NAT tree
        for r in self.static_tree.get_children():
            self.static_tree.delete(r)
        for entry in snap['static']:
            self.static_tree.insert("", "end", values=(entry['inside_local'], entry['inside_global']))
        
        # Update pool tree
        for r in self.pool_tree.get_children():
            self.pool_tree.delete(r)
        for ip in dynamic_nat_pool:
            self.pool_tree.insert("", "end", values=(ip,))
        
        # Update port forwarding tree
        for r in self.pf_tree.get_children():
            self.pf_tree.delete(r)
        for entry in snap['port_forward']:
            self.pf_tree.insert("", "end", values=(entry['outside'], entry['inside'], entry['proto']))
        
        # Update PAT translation tree
        for r in self.pat_tree.get_children():
            self.pat_tree.delete(r)
        for entry in snap['pat']:
            self.pat_tree.insert("", "end", values=(entry['inside'], entry['outside'], entry['proto'], entry['age']))
        
        # Update dynamic NAT tree
        for r in self.dyn_tree.get_children():
            self.dyn_tree.delete(r)
        for entry in snap['dynamic']:
            self.dyn_tree.insert("", "end", values=(entry['inside_local'], entry['inside_global'], entry['age']))


if __name__ == "__main__":
    conf.verb = 0
    try:
        conf.use_pcap = True
    except Exception:
        pass
    root = Tk()
    app = App(root)
    def on_close():
        app.shutdown()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()