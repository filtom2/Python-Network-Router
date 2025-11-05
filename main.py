import sys
import time
import threading
import random
import ipaddress
from tkinter import *
from tkinter import ttk, messagebox
from scapy.all import sniff, sendp, Ether, ARP, conf, get_if_hwaddr, IP

# 192.168.01 / 25
# 172.16.0.1 / 30
# TODO staticke routovanie, rekurzivne routovanie, proxy arp

class Iface:
    def __init__(self, label, phys_iface):
        self.label = label
        self.phys = phys_iface
        self.virt_ip = None
        self.netmask = None
        self._stop = threading.Event()
        self.sniffer = None
        self.forwarder = None  # forwarder thread handle


PORT1 = "en8"
PORT2 = "en15"

interfaces = {}
arp_table = {}
routing_table = []  # {'net': IPv4Network, 'iface': str|None, 'next_hop': str|None, 'type': 'static'|'dynamic'|'connected'}
arp_lock = threading.Lock()
arp_ttl = 120  # seconds


# ARP handling 
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


# Routing table op
def _route_equals(a, b):
    return a['net'] == b['net'] and a.get('iface') == b.get('iface') and a.get('next_hop') == b.get('next_hop') and a.get('type') == b.get('type')

def add_static_route(dest: str, mask: str, iface: str = None, next_hop: str = None):
    try:
        net = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
    except Exception:
        return False
    entry = {'net': net, 'iface': iface, 'next_hop': next_hop, 'type': 'static'}
    for r in routing_table:
        if _route_equals(r, entry):
            return True
    routing_table.append(entry)
    return True

def remove_static_route(dest: str, mask: str, iface: str = None, next_hop: str = None):
    try:
        net = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
    except Exception:
        return False
    removed = False
    new_rt = []
    for r in routing_table:
        if r['net'] == net and r['type'] == 'static':
            if (iface is None or r.get('iface') == iface) and (next_hop is None or r.get('next_hop') == next_hop):
                removed = True
                continue
        new_rt.append(r)
    routing_table[:] = new_rt
    return removed

# Route lookup
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
    candidates = []
    for r in routing_table:
        if ip in r['net']:
            candidates.append((r['net'].prefixlen, r))
    if not candidates:
        return None, None
    candidates.sort(reverse=True)
    _, route = candidates[0]
    # If the caller already specified a requested next-hop (first hop in chain), keep it
    # If this route has an iface, we're at a connected route => return iface and requested_nh or addr
    if route.get('iface'):
        arp_target = requested_nh or addr
        return route, arp_target
    # Otherwise follow next_hop recursively; propagate the first seen next_hop as requested_nh
    nh = route.get('next_hop')
    if nh:
        if nh in visited:
            return None, None
        visited.add(nh)
        # first next-hop in chain should be used as ARP target
        new_requested = requested_nh or nh
        return route_lookup(nh, requested_nh=new_requested, visited=visited)
    return None, None

def route_snapshot():
    out = []
    for r in routing_table:
        out.append({
            'dest': str(r['net'].network_address),
            'mask': str(r['net'].netmask),
            'prefix': r['net'].prefixlen,
            'iface': r.get('iface') or '',
            'next_hop': r.get('next_hop') or '',
            'type': r.get('type')
        })
    return out


# Connected routes for interfaces
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
    for r in routing_table:
        if r.get('type') == 'connected' and r['net'] == net and r.get('iface') == obj.label:
            return
    routing_table.append(entry)


def remove_connected_route_for_iface(obj: Iface):
    net = _make_iface_network(obj)
    if net is None:
        return
    routing_table[:] = [r for r in routing_table if not (r.get('type') == 'connected' and r['net'] == net and r.get('iface') == obj.label)]


def _ip_in_iface_network(target_ip: str, obj: Iface) -> bool:
    """Return True if target_ip is inside obj's configured network."""
    if not obj.virt_ip or not obj.netmask:
        return False
    try:
        net = ipaddress.ip_network(f"{obj.virt_ip}/{obj.netmask}", strict=False)
        return ipaddress.ip_address(target_ip) in net
    except Exception:
        return False


def start_sniffer(iface: Iface):
    """Sniff ARP packets and respond to queries for our virtual IP and act as proxy ARP.

    Behavior:
    - If ARP reply: learn mapping into arp_table.
    - If ARP request for one of our configured virt_ip -> reply with this interface's MAC.
    - If ARP request for IP inside *other interface's* network -> send a proxy-ARP reply (proxy on receiving iface).
    """
    def handle(pkt):
        if not pkt.haslayer(ARP):
            return
        arp = pkt.getlayer(ARP)

        # Ignore our own ARP packets
        if arp.hwsrc in [get_if_hwaddr(i.phys) for i in interfaces.values()]:
            return

        # Learn  ARP replies
        if arp.op == 2 and arp.psrc and arp.hwsrc:
            arp_update(arp.psrc, arp.hwsrc)
            return

        # Handle ARP requests
        if arp.op == 1:
            target = arp.pdst

            # 1) If it's exactly one of our configured IPs, answer from that interface
            for obj in interfaces.values():
                if obj.virt_ip is None:
                    continue
                if obj.virt_ip == target:
                    reply = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(obj.phys)) / ARP(
                        op=2,
                        hwsrc=get_if_hwaddr(obj.phys),
                        psrc=target,
                        hwdst=arp.hwsrc,
                        pdst=arp.psrc
                    )
                    sendp(reply, iface=obj.phys, verbose=False)
                    if arp.psrc and arp.hwsrc:
                        arp_update(arp.psrc, arp.hwsrc)
                    return

            # 2) Proxy ARP: if target is within network of any other interface, reply on the receiving iface
            for other in interfaces.values():
                if other == iface:
                    continue
                if other.virt_ip is None or other.netmask is None:
                    continue
                try:
                    if _ip_in_iface_network(target, other):
                        proxy_src_mac = get_if_hwaddr(iface.phys)
                        reply = Ether(dst=pkt[Ether].src, src=proxy_src_mac) / ARP(
                            op=2,
                            hwsrc=proxy_src_mac,
                            psrc=target,
                            hwdst=arp.hwsrc,
                            pdst=arp.psrc
                        )
                        sendp(reply, iface=iface.phys, verbose=False)
                        if arp.psrc and arp.hwsrc:
                            arp_update(arp.psrc, arp.hwsrc)
                        return
                except Exception:
                    continue

    def loop():
        while not iface._stop.is_set():
            try:
                sniff(iface=iface.phys, prn=handle, store=False, timeout=1)
            except Exception as e:
                print(f"[sniffer:{iface.label}] error: {e}")
                time.sleep(1)

    t = threading.Thread(target=loop, daemon=True)
    iface.sniffer = t
    t.start()


def start_ip_forwarder(iface: Iface):
    # Basic IP forwarding between interfaces using routing_table and ARP resolution
    def handle(pkt):
        if not pkt.haslayer(IP):
            return
        ip_layer = pkt.getlayer(IP)
        dst = ip_layer.dst
        # ignore packets originated by us
        if pkt[Ether].src in [get_if_hwaddr(i.phys) for i in interfaces.values()]:
            return
        # lookup returns (final_route, arp_target_ip)
        route, arp_target = route_lookup(dst)
        if not route:
            return
        out_iface_label = route.get('iface')
        if not out_iface_label:
            return
        # do not forward back to same iface (avoid reflect)
        if out_iface_label == iface.label:
            return
        out_iface = interfaces.get(out_iface_label)
        if not out_iface:
            return
        # arp_target is the IP we should ARP for (may be next_hop or dst)
        nh = arp_target or dst
        with arp_lock:
            arp_entry = arp_table.get(nh)
        if arp_entry is None:
            send_arp_request(out_iface, nh)
            return
        dst_mac = arp_entry['mac']
        src_mac = get_if_hwaddr(out_iface.phys)
        new_pkt = pkt.copy()
        # TTL handling and checksum recalculation
        try:
            cur_ttl = int(new_pkt[IP].ttl)
            if cur_ttl <= 1:
                # drop packet (could send ICMP Time Exceeded here)
                return
            new_pkt[IP].ttl = cur_ttl - 1
            try:
                del new_pkt[IP].chksum  # Scapy will recompute on send
            except Exception:
                pass
        except Exception:
            pass
        new_pkt[Ether].src = src_mac
        new_pkt[Ether].dst = dst_mac
        try:
            sendp(new_pkt, iface=out_iface.phys, verbose=False)
        except Exception:
            pass

    def loop():
        while not iface._stop.is_set():
            try:
                sniff(iface=iface.phys, prn=handle, store=False, timeout=1)
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


def send_arp_request(from_iface: Iface, target_ip: str):
    if from_iface.virt_ip is None:
        print(f"[WARN] Interface {from_iface.label} has no IP set, skipping ARP request")
        return
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(from_iface.phys)) / ARP(
        op=1,
        hwsrc=get_if_hwaddr(from_iface.phys),
        psrc=from_iface.virt_ip,
        hwdst="00:00:00:00:00:00",
        pdst=target_ip
    )
    sendp(pkt, iface=from_iface.phys, verbose=False)


#  GUI 
class App:
    def __init__(self, root):
        self.root = root
        root.title("SWRouter")
        print(f"Router starting on {PORT1} and {PORT2}")

        interfaces["port1"] = Iface(label="port1", phys_iface=PORT1)
        interfaces["port2"] = Iface(label="port2", phys_iface=PORT2)
        start_sniffer(interfaces["port1"])
        start_sniffer(interfaces["port2"])
        # start forwarders (stored on iface to allow clean shutdown)
        interfaces["port1"].forwarder = start_ip_forwarder(interfaces["port1"])
        interfaces["port2"].forwarder = start_ip_forwarder(interfaces["port2"])

        # Layout 
        self.if_frame = Frame(root)
        self.if_frame.pack(fill=X, padx=6, pady=6)
        self.if_widgets = {}

        for label in ("port1", "port2"):
            f = LabelFrame(self.if_frame, text=label)
            f.pack(side=LEFT, padx=6, pady=6)
            Label(f, text="Virt IP:").grid(row=0, column=0, sticky=W)
            ip_e = Entry(f, width=20)
            ip_e.grid(row=0, column=1)
            Label(f, text="Netmask:").grid(row=1, column=0, sticky=W)
            mask_e = Entry(f, width=20)
            mask_e.grid(row=1, column=1)
            mask_e.insert(0, "255.255.255.0")
            Button(f, text="Apply", command=lambda L=label: self.apply_iface(L)).grid(row=2, column=0, columnspan=2, pady=4)
            Label(f, text=f"MAC: {get_if_hwaddr(interfaces[label].phys)}").grid(row=3, column=0, columnspan=2, sticky=W)
            self.if_widgets[label] = {"ip": ip_e, "mask": mask_e}

        # ARP request button
        arp_frame = LabelFrame(root, text="ARP request (who-has)")
        arp_frame.pack(fill=X, padx=6, pady=6)
        Label(arp_frame, text="From:").grid(row=0, column=0, sticky=W)
        self.arp_from = StringVar(value="port1")
        OptionMenu(arp_frame, self.arp_from, "port1", "port2").grid(row=0, column=1)
        Label(arp_frame, text="Target IP:").grid(row=0, column=2, sticky=W)
        self.arp_target = Entry(arp_frame, width=18)
        self.arp_target.grid(row=0, column=3)
        Button(arp_frame, text="Send ARP", command=self.arp_send).grid(row=0, column=4, padx=6)

        # TTL 
        ttl_frame = Frame(root)
        ttl_frame.pack(fill=X, padx=6, pady=2)
        Label(ttl_frame, text="ARP TTL (s):").pack(side=LEFT)
        self.ttl_entry = Entry(ttl_frame, width=6)
        self.ttl_entry.pack(side=LEFT, padx=4)
        self.ttl_entry.insert(0, str(arp_ttl))
        Button(ttl_frame, text="Confirm TTL", command=self.confirm_ttl).pack(side=LEFT, padx=4)

        # routing GUI init
        self._init_routing_gui()

        # ARP table
        table_frame = Frame(root)
        table_frame.pack(fill=BOTH, expand=True, padx=6, pady=6)
        self.tree = ttk.Treeview(table_frame, columns=("mac", "age"), show="headings")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("age", text="Age(s)")
        self.tree.column("mac", width=160)
        self.tree.column("age", width=80, anchor=CENTER)
        self.tree.pack(fill=BOTH, expand=True, side=LEFT)
        scrollbar = Scrollbar(table_frame, orient=VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.tree.configure(yscroll=scrollbar.set)

        Button(root, text="Clear all ARP entries", command=lambda: self.delete_selected(all=True)).pack(pady=4)

        self._running = True
        self.root.after(1000, self.periodic)

    # Handlers
    def apply_iface(self, label):
        w = self.if_widgets[label]
        obj = interfaces[label]
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

    def periodic(self):
        now = time.time()
        with arp_lock:
            expired = [ip for ip, v in arp_table.items() if now - v["ts"] > arp_ttl]
            for ip in expired:
                del arp_table[ip]
        snap = arp_snapshot()
        for r in self.tree.get_children():
            self.tree.delete(r)
        for ip, info in sorted(snap.items()):
            age = int(now - info["ts"])
            self.tree.insert("", "end", iid=ip, values=(info["mac"], str(age)))
        try:
            self.update_rt_view()
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
        rt_frame = LabelFrame(self.root, text="Static Routes")
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
        self.rt_tree = ttk.Treeview(rt_frame, columns=("dest","mask", "iface", "nh", "type"), show="headings")
        self.rt_tree.heading("dest", text="Dest")
        self.rt_tree.heading("mask", text="Mask")
        self.rt_tree.heading("iface", text="Iface")
        self.rt_tree.heading("nh", text="NextHop")
        self.rt_tree.heading("type", text="Type")
        self.rt_tree.column("dest", width=140)
        self.rt_tree.column("mask", width=120)
        self.rt_tree.column("iface", width=80)
        self.rt_tree.column("nh", width=120)
        self.rt_tree.column("type", width=80)
        self.rt_tree.grid(row=1, column=0, columnspan=10, sticky="ew", pady=4)
        self.update_rt_view()

    # Add static route
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

    # Remove static route
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

    # Refresh displayed routing table
    def update_rt_view(self):
        for r in self.rt_tree.get_children():
            self.rt_tree.delete(r)
        for r in route_snapshot():
            self.rt_tree.insert("", "end", values=(f"{r['dest']}/{r['prefix']}", r["mask"], r["iface"], r["next_hop"], r["type"]))


# --- main entrypoint ---
if __name__ == "__main__":
    conf.verb = 0
    root = Tk()
    app = App(root)
    def on_close():
        app.shutdown()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()