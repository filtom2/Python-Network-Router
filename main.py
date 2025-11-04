import sys
import time
import threading
import random
import ipaddress
from tkinter import *
from tkinter import ttk, messagebox
from scapy.all import sniff, sendp, Ether, ARP, conf, get_if_hwaddr

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


PORT1 = "en8"
PORT2 = "en9"

interfaces = {}
arp_table = {}
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

        # Learn ARP replies
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
                # skip self
                if other == iface:
                    continue
                # skip if other has no network configured or it's the same interface that received the request
                if other.virt_ip is None or other.netmask is None:
                    continue
                # If the target IP lies in the 'other' interface's subnet, we can proxy
                try:
                    if _ip_in_iface_network(target, other):
                        # Craft proxy reply that tells requester: "I (this interface) own that IP"
                        proxy_src_mac = get_if_hwaddr(iface.phys)
                        reply = Ether(dst=pkt[Ether].src, src=proxy_src_mac) / ARP(
                            op=2,
                            hwsrc=proxy_src_mac,
                            psrc=target,
                            hwdst=arp.hwsrc,
                            pdst=arp.psrc
                        )
                        sendp(reply, iface=iface.phys, verbose=False)
                        # Also learn the requester (so GUI shows who asked)
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


def stop_sniffer(iface: Iface):
    iface._stop.set()
    if iface.sniffer:
        iface.sniffer.join(timeout=2)


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
        ip = w["ip"].get().strip()
        mask = w["mask"].get().strip()
        obj.virt_ip = ip if ip else None
        obj.netmask = mask if mask else None
        messagebox.showinfo("Applied", f"{label}: {obj.virt_ip}/{obj.netmask} on {obj.phys}")

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


def main():
    conf.verb = 1 # for scapy
    root = Tk()
    app = App(root)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        app.shutdown()


if __name__ == "__main__":
    main()
