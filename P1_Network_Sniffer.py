import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext

from scapy.all import sniff, Packet  # pip install scapy


class PacketSnifferGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Basic Network Sniffer")

        # State
        self.sniffing = False
        self.packets = []  # store scapy Packet objects

        # Controls frame
        ctrl_frame = ttk.Frame(master)
        ctrl_frame.pack(fill=tk.X, padx=5, pady=5)

        self.iface_var = tk.StringVar(value="")  # leave empty for default
        ttk.Label(ctrl_frame, text="Interface:").pack(side=tk.LEFT)
        self.iface_entry = ttk.Entry(
            ctrl_frame, textvariable=self.iface_var, width=10
        )
        self.iface_entry.pack(side=tk.LEFT, padx=5)

        self.filter_var = tk.StringVar(value="")  # BPF filter
        ttk.Label(ctrl_frame, text="Filter:").pack(side=tk.LEFT)
        self.filter_entry = ttk.Entry(
            ctrl_frame, textvariable=self.filter_var, width=20
        )
        self.filter_entry.pack(side=tk.LEFT, padx=5)

        self.start_btn = ttk.Button(
            ctrl_frame, text="Start Sniffing", command=self.start_sniffing
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(
            ctrl_frame,
            text="Stop",
            command=self.stop_sniffing,
            state=tk.DISABLED,
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Packet list
        list_frame = ttk.Frame(master)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("no", "time", "src", "dst", "proto", "length")
        self.tree = ttk.Treeview(
            list_frame, columns=columns, show="headings", height=15
        )
        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=100, anchor=tk.W)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        scrollbar = ttk.Scrollbar(
            list_frame,
            orient=tk.VERTICAL,
            command=self.tree.yview,
        )
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Packet detail
        detail_frame = ttk.LabelFrame(master, text="Packet Details")
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.detail_text = scrolledtext.ScrolledText(
            detail_frame, height=10, wrap=tk.WORD
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True)

    def start_sniffing(self):
        if self.sniffing:
            return
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.packets.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        iface = self.iface_var.get().strip() or None
        bpf_filter = self.filter_var.get().strip() or None

        # Run sniffing in background thread to keep GUI responsive
        t = threading.Thread(
            target=self.sniff_packets,
            args=(iface, bpf_filter),
            daemon=True,
        )
        t.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def sniff_packets(self, iface, bpf_filter):
        """
        Sniff packets and update GUI.
        Using prn callback and stop_filter so we can stop gracefully.
        """
        def _process(pkt: Packet):
            # store packet
            index = len(self.packets)
            self.packets.append(pkt)

            # basic fields
            ts = time.strftime("%H:%M:%S", time.localtime(pkt.time))
            src = pkt[0].src if hasattr(pkt[0], "src") else ""
            dst = pkt[0].dst if hasattr(pkt[0], "dst") else ""
            last = pkt.lastlayer()
            proto = last.name if last else pkt.__class__.__name__
            length = len(pkt)

            # update GUI from main thread
            self.master.after(
                0,
                self._insert_packet_row,
                index,
                ts,
                src,
                dst,
                proto,
                length,
            )

        sniff(
            iface=iface,
            filter=bpf_filter,
            prn=_process,
            store=False,
            stop_filter=lambda p: not self.sniffing
        )

        # when stopped
        self.master.after(0, lambda: self.stop_sniffing())

    def _insert_packet_row(self, index, ts, src, dst, proto, length):
        self.tree.insert(
            "",
            tk.END,
            iid=str(index),
            values=(index, ts, src, dst, proto, length),
        )

    def on_packet_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        idx = int(selected[0])
        if idx < 0 or idx >= len(self.packets):
            return
        pkt = self.packets[idx]

        lines = []
        lines.append(f"Packet #{idx}")
        lines.append("=" * 60)

        # Summary
        try:
            lines.append(f"Summary: {pkt.summary()}")
        except Exception:
            pass

        # Layers and fields (fixed: no layer(pkt) call)
        lines.append("\n[Layers]")
        try:
            for layer in pkt.layers():
                try:
                    layer_obj = pkt[layer]          # use existing layer
                    fields = dict(layer_obj.fields)  # copy for printing
                except Exception:
                    fields = {}
                lines.append(f"- {layer.name}: {fields}")
        except Exception:
            lines.append("- (error reading layers)")

        # Raw payload
        payload = getattr(pkt, "load", None)
        if payload is not None:
            lines.append("\n[Raw Payload]")
            try:
                text = payload.decode("utf-8", errors="replace")
                lines.append(text)
            except Exception:
                lines.append(repr(payload))

        # Update text widget
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "\n".join(lines))


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
