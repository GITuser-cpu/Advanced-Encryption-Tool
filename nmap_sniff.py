#!/usr/bin/env python3
import os
import sys
import threading
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import xml.etree.ElementTree as ET
import re

def check_admin():
    """Check if running with admin/root privileges"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

class NetworkPacket:
    """Class to represent a network packet or scan result"""
    def __init__(self, timestamp, src_ip, dst_ip, protocol,
                 src_port=None, dst_port=None, payload="", rssi=None, channel=None):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.payload = payload
        self.rssi = rssi
        self.channel = channel

    def get_details(self):
        """Get detailed packet information"""
        details = [
            f"Timestamp: {self.timestamp}",
            f"Source IP: {self.src_ip}",
            f"Destination IP: {self.dst_ip}",
            f"Protocol: {self.protocol}"
        ]

        if self.src_port:
            details.append(f"Source Port: {self.src_port}")
        if self.dst_port:
            details.append(f"Destination Port: {self.dst_port}")

        if self.payload:
            details.append(f"Payload: {self.payload[:200]}...")

        if self.rssi is not None:
            details.append(f"Signal Strength (RSSI): {self.rssi}")
        if self.channel is not None:
            details.append(f"Channel: {self.channel}")

        return "\n".join(details)

class NetworkSniffer:
    """Network sniffer with port and WiFi scanning"""
    def __init__(self):
        self.is_sniffing = False
        self.sniffer_thread = None
        self.packet_callback = None
        self.nmap_process = None
        self.wifi_process = None
        self.scan_type = "port"
        self.custom_ports = "21-23,25,53,80,110,135-139,443,445,1433-1434,3306,3389,5432,5900,6379,8080,9200,27017"

    def set_packet_callback(self, callback):
        self.packet_callback = callback

    def set_scan_type(self, scan_type):
        self.scan_type = scan_type

    def set_custom_ports(self, ports):
        self.custom_ports = ports

    def start_sniffing(self, interface):
        if self.is_sniffing:
            return False

        try:
            if self.scan_type == "wifi":
                return self._start_wifi_scan(interface)
            else:
                return self._start_port_scan(interface)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start scan: {e}")
            return False

    def _start_port_scan(self, interface):
        try:
            self.nmap_process = subprocess.Popen(
                ["nmap", "-sS", "-sV", "-O", "-T4",
                 "-p", self.custom_ports,
                 "-e", interface,
                 "--open",
                 "-oX", "-"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            self.is_sniffing = True
            self.sniffer_thread = threading.Thread(target=self._read_nmap_output)
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start port scan: {e}")
            return False

    def _start_wifi_scan(self, interface):
        try:
            if os.name == 'nt':
                self.wifi_process = subprocess.Popen(
                    ["netsh", "wlan", "show", "network", "mode=bssid"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:
                self.wifi_process = subprocess.Popen(
                    ["iwlist", interface, "scan"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

            self.is_sniffing = True
            self.sniffer_thread = threading.Thread(target=self._read_wifi_output)
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start WiFi scan: {e}")
            return False

    def _read_nmap_output(self):
        try:
            xml_output = ""
            while self.is_sniffing:
                line = self.nmap_process.stdout.readline()
                if not line:
                    break
                xml_output += line

                if "</nmaprun>" in xml_output:
                    self._parse_nmap_xml(xml_output)
                    xml_output = ""
        except Exception as e:
            print(f"Error reading nmap output: {e}")
        finally:
            self.stop_sniffing()

    def _read_wifi_output(self):
        try:
            output = self.wifi_process.stdout.read()
            if os.name == 'nt':
                self._parse_windows_wifi(output)
            else:
                self._parse_linux_wifi(output)
        except Exception as e:
            print(f"Error reading WiFi output: {e}")
        finally:
            self.stop_sniffing()

    def _parse_nmap_xml(self, xml_output):
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall('host'):
                host_ip = "0.0.0.0"
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        host_ip = address.get('addr', '0.0.0.0')

                for port in host.findall('ports/port'):
                    protocol = port.get('protocol', 'tcp')
                    portid = port.get('portid', '0')
                    service_name = "unknown"
                    state_val = "unknown"

                    service = port.find('service')
                    if service is not None:
                        service_name = service.get('name', 'unknown')

                    state = port.find('state')
                    if state is not None:
                        state_val = state.get('state')

                    packet = NetworkPacket(
                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        src_ip=host_ip,
                        dst_ip="0.0.0.0",
                        protocol=protocol.upper(),
                        src_port=int(portid) if protocol == 'tcp' else None,
                        dst_port=int(portid) if protocol == 'tcp' else None,
                        payload=f"{service_name} - {state_val}"
                    )

                    if self.packet_callback:
                        self.packet_callback(packet)
        except Exception as e:
            print(f"Error parsing Nmap XML: {e}")

    def _parse_windows_wifi(self, output):
        try:
            networks = re.findall(
                r'SSID \d+ : (.*?)\n.*?Signal\s+:\s+(\d+)%.*?Channel\s+:\s+(\d+)',
                output,
                re.DOTALL
            )

            for ssid, signal, channel in networks:
                packet = NetworkPacket(
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    src_ip="0.0.0.0",
                    dst_ip="0.0.0.0",
                    protocol="WiFi",
                    payload=f"SSID: {ssid}, Signal: {signal}%, Channel: {channel}",
                    rssi=int(signal),
                    channel=int(channel)
                )

                if self.packet_callback:
                    self.packet_callback(packet)
        except Exception as e:
            print(f"Error parsing Windows WiFi output: {e}")

    def _parse_linux_wifi(self, output):
        try:
            cells = re.findall(
                r'Cell \d+ - Address: (.*?)\n.*?ESSID:"(.*?)"\n.*?Signal level=(-?\d+ dBm)',
                output,
                re.DOTALL
            )

            for mac, ssid, signal in cells:
                packet = NetworkPacket(
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    src_ip="0.0.0.0",
                    dst_ip="0.0.0.0",
                    protocol="WiFi",
                    payload=f"SSID: {ssid}, Signal: {signal} dBm, MAC: {mac}",
                    rssi=int(signal.split()[0])
                )

                if self.packet_callback:
                    self.packet_callback(packet)
        except Exception as e:
            print(f"Error parsing Linux WiFi output: {e}")

    def stop_sniffing(self):
        self.is_sniffing = False
        if hasattr(self, 'nmap_process') and self.nmap_process:
            try:
                self.nmap_process.terminate()
                self.nmap_process.wait(timeout=5)
            except:
                pass
            finally:
                self.nmap_process = None

        if hasattr(self, 'wifi_process') and self.wifi_process:
            try:
                self.wifi_process.terminate()
                self.wifi_process.wait(timeout=5)
            except:
                pass
            finally:
                self.wifi_process = None

    def get_available_interfaces(self):
        try:
            result = subprocess.run(
                ['nmap', '--iflist'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                interfaces = []
                for line in result.stdout.split('\n'):
                    if 'Interface' in line and '(' in line:
                        interface = line.split('(')[1].split(')')[0]
                        if interface not in ['lo', 'docker0']:
                            interfaces.append(interface)
                return interfaces if interfaces else ["eth0"]
            return ["eth0"]
        except:
            return ["eth0"]

class NetworkSnifferUI:
    """Main UI class"""
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("1000x700")
        self.root.configure(bg="#2b2b2b")

        self.sniffer = NetworkSniffer()
        self.sniffer.set_packet_callback(self.on_packet_captured)
        self.packet_data = []

        self.create_widgets()
        self.update_statistics()

    def create_widgets(self):
        """Create all UI widgets"""
        # Main layout
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        # Title frame
        title_frame = tk.Frame(self.root, bg="#3c3f41")
        title_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        title_frame.grid_columnconfigure(1, weight=1)

        tk.Label(
            title_frame, text="Network Scanner",
            font=("Arial", 16, "bold"), fg="white", bg="#3c3f41"
        ).grid(row=0, column=0, padx=10, pady=5)

        tk.Label(
            title_frame, text="Note: Requires admin privileges",
            font=("Arial", 10), fg="#ff6b6b", bg="#3c3f41"
        ).grid(row=0, column=1, padx=10, pady=5, sticky="e")

        # Scan type selection
        scan_type_frame = tk.LabelFrame(
            self.root, text="Scan Type",
            font=("Arial", 12), bg="#2b2b2b", fg="white"
        )
        scan_type_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        self.scan_type_var = tk.StringVar(value="port")
        tk.Radiobutton(
            scan_type_frame, text="Port Scan",
            variable=self.scan_type_var, value="port",
            command=self.update_scan_type, bg="#2b2b2b", fg="white",
            selectcolor="#2b2b2b"
        ).grid(row=0, column=0, padx=10, pady=5, sticky="w")

        tk.Radiobutton(
            scan_type_frame, text="WiFi Scan",
            variable=self.scan_type_var, value="wifi",
            command=self.update_scan_type, bg="#2b2b2b", fg="white",
            selectcolor="#2b2b2b"
        ).grid(row=0, column=1, padx=10, pady=5, sticky="w")

        # Port selection (only for port scans)
        self.port_frame = tk.LabelFrame(
            self.root, text="Port Selection",
            font=("Arial", 12), bg="#2b2b2b", fg="white"
        )

        self.port_var = tk.StringVar()
        self.port_entry = ttk.Entry(
            self.port_frame, textvariable=self.port_var,
            width=40
        )
        self.port_entry.grid(row=0, column=0, padx=5, pady=5)
        self.port_entry.insert(0, "21-23,25,53,80,110,135-139,443,445,1433-1434,3306,3389,5432,5900,6379,8080,9200,27017")

        # Control frame
        control_frame = tk.LabelFrame(
            self.root, text="Control Panel",
            font=("Arial", 12), bg="#2b2b2b", fg="white"
        )
        control_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        control_frame.grid_columnconfigure(4, weight=1)

        # Interface selection
        tk.Label(
            control_frame, text="Interface:",
            font=("Arial", 10), bg="#2b2b2b", fg="white"
        ).grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(
            control_frame, textvariable=self.interface_var,
            state="readonly", width=20
        )
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Button(
            control_frame, text="Refresh",
            command=self.refresh_interfaces
        ).grid(row=0, column=2, padx=5, pady=5)

        ttk.Button(
            control_frame, text="Start Scan",
            command=self.start_sniffing
        ).grid(row=0, column=3, padx=5, pady=5)

        ttk.Button(
            control_frame, text="Stop Scan",
            command=self.stop_sniffing
        ).grid(row=0, column=4, padx=5, pady=5)

        ttk.Button(
            control_frame, text="Clear",
            command=self.clear_data
        ).grid(row=0, column=5, padx=5, pady=5)

        # Main content area
        self.main_frame = tk.Frame(self.root, bg="#2b2b2b")
        self.main_frame.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Packet list frame
        self.packet_frame = tk.LabelFrame(
            self.main_frame, text="Scan Results",
            font=("Arial", 12), bg="#2b2b2b", fg="white"
        )
        self.packet_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.packet_frame.grid_rowconfigure(0, weight=1)
        self.packet_frame.grid_columnconfigure(0, weight=1)

        # Create Treeview with scrollbar
        self.tree_container = tk.Frame(self.packet_frame)
        self.tree_container.grid(row=0, column=0, sticky="nsew")

        self.tree_scroll = ttk.Scrollbar(self.tree_container)
        self.tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.packet_tree = ttk.Treeview(
            self.tree_container,
            show="headings",
            yscrollcommand=self.tree_scroll.set
        )
        self.tree_scroll.config(command=self.packet_tree.yview)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Bind selection event
        self.packet_tree.bind("<<TreeviewSelect>>", self.show_packet_details)

        # Details frame
        self.details_frame = tk.LabelFrame(
            self.main_frame, text="Packet Details",
            font=("Arial", 12), bg="#2b2b2b", fg="white"
        )
        self.details_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.details_frame.grid_rowconfigure(0, weight=1)
        self.details_frame.grid_columnconfigure(0, weight=1)

        self.details_text = scrolledtext.ScrolledText(
            self.details_frame,
            height=10,
            bg="#1e1e1e",
            fg="#dcdcdc",
            font=("Consolas", 10)
        )
        self.details_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Statistics frame
        stats_frame = tk.LabelFrame(
            self.root, text="Statistics",
            font=("Arial", 12), bg="#2b2b2b", fg="white"
        )
        stats_frame.grid(row=4, column=0, sticky="ew", padx=5, pady=5)

        self.stats_labels = {}
        stats_config = [
            ("Total Results:", "total_packets"),
            ("Protocols:", "protocols"),
            ("Top IPs:", "top_ips"),
            ("Top Ports:", "top_ports")
        ]

        for i, (label_text, key) in enumerate(stats_config):
            tk.Label(
                stats_frame, text=label_text,
                font=("Arial", 10, "bold"), bg="#2b2b2b", fg="#4db8ff"
            ).grid(row=0, column=i*2, padx=10, pady=5, sticky="w")

            self.stats_labels[key] = tk.Label(
                stats_frame, text="0", font=("Arial", 10),
                bg="#2b2b2b", fg="white", width=20
            )
            self.stats_labels[key].grid(
                row=0, column=i*2+1, padx=5, pady=5, sticky="w"
            )

        # WiFi networks frame (only for WiFi scans)
        self.wifi_frame = tk.LabelFrame(
            self.root, text="WiFi Networks",
            font=("Arial", 12), bg="#2b2b2b", fg="white"
        )

        self.wifi_tree = ttk.Treeview(
            self.wifi_frame,
            columns=("SSID", "Signal", "Channel", "MAC"),
            show="headings"
        )
        for col in ("SSID", "Signal", "Channel", "MAC"):
            self.wifi_tree.heading(col, text=col)
            self.wifi_tree.column(col, width=100)
        self.wifi_tree.column("SSID", width=200)
        self.wifi_tree.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Initialize interface list
        self.refresh_interfaces()
        self.update_scan_type()

    def show_packet_details(self, event):
        """Show detailed information about the selected packet"""
        selected_items = self.packet_tree.selection()
        if not selected_items:
            return

        item = selected_items[0]
        packet_index = int(self.packet_tree.item(item, "tags")[0]) if self.packet_tree.item(item, "tags") else 0

        if packet_index < len(self.packet_data):
            packet = self.packet_data[packet_index]
            details = packet.get_details()
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(1.0, details)

    def update_scan_type(self):
        """Update UI based on selected scan type"""
        scan_type = self.scan_type_var.get()
        self.sniffer.set_scan_type(scan_type)

        # Show/hide port selection
        if scan_type == "port":
            self.port_frame.grid(row=3, column=0, sticky="ew", padx=5, pady=5)
            self.wifi_frame.grid_forget()
        else:
            self.port_frame.grid_forget()
            self.wifi_frame.grid(row=3, column=0, sticky="ew", padx=5, pady=5)

        # Update packet tree columns
        self.packet_tree.delete(*self.packet_tree.get_children())

        if scan_type == "port":
            columns = ("Time", "Host", "Protocol", "Port", "Service", "State")
            self.packet_tree["columns"] = columns
            for col in columns:
                self.packet_tree.heading(col, text=col)
                self.packet_tree.column(col, width=100)
            self.packet_tree.column("Time", width=180)
            self.packet_tree.column("Host", width=150)
        else:
            columns = ("Time", "SSID", "Signal", "Channel", "Details")
            self.packet_tree["columns"] = columns
            for col in columns:
                self.packet_tree.heading(col, text=col)
                self.packet_tree.column(col, width=100)
            self.packet_tree.column("Time", width=180)
            self.packet_tree.column("SSID", width=200)

    def refresh_interfaces(self):
        interfaces = self.sniffer.get_available_interfaces()
        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_var.set(interfaces[0])

    def start_sniffing(self):
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select an interface")
            return

        if self.scan_type_var.get() == "port":
            ports = self.port_var.get()
            if not ports:
                messagebox.showerror("Error", "Please specify ports to scan")
                return
            self.sniffer.set_custom_ports(ports)

        if self.sniffer.start_sniffing(interface):
            self.packet_data = []
            self.packet_tree.delete(*self.packet_tree.get_children())
            if self.scan_type_var.get() == "wifi":
                self.wifi_tree.delete(*self.wifi_tree.get_children())
            self.details_text.delete(1.0, tk.END)

    def stop_sniffing(self):
        self.sniffer.stop_sniffing()

    def clear_data(self):
        if messagebox.askyesno("Confirm", "Clear all data?"):
            self.packet_data = []
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.wifi_tree.delete(*self.wifi_tree.get_children())
            self.details_text.delete(1.0, tk.END)

    def on_packet_captured(self, packet):
        self.packet_data.append(packet)

        if self.scan_type_var.get() == "port":
            values = (
                packet.timestamp,
                packet.src_ip,
                packet.protocol,
                packet.src_port if packet.src_port else packet.dst_port,
                packet.payload.split('-')[0].strip(),
                packet.payload.split('-')[1].strip()
            )
        else:
            values = (
                packet.timestamp,
                packet.payload.split(':')[1].strip().split(',')[0].strip(),
                packet.rssi,
                packet.channel if packet.channel else "N/A",
                packet.payload
            )

        # Store packet index as tag
        item_id = self.packet_tree.insert("", tk.END, values=values, tags=(str(len(self.packet_data)-1),))

        if len(self.packet_data) > 1000:
            items = self.packet_tree.get_children()
            if items:
                self.packet_tree.delete(items[0])
                self.packet_data.pop(0)

        # Update WiFi networks list
        if self.scan_type_var.get() == "wifi" and packet.protocol == "WiFi":
            ssid = packet.payload.split(':')[1].strip().split(',')[0].strip()
            for item in self.wifi_tree.get_children():
                if self.wifi_tree.item(item)['values'][0] == ssid:
                    self.wifi_tree.delete(item)

            wifi_values = (
                ssid,
                packet.rssi,
                packet.channel if packet.channel else "N/A",
                packet.payload.split('MAC:')[1].strip() if 'MAC:' in packet.payload else "N/A"
            )
            self.wifi_tree.insert("", tk.END, values=wifi_values)

    def update_statistics(self):
        # This is a simplified version - you can implement actual statistics if needed
        self.root.after(1000, self.update_statistics)

def main():
    if not check_admin():
        messagebox.showerror(
            "Error",
            "This application requires administrator/root privileges.\n"
            "Windows: Right-click and 'Run as administrator'\n"
            "Linux/Mac: Use 'sudo'"
        )
        return

    try:
        root = tk.Tk()
        root.lift()
        root.attributes('-topmost', True)
        root.after_idle(root.attributes, '-topmost', False)
        app = NetworkSnifferUI(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start GUI: {str(e)}")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()