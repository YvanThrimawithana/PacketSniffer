import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
from scapy.all import sniff, IP
import threading
import queue
import time

# Constants
FONT_NAME = "Poppins"
FONT_SIZE = 12
FONT_COLOR = "#333"

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer")
        self.root.geometry("1000x700")
        self.root.configure(bg="#333")

        # Add Poppins font
        self.font = (FONT_NAME, FONT_SIZE)

        # Create UI elements
        self.create_widgets()

        # Initialize packet storage and thread management
        self.packets = []
        self.sniffing = False
        self.sniff_thread = None
        self.packet_queue = queue.Queue()

        # Regularly process packets from the queue
        self.root.after(100, self.process_packet_queue)

    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self.root, bg="#444", pady=10)
        header_frame.grid(row=0, column=0, sticky="nsew")

        header = tk.Label(header_frame, text="Advanced Packet Sniffer", font=(FONT_NAME, 24, "bold"), bg="#444", fg="white")
        header.pack()

        # Filter and Control Buttons
        filter_control_frame = tk.Frame(self.root, bg="#333", pady=10)
        filter_control_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        # Packet Type Filter
        tk.Label(filter_control_frame, text="Filter:", font=self.font, bg="#333", fg="white").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        self.filter_var.set("All")
        filter_dropdown = ttk.Combobox(filter_control_frame, textvariable=self.filter_var, font=self.font, state="readonly")
        filter_dropdown['values'] = ("All", "TCP", "UDP", "ICMP", "IP")
        filter_dropdown.pack(side=tk.LEFT, padx=5)
        self.filter_button = tk.Button(filter_control_frame, text="Apply Filter", command=self.filter_packets, font=self.font)
        self.filter_button.pack(side=tk.LEFT, padx=5)

        # Search Bar
        tk.Label(filter_control_frame, text="Search:", font=self.font, bg="#333", fg="white").pack(side=tk.LEFT, padx=5)
        self.search_entry = tk.Entry(filter_control_frame, font=self.font)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_button = tk.Button(filter_control_frame, text="Search", command=self.search_packets, font=self.font)
        self.search_button.pack(side=tk.LEFT, padx=5)

        # Control Buttons
        self.start_button = tk.Button(filter_control_frame, text="Start Scan", command=self.start_sniffing, font=self.font, bg="#4CAF50", fg="white")
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = tk.Button(filter_control_frame, text="Stop Scan", command=self.stop_sniffing, font=self.font, state=tk.DISABLED, bg="#F44336", fg="white")
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.clear_button = tk.Button(filter_control_frame, text="Clear", command=self.clear_packets, font=self.font, bg="#FFC107", fg="white")
        self.clear_button.pack(side=tk.LEFT, padx=5)
        self.export_button = tk.Button(filter_control_frame, text="Export", command=self.export_packets, font=self.font, bg="#2196F3", fg="white")
        self.export_button.pack(side=tk.LEFT, padx=5)

        # Packet Count
        self.packet_count_label = tk.Label(filter_control_frame, text="Packets Captured: 0", font=self.font, bg="#333", fg="white")
        self.packet_count_label.pack(side=tk.RIGHT, padx=5)

        # PanedWindow for retractable panels
        self.paned_window = tk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.paned_window.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)

        # Create frames for packet list and details
        self.packet_list_frame = tk.Frame(self.paned_window, bg="#333")
        self.packet_details_frame = tk.Frame(self.paned_window, bg="#333")

        # Add frames to the PanedWindow
        self.paned_window.add(self.packet_list_frame, minsize=150)  # Set a minimum size to keep the gap
        self.paned_window.add(self.packet_details_frame)

        # Packet Listbox
        self.packet_listbox = tk.Listbox(self.packet_list_frame, font=self.font, bg="white", selectmode=tk.SINGLE)
        self.packet_listbox.pack(fill=tk.BOTH, expand=True)

        # Scrollbar for listbox
        scrollbar = tk.Scrollbar(self.packet_listbox, orient=tk.VERTICAL, command=self.packet_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_listbox.config(yscrollcommand=scrollbar.set)

        # Text area for packet details
        self.packet_details = scrolledtext.ScrolledText(self.packet_details_frame, font=self.font, bg="white", wrap=tk.WORD)
        self.packet_details.pack(fill=tk.BOTH, expand=True)

    def sniff_packets(self):
        while self.sniffing:
            sniff(prn=self.process_packet, store=0, timeout=1)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniff_thread.start()
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            if self.sniff_thread:
                self.sniff_thread.join()
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def process_packet(self, packet):
        # Check the packet type and apply filters
        if self.filter_var.get() == "All" or self.filter_var.get() in packet:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            ip_src = packet[IP].src if IP in packet else 'Unknown'
            ip_dst = packet[IP].dst if IP in packet else 'Unknown'
            packet_type = packet[IP].proto if IP in packet else 'Unknown'
            data = f"{timestamp} | Src: {ip_src} | Dst: {ip_dst} | Type: {packet_type} | {packet.summary()}"
            self.packet_queue.put({'src': ip_src, 'data': data, 'details': packet.show(dump=True)})

    def process_packet_queue(self):
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            self.packets.append(packet)
            self.packet_listbox.insert(tk.END, packet['data'])
            self.packet_count_label.config(text=f"Packets Captured: {len(self.packets)}")
        self.packet_listbox.bind('<<ListboxSelect>>', self.show_packet_details)
        self.root.after(100, self.process_packet_queue)

    def show_packet_details(self, event):
        selected_index = self.packet_listbox.curselection()
        if selected_index:
            packet = self.packets[selected_index[0]]
            self.packet_details.delete(1.0, tk.END)
            self.packet_details.insert(tk.END, packet['details'])

    def search_packets(self):
        search_term = self.search_entry.get()
        self.packet_listbox.delete(0, tk.END)
        for packet in self.packets:
            if search_term.lower() in packet['data'].lower():
                self.packet_listbox.insert(tk.END, packet['data'])

    def filter_packets(self):
        filter_type = self.filter_var.get()
        self.packet_listbox.delete(0, tk.END)
        for packet in self.packets:
            if filter_type == "All" or filter_type in packet['data']:
                self.packet_listbox.insert(tk.END, packet['data'])

    def clear_packets(self):
        self.packets.clear()
        self.packet_listbox.delete(0, tk.END)
        self.packet_details.delete(1.0, tk.END)
        self.packet_count_label.config(text="Packets Captured: 0")

    def export_packets(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                for packet in self.packets:
                    file.write(f"{packet['data']}\n{packet['details']}\n\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
