"""
gui.py
Tableau de bord graphique (Tkinter) pour le Network Scanner.
Le scan tourne dans un thread séparé pour ne pas geler l'interface.

Usage :
    sudo python3 gui.py
"""

import threading
import tkinter as tk
from tkinter import ttk

from scanner import run_scan


class NetworkScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Network Scanner & Security Dashboard")
        self.root.geometry("800x450")

        self._build_top_bar()
        self._build_table()
        self._build_status_bar()

    def _build_top_bar(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Plage réseau :").pack(side="left")
        self.range_entry = ttk.Entry(top, width=20)
        self.range_entry.insert(0, "192.168.1.0/24")
        self.range_entry.pack(side="left", padx=5)

        self.ports_var = tk.BooleanVar()
        ttk.Checkbutton(top, text="Scanner les ports", variable=self.ports_var).pack(
            side="left", padx=10
        )

        self.scan_button = ttk.Button(top, text="Scanner", command=self.start_scan)
        self.scan_button.pack(side="left", padx=10)

        self.count_label = ttk.Label(top, text="Nombre d'appareils : 0")
        self.count_label.pack(side="right")

    def _build_table(self):
        columns = ("ip", "hostname", "mac", "vendor", "state", "ports")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")

        headers = {
            "ip": "IP", "hostname": "Nom", "mac": "MAC",
            "vendor": "Fabricant", "state": "Etat", "ports": "Ports ouverts",
        }
        widths = {"ip": 110, "hostname": 130, "mac": 140, "vendor": 130, "state": 90, "ports": 150}

        for col in columns:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=widths[col])

        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

    def _build_status_bar(self):
        self.status_label = ttk.Label(self.root, text="Prêt.", anchor="w")
        self.status_label.pack(fill="x", padx=10, pady=(0, 10))

    def start_scan(self):
        """Lance le scan dans un thread séparé pour ne pas bloquer l'UI."""
        self.scan_button.config(state="disabled")
        self.status_label.config(text="Scan en cours...")
        self.tree.delete(*self.tree.get_children())

        ip_range = self.range_entry.get().strip()
        do_ports = self.ports_var.get()

        thread = threading.Thread(
            target=self._run_scan_thread, args=(ip_range, do_ports), daemon=True
        )
        thread.start()

    def _run_scan_thread(self, ip_range: str, do_ports: bool):
        try:
            devices = run_scan(ip_range, do_port_scan=do_ports)
        except Exception as exc:
            self.root.after(0, self._on_error, str(exc))
            return
        self.root.after(0, self._on_scan_complete, devices)

    def _on_scan_complete(self, devices: list[dict]):
        for d in devices:
            ports_str = ", ".join(str(p["port"]) for p in d["open_ports"]) or "-"
            self.tree.insert(
                "", "end",
                values=(d["ip"], d["hostname"], d["mac"], d["vendor"], d["state"], ports_str),
            )
        self.count_label.config(text=f"Nombre d'appareils : {len(devices)}")
        self.status_label.config(text="Scan terminé.")
        self.scan_button.config(state="normal")

    def _on_error(self, message: str):
        self.status_label.config(text=f"Erreur : {message}")
        self.scan_button.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
