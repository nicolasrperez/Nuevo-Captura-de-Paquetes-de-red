import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import subprocess
import re
import webbrowser
from scapy.all import sniff, wrpcap, get_if_list, conf

def npcap_installed():
    """Verifica si Npcap está instalado en el sistema."""
    try:
        result = subprocess.run(
            ["sc query npcap"], shell=True, capture_output=True, text=True
        )
        if "RUNNING" in result.stdout or "STOPPED" in result.stdout:
            return True
    except Exception:
        pass
    return False

class SimpleSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("SnifferApp - Capturador de Red")
        self.root.geometry("700x500")
        self.running = False
        self.packets = []

        ttk.Label(root, text="SnifferApp - Capturador de red (Scapy)", font=("Segoe UI", 12, "bold")).pack(pady=5)

        frame = ttk.Frame(root)
        frame.pack(pady=5)

        ttk.Label(frame, text="Interfaz:").grid(row=0, column=0, padx=5)
        self.iface_var = tk.StringVar()
        interfaces = get_if_list()
        self.iface_combo = ttk.Combobox(frame, textvariable=self.iface_var, values=interfaces, width=40)
        if interfaces:
            self.iface_combo.current(0)
        self.iface_combo.grid(row=0, column=1, padx=5)

        ttk.Button(frame, text="Iniciar", command=self.start_capture).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(frame, text="Detener", command=self.stop_capture).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Guardar .pcap", command=self.save_capture).grid(row=1, column=2, padx=5, pady=5)

        self.text = tk.Text(root, height=20)
        self.text.pack(fill="both", expand=True, padx=10, pady=10)

    def start_capture(self):
        if self.running:
            messagebox.showinfo("Aviso", "Ya está capturando.")
            return
        iface = self.iface_var.get()
        if not iface:
            messagebox.showerror("Error", "Seleccioná una interfaz.")
            return
        self.running = True
        self.packets = []
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, f"Capturando en interfaz: {iface}\n")
        self.thread = threading.Thread(target=self.sniff_packets, args=(iface,), daemon=True)
        self.thread.start()

    def sniff_packets(self, iface):
        try:
            sniff(
                iface=iface,
                prn=self.process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.text.insert(tk.END, f"\nError: {e}\n")

    def process_packet(self, pkt):
        if not self.running:
            return False
        self.packets.append(pkt)
        summary = pkt.summary()
        self.text.insert(tk.END, f"{summary}\n")
        self.text.see(tk.END)

    def stop_capture(self):
        self.running = False
        self.text.insert(tk.END, "\n--- Captura detenida ---\n")

    def save_capture(self):
        if not self.packets:
            messagebox.showinfo("Sin datos", "No hay paquetes para guardar.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")])
        if not path:
            return
        wrpcap(path, self.packets)
        messagebox.showinfo("Guardado", f"Captura guardada en:\n{path}")

def main():
    if not npcap_installed():
        msg = (
            "Npcap no está instalado o no se está ejecutando.\n\n"
            "Descargalo desde:\nhttps://npcap.com/#download\n\n"
            "Instalalo con la opción:\n✅ Install Npcap in WinPcap API-compatible Mode"
        )
        messagebox.showerror("Npcap faltante", msg)
        webbrowser.open("https://npcap.com/#download")
        return

    conf.use_pcap = True
    root = tk.Tk()
    app = SimpleSniffer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
