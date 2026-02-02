import customtkinter as ctk
from tkinter import filedialog, messagebox
from scapy.all import rdpcap, Ether, IP
import pyperclip # Kopyalama için: pip install pyperclip

# Arayüz Teması
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PcapParserApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Pcap-X-Ray v1.0 | Radagone Edition")
        self.geometry("700x500")

        # Arayüz Elemanları
        self.label = ctk.CTkLabel(self, text="PCAP Packet Analyzer", font=("Orbitron", 20, "bold"))
        self.label.pack(pady=20)

        self.btn_open = ctk.CTkButton(self, text="PCAP Dosyası Seç", command=self.analyze_pcap, 
                                     fg_color="#1f538d", hover_color="#14375e")
        self.btn_open.pack(pady=10)

        self.result_text = ctk.CTkTextbox(self, width=600, height=250, font=("Courier New", 12))
        self.result_text.pack(pady=10, padx=20)

        self.btn_copy = ctk.CTkButton(self, text="Sonuçları Kopyala", command=self.copy_to_clipboard,
                                     fg_color="#27ae60", hover_color="#1e8449")
        self.btn_copy.pack(pady=10)

        self.status_label = ctk.CTkLabel(self, text="Durum: Bekleniyor...", font=("Arial", 10))
        self.status_label.pack(side="bottom", pady=5)

    def analyze_pcap(self):
        file_path = filedialog.askopenfilename(filetypes=[("Pcap files", "*.pcap *.pcapng")])
        if not file_path:
            return
        
        self.status_label.configure(text="Durum: Analiz ediliyor...")
        self.update_idletasks()

        try:
            packets = rdpcap(file_path)
            self.result_text.delete("1.0", ctk.END)
            
            output = f"{'ID':<5} | {'Source MAC':<18} | {'Dest MAC':<18} | {'Type'}\n"
            output += "-" * 60 + "\n"
            
            for i, pkt in enumerate(packets[:100]): # İlk 100 paket
                if pkt.haslayer(Ether):
                    src = pkt[Ether].src
                    dst = pkt[Ether].dst
                    proto = "IP" if pkt.haslayer(IP) else "Other"
                    output += f"{i:<5} | {src:<18} | {dst:<18} | {proto}\n"
            
            self.result_text.insert("1.0", output)
            self.status_label.configure(text=f"Durum: {len(packets)} paket analiz edildi.")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Dosya okuma hatası: {e}")
            self.status_label.configure(text="Durum: Hata oluştu.")

    def copy_to_clipboard(self):
        content = self.result_text.get("1.0", ctk.END)
        pyperclip.copy(content)
        messagebox.showinfo("Başarılı", "Sonuçlar panoya kopyalandı.")

if __name__ == "__main__":
    app = PcapParserApp()
    app.mainloop()