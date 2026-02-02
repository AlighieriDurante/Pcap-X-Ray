# Pcap-X-Ray
Siber güvenlik analizleri için geliştirilmiş hafif siklet bir PCAP parser. 

Bu araç, ağ paketlerini (PCAP/PCAPNG) doğrudan Ethernet katmanı seviyesinde okuyarak MAC adreslerini ve temel protokol verilerini ayıklar. Analiz sonuçlarını raporlara hızlıca aktarmak için kopyalanabilir bir arayüz sunar.

### Özellikler
- Ham pcap verisini saniyeler içinde parse eder.
- Kaynak ve Hedef MAC adreslerini tablo halinde listeler.
- Tek tıkla çıktı kopyalama özelliği.
- Modern ve sade GUI (CustomTkinter).

### Kurulum ve Çalıştırma
```bash
pip install -r requirements.txt
python PcapXRay.py
