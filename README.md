WinMiniFirewall GUI

<img width="1226" height="739" alt="image" src="https://github.com/user-attachments/assets/444b1c32-702a-4397-898e-e70324ddd491" />


**WinMiniFirewall**, Windows üzerinde çalışan, tamamen Python ile yazılmış kullanıcı dostu bir mini firewall uygulamasıdır.  
PySide6 tabanlı grafik arayüz sayesinde komut satırı kullanmadan ağ kurallarını kolayca oluşturabilir, düzenleyebilir ve etkinleştirebilirsiniz.

---


![Uploading WhatsApp Görsel 2025-11-10 saat 13.18.53_0898d081.jpg…]()


## Özellikler

- **Kural Tabanlı Filtreleme:**  
  IP, port, protokol (TCP/UDP/ICMP) ve yön (in/out/any) bazlı trafik kontrolü

- **GUI Arayüz (PySide6):**  
  Kuralları elle yazmadan oluşturma, düzenleme ve silme

- **WinDivert Entegrasyonu:**  
  Gerçek zamanlı paket yakalama, filtreleme ve `accept/drop` kararı verme

- **Güvenlik İstisnaları:**  
  RDP (3389) ve Loopback (127.0.0.1, ::1) trafiğine otomatik izin

- **YAML Desteği:**  
  Kural dosyalarını (`rules.yaml`) kolayca kaydetme ve yükleme

- **Canlı Sayaç:**  
  Anlık `accepted / dropped` paket sayısını gösterir

---

## Kurulum

> Windows’ta çalışır. Yönetici izni (Administrator Privilege) gerektirir.

indirilmesi gereken paket :
pip install pydivert PySide6 pyyaml
