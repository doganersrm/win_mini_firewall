WinMiniFirewall GUI

<img width="1226" height="739" alt="image" src="https://github.com/user-attachments/assets/444b1c32-702a-4397-898e-e70324ddd491" />


**WinMiniFirewall**, Windows üzerinde çalışan, tamamen Python ile yazılmış kullanıcı dostu bir mini firewall uygulamasıdır.  
PySide6 tabanlı grafik arayüz sayesinde komut satırı kullanmadan ağ kurallarını kolayca oluşturabilir, düzenleyebilir ve etkinleştirebilirsiniz.

---

<img width="1287" height="603" alt="image" src="https://github.com/user-attachments/assets/16384646-dedc-41b5-9d9a-a23cb37a42dc" />


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
