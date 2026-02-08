# ATOOL - Android Static Analysis & Exploit Scanner v1.0

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Security](https://img.shields.io/badge/Security-Android-red.svg)
![Release](https://img.shields.io/badge/Release-v1.0-green.svg)

**ATOOL**, Android uygulamalarının kaynak kodlarını (decompiled APK) tarayarak güvenlik açıklarını, sızdırılmış API anahtarlarını, tehlikeli izinleri ve zafiyet barındıran kod bloklarını tespit eden gelişmiş bir statik analiz aracıdır.

> **"Control is an Illusion"**

## Özellikler

ATOOL, 150'den fazla güvenlik imzasını ve regex desenini kullanarak derinlemesine analiz yapar:

* **Hardcoded Secrets Avcısı:**
    * AWS, Google, Firebase, Stripe, Slack, GitHub, Twilio ve 100+ servis için API Key/Token taraması.
    * `google-services.json` ve `strings.xml` içerisindeki yanlış yapılandırılmış Firebase URL'leri.
    * Özel anahtarlar (RSA, DSA, EC, PGP).
* **Kod Zafiyet Analizi (Smali & Java):**
    * **RCE:** WebView (addJavascriptInterface), Zip Slip, Gson Deserialization.
    * **SQL Injection:** RawQuery ve ContentProvider açıklarını tespit eder.
    * **Crypto:** Zayıf şifreleme (AES/ECB, MD5, Hardcoded IV/Salt).
    * **Network:** SSL Pinning bypass, HostnameVerifier zafiyetleri, Cleartext trafik izinleri.
* **Güvenlik Mekanizması Tespiti:**
    * Root tespiti (RootBeer vb.), Emulator tespiti ve SSL Pinning korumalarını bulur (Bypass için ipuçları verir).
* **Manifest Analizi:**
    * Tehlikeli izinler (SMS, Konum, Kamera vb.).
    * Exported Activity/Service/Broadcast Receiver tespiti.
    * Deep Link (Scheme/Host) analizi.
* **Native Library Analizi:**
    * `.so` dosyaları içinde güvensiz C fonksiyonlarını (strcpy, system, exec) arar.
    * React Native ve Flutter yapılarını tespit eder.
* **Raporlama:**
    * Tarama sonucunda detaylı, renkli ve okunabilir bir **HTML raporu** oluşturur.

## Kurulum

Projeyi klonlayın ve gereksinimleri yükleyin:

```bash
git clone [https://github.com/berkayeacar00-commits/atool.git](https://github.com/kullaniciadi/atool.git)
cd atool
pip install -r requirements.txt
