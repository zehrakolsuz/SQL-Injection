

-----

# 🛡️ Advanced SQL Injection Tester 👩‍💻 (Gelişmiş SQL Enjeksiyon Test Aracı 🚀)

This project provides an advanced, automated SQL Injection (SQLi) testing tool designed to identify potential vulnerabilities in web applications. It leverages a comprehensive set of SQL injection payloads for various database types and integrates with Playwright to intercept and analyze network requests.

(Bu proje, web uygulamalarındaki potansiyel güvenlik açıklarını tespit etmek için tasarlanmış gelişmiş, otomatik bir SQL Enjeksiyonu (SQLi) test aracı sunar. Çeşitli veritabanı türleri için kapsamlı bir SQL enjeksiyonu yük koleksiyonunu kullanır ve ağ isteklerini yakalamak ve analiz etmek için Playwright ile entegre olur.)

-----

## ✨ Features (Özellikler) ✨

  * **Comprehensive Payload Generation (Kapsamlı Payload Üretimi):** Includes a wide array of SQL injection payloads categorized by common database types (MySQL, MSSQL, Oracle, PostgreSQL, SQLite, MariaDB, DB2, HANA, Firebird) and general-purpose payloads.
    (Yaygın veritabanı türlerine (MySQL, MSSQL, Oracle, PostgreSQL, SQLite, MariaDB, DB2, HANA, Firebird) ve genel amaçlı payload'lara göre kategorize edilmiş çok çeşitli SQL enjeksiyonu payload'ları içerir.)
  * **Database Type Detection (Veritabanı Türü Tespiti):** Intelligently attempts to detect the underlying database technology of the target application using specific detection payloads.
    (Hedef uygulamanın altında yatan veritabanı teknolojisini belirli tespit payload'ları kullanarak akıllıca tespit etmeye çalışır.)
  * **Automated Request Interception (Otomatik İstek Yakalama):** Utilizes Playwright to launch a browser, navigate to a specified URL, and intercept all outgoing HTTP/S requests.
    (Bir tarayıcı başlatmak, belirtilen bir URL'ye gitmek ve tüm giden HTTP/S isteklerini yakalamak için Playwright'ı kullanır.)
  * **Parameter Extraction (Parametre Çıkarma):** Automatically identifies and extracts parameters from both URL query strings and POST request bodies (JSON and form-encoded).
    (Hem URL sorgu dizgilerinden hem de POST istek gövdelerinden (JSON ve form kodlu) parametreleri otomatik olarak tanımlar ve çıkarır.)
  * **Parallel Payload Testing (Paralel Payload Testi):** Tests multiple parameters with various payloads concurrently using threading for improved efficiency.
    (Geliştirilmiş verimlilik için birden fazla parametreyi çeşitli payload'larla eş zamanlı olarak, threading kullanarak test eder.)
  * **Error-Based Detection (Hata Tabanlı Tespit):** Identifies potential SQL injection vulnerabilities by looking for common database-specific error messages in the application's responses.
    (Uygulamanın yanıtlarında yaygın veritabanına özgü hata mesajlarını arayarak potansiyel SQL enjeksiyonu güvenlik açıklarını tespit eder.)
  * **Structured Vulnerability Reporting (Yapılandırılmış Güvenlik Açığı Raporlama):** Outputs detected vulnerabilities in a clear, JSON-formatted structure, detailing the URL, method, vulnerable parameter, and payload used.
    (Tespit edilen güvenlik açıklarını URL, yöntem, hassas parametre ve kullanılan payload'ı ayrıntılandıran açık, JSON formatında bir yapıda çıktı verir.)

-----

## 🚀 Getting Started (Başlarken) 🚀

### 🛠️ Prerequisites (Ön Koşullar)

  * Python 3.x
  * `playwright` library
  * `requests` or `httpx` (for a real-world scenario, the current `_simulate_request` is a placeholder)

### ⬇️ Installation (Kurulum)

1.  **Clone the repository (Depoyu klonlayın):**
    ```bash
    git clone https://github.com/zehrakolsuz/sqlinjection.git
    cd sqlinjection
    ```
2.  **Install Python dependencies (Python bağımlılıklarını yükleyin):**
    ```bash
    pip install playwright
    playwright install
    ```
    (Note: The current code uses `_simulate_request` which is a placeholder. For actual web requests, you'd integrate a library like `requests` or `httpx`.)
    (Not: Mevcut kod, bir yer tutucu olan `_simulate_request`'i kullanır. Gerçek web istekleri için, `requests` veya `httpx` gibi bir kütüphane entegre etmeniz gerekir.)

-----

## ⚙️ Usage (Kullanım) ⚙️

To run the SQL Injection Tester, execute the `main.py` script. The script will launch a Chromium browser (defaulting to `headless=False` for visibility), navigate to `https://www.binance.com/en` (as configured), and start intercepting requests.

(SQL Enjeksiyon Test Aracını çalıştırmak için `main.py` betiğini yürütün. Betik bir Chromium tarayıcı başlatacak (görünürlük için varsayılan olarak `headless=False`), yapılandırıldığı gibi `https://www.binance.com/en` adresine gidecek ve istekleri yakalamaya başlayacaktır.)

```bash
python your_script_name.py
```

(Replace `your_script_name.py` with the actual name of your Python file.)
(`your_script_name.py` yerine Python dosyanızın gerçek adını yazın.)

### 📝 Configuration (Yapılandırma)

You can modify the `main` function to change the target URL:

(Hedef URL'yi değiştirmek için `main` fonksiyonunu düzenleyebilirsiniz:)

```python
def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        sql_tester = AdvancedSQLInjectionTester()

        def handle_request(request):
            # ... (request handling logic)
            pass

        page.on("request", handle_request)
        page.goto("https://www.example.com/your-target-page") # <--- 🎯 Change this URL (Bu URL'yi değiştirin)
        page.wait_for_timeout(60000) # ⏳ Adjust timeout as needed (Gerektiğinde zaman aşımını ayarlayın)
        browser.close()
```

-----

## 🔍 How it Works (Nasıl Çalışır) 🔍

1.  **Playwright Integration (Playwright Entegrasyonu):** The tool uses Playwright to programmatically control a browser. It sets up a request interception mechanism so that every HTTP/S request made by the browser is captured before it's sent.
    (Araç, bir tarayıcıyı programatik olarak kontrol etmek için Playwright'ı kullanır. Tarayıcı tarafından yapılan her HTTP/S isteğinin gönderilmeden önce yakalanmasını sağlayan bir istek engelleme mekanizması kurar.)
2.  **Parameter Identification (Parametre Tanımlama):** For each intercepted request, the `_extract_parameters` method parses the URL and (if applicable) the POST data to identify all input parameters.
    (Yakalanan her istek için, `_extract_parameters` yöntemi, tüm girdi parametrelerini tanımlamak üzere URL'yi ve (varsa) POST verilerini ayrıştırır.)
3.  **Database Detection (Veritabanı Tespiti):** Before applying general payloads, the `detect_db_type` method sends specific payloads designed to elicit errors or responses characteristic of various database systems. This helps in tailoring the subsequent attacks.
    (Genel payload'ları uygulamadan önce, `detect_db_type` yöntemi, çeşitli veritabanı sistemlerinin karakteristik hatalarını veya yanıtlarını almak için tasarlanmış belirli payload'lar gönderir. Bu, sonraki saldırıları uyarlamaya yardımcı olur.)
4.  **Payload Injection (Payload Enjeksiyonu):** For each identified parameter, the tool iterates through a list of known SQL injection payloads (either general or database-specific). It constructs new requests where the original parameter value is appended with a payload.
    (Tanımlanan her parametre için, araç bilinen SQL enjeksiyonu payload'ları listesi (genel veya veritabanına özgü) arasında gezinir. Orijinal parametre değerinin bir payload ile birleştirildiği yeni istekler oluşturur.)
5.  **Vulnerability Detection (Güvenlik Açığı Tespiti):** The response from each injected request is then analyzed. The `_test_injection` method looks for specific error messages or patterns in the HTTP response body that indicate a successful SQL injection or a database-related error.
    (Enjekte edilen her isteğin yanıtı daha sonra analiz edilir. `_test_injection` yöntemi, başarılı bir SQL enjeksiyonunu veya veritabanıyla ilgili bir hatayı gösteren HTTP yanıt gövdesindeki belirli hata mesajlarını veya kalıpları arar.)
6.  **Reporting (Raporlama):** If a potential vulnerability is found, its details (URL, method, parameter, payload, and detection method) are printed to the console.

-----

## ⚠️ Important Considerations (Önemli Hususlar) ⚠️

  * **Ethical Hacking Only (Yalnızca Etik Hacking):** This tool is provided for **educational purposes and legitimate security testing ONLY**. Using this tool on systems you do not have explicit permission to test is illegal and unethical.
    (Bu araç **yalnızca eğitim amaçlı ve yasal güvenlik testi için** sağlanmıştır. Bu aracı, test etme izniniz olmayan sistemlerde kullanmak yasa dışıdır ve etik değildir.)
  * **Simulation vs. Real Requests (Simülasyon ve Gerçek İstekler):** The `_simulate_request` method is currently a placeholder and does not send actual HTTP requests. For a fully functional tool, you would integrate a library like `requests` or `httpx` to perform the web requests and capture responses.
    ( `_simulate_request` yöntemi şu anda bir yer tutucudur ve gerçek HTTP istekleri göndermez. Tamamen işlevsel bir araç için, web isteklerini gerçekleştirmek ve yanıtları yakalamak üzere `requests` veya `httpx` gibi bir kütüphane entegre etmeniz gerekir.)
  * **Detection Limitations (Tespit Sınırlamaları):** This tool primarily relies on error-based SQL injection detection. It may not detect blind SQL injection or other advanced SQLi techniques that do not produce immediate error messages.
    (Bu araç öncelikli olarak hata tabanlı SQL enjeksiyonu tespitine dayanmaktadır. Kör SQL enjeksiyonunu veya hemen hata mesajı üretmeyen diğer gelişmiş SQLi tekniklerini tespit edemeyebilir.)
  * **Rate Limiting and WAFs (Hız Sınırlaması ve WAF'lar):** Real-world applications often employ Web Application Firewalls (WAFs) and rate-limiting mechanisms that can block or slow down automated scanning. This script does not include advanced evasion techniques.
    (Gerçek dünya uygulamaları genellikle Otomatik Güvenlik Duvarları (WAF'lar) ve otomatik taramayı engelleyebilecek veya yavaşlatabilecek hız sınırlama mekanizmaları kullanır. Bu betik gelişmiş kaçınma teknikleri içermez.)

-----

## 📈 Future Enhancements (Gelecekteki Geliştirmeler) 📈

  * Integration with a proper HTTP client (e.g., `requests`, `httpx`) for sending actual requests.
    (Gerçek istekler göndermek için uygun bir HTTP istemcisi (örn. `requests`, `httpx`) ile entegrasyon.)
  * Support for Blind SQL Injection (Time-based, Boolean-based) techniques.
    (Kör SQL Enjeksiyonu (Zaman tabanlı, Boolean tabanlı) teknikleri için destek.)
  * Adding proxy support.
    (Proxy desteği ekleme.)
  * Implementing WAF evasion techniques.
    (WAF kaçınma teknikleri uygulama.)
  * More sophisticated parsing of responses for better vulnerability detection.
    (Daha iyi güvenlik açığı tespiti için yanıtların daha gelişmiş ayrıştırılması.)
  * Command-line interface (CLI) for easier usage and configuration.
    (Daha kolay kullanım ve yapılandırma için komut satırı arayüzü (CLI).)

-----
