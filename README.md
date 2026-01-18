## ShadowParse: The Luxe PCAP Forensics Engine 🕵️‍♂️🛡️

**ShadowParse** is a high-performance PCAP analysis and forensics tool designed for security researchers and CTF players. It combines deep packet inspection (DPI) with the **DeepRead Integration**, an automated multi-layered decoding engine.

## ✨ Key Features
- **Dual Scan Modes**: 
  - `Basic Scan`: Rapid analysis for quick flag hunting and traffic overviews.
  - `Deep Scan`: Full TCP/UDP stream reconstruction and multi-depth cipher analysis.
- **DeepRead Universal Decoder**: Automatically detects and decodes over 40+ encodings and ciphers (Base64, Caesar, Rot47, Morse, Tap Code, etc.).
- **Automatic Forensics**: Extracts files from HTTP traffic and identifies high-entropy payloads (potential encrypted C2 traffic).
- **Comprehensive Reporting**: Generates interactive Markdown reports, JSON data exports, and filtered PCAPs of suspicious traffic.

## 🚀 Installation

1. **Clone the repository:**
```
   git clone [https://github.com/YOUR_USERNAME/ShadowParse.git](https://github.com/YOUR_USERNAME/ShadowParse.git)
   cd ShadowParse

```

2. **Install dependencies:**
```bash
pip install -r requirements.txt

```


## 🛠️ Usage

### Basic Scan (Fast)

```bash
python shadowparse.py -f evidence.pcap --basic-scan

```

### Deep Scan (Thorough)

```bash
python shadowparse.py -f evidence.pcap -o ctf_report_folder

```

## 📊 Output

ShadowParse generates a structured report folder containing:

* `shadow_report.md`: A human-readable summary of all findings.
* `flags.json`: All captured unique flags (CTF style).
* `extracted_files/`: Any files recovered from the network streams.
* `suspicious_traffic.pcap`: A filtered PCAP containing only the "weird" or suspicious packets for further analysis in Wireshark.

## ⚖️ License

This project is licensed under the MIT License.
