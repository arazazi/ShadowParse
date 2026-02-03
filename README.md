## ShadowParse: The Luxe PCAP Forensics Engine 🕵️‍♂️🛡️

**ShadowParse** is a high-performance PCAP analysis and forensics tool designed for security researchers and CTF players. It combines deep packet inspection (DPI) with the **DeepRead Integration**, an automated multi-layered decoding engine, and now includes comprehensive **CTF-specific features** for automated challenge solving.

## ✨ Key Features
- **Dual Scan Modes**: 
  - `Basic Scan`: Rapid analysis for quick flag hunting and traffic overviews.
  - `Deep Scan`: Full TCP/UDP stream reconstruction and multi-depth cipher analysis.
- **DeepRead Universal Decoder**: Automatically detects and decodes over 40+ encodings and ciphers (Base64, Caesar, Rot47, Morse, Tap Code, etc.).
- **CTF Mode**: Specialized features for CTF challenges including:
  - **Auto-Solver Library**: Automated solving for ROT, XOR, substitution ciphers, QR codes, barcodes
  - **Challenge Categorization**: Intelligent detection of challenge type (Crypto, Forensics, Stego, Web, Network, Reverse)
  - **Progressive Hints**: Context-aware hints based on findings
  - **Flag Submission**: Integration with CTFd, HackTheBox, and custom webhooks
  - **Tool Recommendations**: Suggests relevant tools based on challenge category
- **Automatic Forensics**: Extracts files from HTTP traffic and identifies high-entropy payloads (potential encrypted C2 traffic).
- **Comprehensive Reporting**: Generates interactive Markdown reports, JSON data exports, and filtered PCAPs of suspicious traffic.

## 🚀 Installation

1. **Clone the repository:**
```
   git clone https://github.com/arazazi/ShadowParse.git
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

### CTF Mode with Auto-Solver

```bash
python shadowparse.py -f evidence.pcap --ctf-mode --auto-solve --hints
```

### CTF Mode with Flag Submission

```bash
# First, create and configure ctf_config.yaml
python shadowparse.py -f evidence.pcap --ctf-mode --auto-solve --submit-flags --config ctf_config.yaml
```

### Command-Line Options

- `-f, --file`: PCAP file to analyze (required)
- `-o, --output`: Output folder name (default: shadow_deepscan_report)
- `-b, --basic-scan`: Run in fast Basic Scan mode
- `--ctf-mode`: Enable CTF-specific features (categorization, hints, enhanced reporting)
- `--auto-solve`: Run auto-solver tools (ROT, XOR, substitution ciphers, QR codes, etc.)
- `--submit-flags`: Enable flag submission to CTF platforms (requires --config)
- `--hints`: Show progressive hints based on findings
- `--config`: Path to CTF configuration file (ctf_config.yaml)

## 📊 Output

ShadowParse generates a structured report folder containing:

* `shadow_report.md`: A human-readable summary of all findings.
* `flags.json`: All captured unique flags (CTF style).
* `extracted_files/`: Any files recovered from the network streams.
* `suspicious_traffic.pcap`: A filtered PCAP containing only the "weird" or suspicious packets for further analysis in Wireshark.

### Additional CTF Mode Outputs

When `--ctf-mode` is enabled, ShadowParse also generates:

* `ctf_analysis.md`: CTF-specific analysis including challenge category, hints, and tool recommendations.
* `auto_solver_results.txt`: Results from automated solving attempts (when `--auto-solve` is used).
* `suggested_tools.txt`: List of recommended tools based on challenge category.
* `flag_submissions.log`: Log of flag submission attempts (when `--submit-flags` is used).

## 🎯 CTF Configuration

To use flag submission features, create a `ctf_config.yaml` file:

```yaml
ctf_platform:
  enabled: true
  platform: "ctfd"  # Options: "ctfd", "htb", "webhook"
  url: "https://ctf.example.com"
  api_token: "your-api-token-here"
  auto_submit: false  # Set to true to auto-submit without confirmation
```

### Supported Platforms

- **CTFd**: Popular CTF platform (requires challenge ID)
- **HackTheBox**: Machine flag submission (user.txt and root.txt)
- **Webhook**: Generic webhook for custom integrations

## 🔧 CTF Auto-Solver Features

The auto-solver can automatically attempt to decode:

- **ROT Ciphers**: All ROT1-25 variations with readability scoring
- **XOR Encryption**: Single and multi-byte XOR bruteforce
- **Substitution Ciphers**: Frequency analysis-based solving
- **CyberChef Chains**: Common encoding chains (Base64→Gunzip→Hex, etc.)
- **QR Codes & Barcodes**: Automatic detection and decoding from images
- **Shellcode**: Pattern detection and disassembly
- **Binary Analysis**: Basic disassembly of extracted executables

## 💡 Challenge Categories

ShadowParse can automatically categorize challenges into:

- **Cryptography**: High entropy, encoded data, cipher patterns
- **Forensics**: File carving, hidden data, metadata analysis
- **Steganography**: Image/audio files, LSB patterns
- **Web Exploitation**: HTTP traffic, SQL injection, XSS patterns
- **Network Analysis**: DNS tunneling, covert channels, protocol abuse
- **Reverse Engineering**: Binary extraction, shellcode, obfuscated code

## ⚖️ License

This project is licensed under the MIT License.
