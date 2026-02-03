#!/usr/bin/env python3
"""
Intelligent Hint System for CTF Challenges
Provides progressive, context-aware hints based on findings
"""
from typing import List, Dict, Any
import json
from pathlib import Path


class HintEngine:
    """Generate progressive hints based on analysis results"""
    
    def __init__(self):
        self.hints_db = self._load_hints_database()
    
    def _load_hints_database(self) -> Dict[str, Any]:
        """Load hints from JSON file or use defaults"""
        hints_file = Path(__file__).parent / "hints.json"
        
        if hints_file.exists():
            try:
                with open(hints_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        
        # Default hints database
        return {
            "high_entropy": [
                {
                    "level": "basic",
                    "condition": "high_entropy_found",
                    "hint": "High entropy data detected - this often indicates encryption or compression. Consider trying XOR with common keys or look for repeating patterns."
                },
                {
                    "level": "intermediate",
                    "condition": "high_entropy_no_decode",
                    "hint": "The high-entropy data hasn't decoded successfully. Try multi-byte XOR bruteforce, or check if it's a compressed format (gzip, zlib)."
                },
                {
                    "level": "advanced",
                    "condition": "multiple_high_entropy",
                    "hint": "Multiple high-entropy payloads found. This might indicate a multi-stage payload or encrypted C2 communication. Look for patterns in packet timing or sizes."
                }
            ],
            "encoding": [
                {
                    "level": "basic",
                    "condition": "base64_non_printable",
                    "hint": "Base64 detected but contains non-printable characters after decode. Try treating the decoded data as binary (image, archive, executable)."
                },
                {
                    "level": "intermediate",
                    "condition": "multiple_encoding_layers",
                    "hint": "Multiple encoding layers detected. Consider automation with CyberChef or recursive decoding. Common chains: Base64→Hex→Gzip."
                },
                {
                    "level": "advanced",
                    "condition": "custom_encoding",
                    "hint": "Standard encodings failed. Look for custom base encodings, character substitution, or obfuscation techniques specific to the challenge."
                }
            ],
            "dns": [
                {
                    "level": "basic",
                    "condition": "unusual_dns",
                    "hint": "DNS queries to unusual domains detected. Check for DNS tunneling or data exfiltration via DNS queries/responses."
                },
                {
                    "level": "intermediate",
                    "condition": "dns_pattern",
                    "hint": "Pattern detected in DNS queries. Extract the subdomain strings and try decoding them (hex, base32, base64)."
                },
                {
                    "level": "advanced",
                    "condition": "dns_covert_channel",
                    "hint": "Potential DNS covert channel. Reconstruct the data from TXT records or subdomain strings in chronological order."
                }
            ],
            "files": [
                {
                    "level": "basic",
                    "condition": "images_extracted",
                    "hint": "Image files extracted. Run steganography tools: steghide (with common passwords), zsteg, stegsolve, binwalk."
                },
                {
                    "level": "intermediate",
                    "condition": "suspicious_file_headers",
                    "hint": "Unusual file headers or magic bytes detected. Use binwalk or foremost for deeper file carving, or check for polyglot files."
                },
                {
                    "level": "advanced",
                    "condition": "hidden_data_in_files",
                    "hint": "Check for hidden data using LSB analysis, EXIF metadata, alternate data streams, or file concatenation tricks."
                }
            ],
            "network": [
                {
                    "level": "basic",
                    "condition": "unusual_ports",
                    "hint": "Unusual port numbers detected. Check what services are running on these ports and look for protocol mismatches."
                },
                {
                    "level": "intermediate",
                    "condition": "covert_channel",
                    "hint": "Potential covert channel detected. Examine packet sizes, timing patterns, or unusual protocol fields (IP ID, TCP sequence numbers)."
                },
                {
                    "level": "advanced",
                    "condition": "protocol_abuse",
                    "hint": "Protocol abuse detected. Look for data hidden in ICMP payloads, TCP options, or IP fragmentation patterns."
                }
            ],
            "web": [
                {
                    "level": "basic",
                    "condition": "sql_injection_pattern",
                    "hint": "SQL injection patterns detected in HTTP traffic. Examine the responses for error messages or data leakage."
                },
                {
                    "level": "intermediate",
                    "condition": "xss_pattern",
                    "hint": "Potential XSS patterns found. Check for JavaScript execution or cookie theft in the HTTP responses."
                },
                {
                    "level": "advanced",
                    "condition": "api_keys_exposed",
                    "hint": "Potential API keys or tokens in HTTP traffic. Try using these credentials with the associated API endpoints."
                }
            ],
            "crypto": [
                {
                    "level": "basic",
                    "condition": "classical_cipher",
                    "hint": "Classical cipher patterns detected (Caesar, Vigenère, Substitution). Try automated cipher identification tools like CyberChef or dcode.fr."
                },
                {
                    "level": "intermediate",
                    "condition": "modern_crypto",
                    "hint": "Modern cryptographic patterns found. Look for weak implementations, known vulnerabilities, or exposed keys/IVs."
                },
                {
                    "level": "advanced",
                    "condition": "crypto_attack",
                    "hint": "Consider advanced attacks: padding oracle, chosen plaintext/ciphertext, frequency analysis on block ciphers, or timing attacks."
                }
            ],
            "flags": [
                {
                    "level": "basic",
                    "condition": "partial_flags",
                    "hint": "Flags found but look incomplete. Check for multi-part flags across different protocols, streams, or packets."
                },
                {
                    "level": "intermediate",
                    "condition": "no_flags_found",
                    "hint": "No obvious flags found. The flag might be hidden in: file metadata, concatenated data, least significant bits, or require computation."
                },
                {
                    "level": "advanced",
                    "condition": "flag_format_unusual",
                    "hint": "Unusual flag format. Check challenge description for custom flag format, or look for hashes that need cracking."
                }
            ]
        }
    
    def generate_hints(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate context-aware hints based on analysis results"""
        hints = []
        
        # High entropy hints
        if analysis_results.get('high_entropy_count', 0) > 0:
            if analysis_results.get('successful_decodes', 0) == 0:
                hints.append(self._get_hint('high_entropy', 'high_entropy_no_decode'))
            elif analysis_results.get('high_entropy_count', 0) > 5:
                hints.append(self._get_hint('high_entropy', 'multiple_high_entropy'))
            else:
                hints.append(self._get_hint('high_entropy', 'high_entropy_found'))
        
        # Encoding hints
        if analysis_results.get('base64_non_printable', False):
            hints.append(self._get_hint('encoding', 'base64_non_printable'))
        
        if analysis_results.get('encoding_layers', 0) > 2:
            hints.append(self._get_hint('encoding', 'multiple_encoding_layers'))
        
        # DNS hints
        unusual_dns_list = analysis_results.get('unusual_dns', [])
        if len(unusual_dns_list) > 0:
            if analysis_results.get('dns_pattern_detected', False):
                hints.append(self._get_hint('dns', 'dns_pattern'))
            else:
                hints.append(self._get_hint('dns', 'unusual_dns'))
        
        # File hints
        if analysis_results.get('image_files', 0) > 0:
            hints.append(self._get_hint('files', 'images_extracted'))
        
        # Network hints
        if analysis_results.get('unusual_ports', []):
            hints.append(self._get_hint('network', 'unusual_ports'))
        
        # Web hints
        if analysis_results.get('sql_injection_detected', False):
            hints.append(self._get_hint('web', 'sql_injection_pattern'))
        
        if analysis_results.get('xss_detected', False):
            hints.append(self._get_hint('web', 'xss_pattern'))
        
        # Flag hints
        if analysis_results.get('flags_found', 0) > 0 and analysis_results.get('flags_incomplete', False):
            hints.append(self._get_hint('flags', 'partial_flags'))
        elif analysis_results.get('flags_found', 0) == 0:
            hints.append(self._get_hint('flags', 'no_flags_found'))
        
        # Sort hints by level (basic first, then intermediate, then advanced)
        level_order = {'basic': 0, 'intermediate': 1, 'advanced': 2}
        hints.sort(key=lambda x: level_order.get(x.get('level', 'basic'), 0))
        
        return hints
    
    def _get_hint(self, category: str, condition: str) -> Dict[str, Any]:
        """Get a specific hint from the database"""
        hints = self.hints_db.get(category, [])
        for hint in hints:
            if hint['condition'] == condition:
                return hint
        return {
            'level': 'basic',
            'condition': condition,
            'hint': 'Analyze the data more carefully and try different decoding techniques.'
        }
    
    def get_tool_recommendations(self, challenge_category: str) -> List[str]:
        """Get tool recommendations based on challenge category"""
        tools = {
            'Cryptography': [
                'CyberChef (https://gchq.github.io/CyberChef/)',
                'dcode.fr cipher identifier',
                'John the Ripper for hash cracking',
                'Hashcat for GPU-accelerated cracking',
                'RSA CTF Tool for RSA challenges'
            ],
            'Forensics': [
                'Binwalk for file carving',
                'Foremost for file recovery',
                'Volatility for memory forensics',
                'Autopsy for disk forensics',
                'ExifTool for metadata analysis'
            ],
            'Steganography': [
                'Steghide (password: common CTF passwords)',
                'zsteg for PNG/BMP LSB analysis',
                'Stegsolve for image analysis',
                'StegSnow for whitespace steganography',
                'OpenStego for general steganography'
            ],
            'Web Exploitation': [
                'Burp Suite for web proxy',
                'sqlmap for SQL injection',
                'OWASP ZAP for vulnerability scanning',
                'dirb/gobuster for directory bruteforcing',
                'jwt.io for JWT analysis'
            ],
            'Network Analysis': [
                'Wireshark for deep packet inspection',
                'tcpdump for packet capture',
                'NetworkMiner for network forensics',
                'Zeek (Bro) for network monitoring',
                'Scapy for packet manipulation'
            ],
            'Reverse Engineering': [
                'Ghidra for decompilation',
                'IDA Pro for disassembly',
                'radare2 for binary analysis',
                'GDB/pwndbg for debugging',
                'strings/ltrace/strace for quick analysis'
            ]
        }
        
        return tools.get(challenge_category, [
            'Try multiple approaches',
            'Google for specific techniques',
            'Check CTF writeups for similar challenges'
        ])
    
    def save_hints_template(self, output_path: Path):
        """Save hints template JSON file for customization"""
        hints_file = output_path / "hints.json"
        try:
            with open(hints_file, 'w') as f:
                json.dump(self.hints_db, f, indent=2)
        except Exception as e:
            print(f"Failed to save hints template: {e}")
