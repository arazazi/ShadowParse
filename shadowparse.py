#!/usr/bin/env python3
"""
ShadowParse – The Luxe PCAP Forensics Engine (Deep Scan Edition with DeepRead Integration)
Author: Azazi
License: MIT
"""
import argparse, base64, gzip, json, math, os, re, sys, urllib.parse
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

import pandas as pd
from scapy.all import (
    DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw, rdpcap, wrpcap,
    Ether, ARP, ICMP,
)

# DeepRead dependencies
import binascii
import string
import html
import itertools
import collections
import hashlib

try:
    import chardet
except ImportError:
    chardet = None
    print("Warning: 'chardet' not installed. File processing encoding will default to UTF-8/latin-1.")
# Explicitly import application-layer protocols from their specific layers
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HTTP_LAYERS_AVAILABLE = True
except ImportError:
    class HTTPRequest: pass
    class HTTPResponse: pass
    HTTP_LAYERS_AVAILABLE = False
    print("Warning: HTTP layers (scapy.layers.http) are missing. HTTP analysis will be skipped.")

try:
    from scapy.layers.inet import FTP, SSH
except ImportError:
    class FTP: pass
    class SSH: pass
    print("Warning: FTP/SSH layers are missing. Dedicated FTP/SSH analysis will be limited.")

try:
    from scapy.layers.snmp import SNMP
except ImportError:
    class SNMP: pass
    print("Warning: SNMP layer is missing. SNMP analysis will be skipped.")

try:
    from scapy.layers.smb import SMB
except ImportError:
    class SMB: pass
    print("Warning: SMB layer is missing. SMB analysis will be skipped.")


from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import track

# CTF Mode imports (optional)
try:
    from ctf_solvers import CTFAutoSolver
    from ctf_categorizer import ChallengeCategorizer
    from hint_engine import HintEngine
    from ctf_submission import FlagSubmitter, create_config_template
    CTF_MODULES_AVAILABLE = True
except ImportError:
    CTF_MODULES_AVAILABLE = False
    print("Warning: CTF modules not available. Install dependencies for CTF mode.")

console = Console(record=True)
VERSION = "5.0.0-feature-complete" # Final version number for new features!

# --- CONSTANTS ---
FLAG_PATTERNS = [
    re.compile(r"flag\{[^}]+\}", re.I), re.compile(r"CTF\{[^}]+\}", re.I), re.compile(r"key\{[^}]+\}", re.I),
    re.compile(r"password\{[^}]+\}", re.I), re.compile(r"Exploit3rs\{[^}]+\}", re.I), re.compile(r"secret\{[^}]+\}", re.I),
    re.compile(r"picoCTF\{[^}]+\}", re.I), re.compile(r"[A-Z0-9]{32}", re.I), re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", re.I),
    re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", re.I),
]

SUSP_KEYWORDS = [
    "shell", "exec", "eval", "wget", "curl", "powershell", "cmd", "base64", "malware", "exploit", "dropper", 
    "ransom", "b64", "nc", "netcat", "reverse shell", "beacon", "meterpreter", "cobalt strike", "c2", 
    "command and control", "trojan", "virus", "worm", "phishing", "credential", "passw", "login", "auth", 
    "token", "jwt", ".php", ".asp", ".jsp", ".exe", ".dll", ".vbs", ".ps1", "xor", "rot13", "cipher", 
    "aes", "rc4", "private key", "leak", "upload", "download", "post", "put",
]
ENTROPY_THRESHOLD = 4.8
MIN_B64_LEN = 16

COMMON_PORTS = {
    20: "FTP_DATA", 21: "FTP_CONTROL", 22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB/CIFS",
}

# ------------------------------ GLOBAL UTILS ------------------------------
def entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte string."""
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def is_base64(s: str) -> str | None:
    """Check if a string is valid Base64 and decode if printable."""
    s = re.sub(r"[^A-Za-z0-9+/_-]", "", s)
    if not s or len(s) < MIN_B64_LEN:
        return None
    try:
        if len(s) % 4:
            s += "=" * (4 - len(s) % 4)
        decoded = base64.b64decode(s, validate=True)
        # Check for sufficient printable ASCII characters
        printable_chars = sum(1 for char in decoded if 32 <= char <= 126 or char in (9, 10, 13))
        if printable_chars / len(decoded) > 0.3:
            return decoded.decode("utf-8", errors="ignore")
        return None
    except Exception:
        return None

def detect_flags(text: str) -> List[str]:
    """Detect flags using defined patterns."""
    return list(set([match for pat in FLAG_PATTERNS for match in pat.findall(text)]))


# ------------------------------ ULTIMATE ENCODING DETECTOR (DEEPREAD) ------------------------------
class UltimateEncodingDetector:
    # --- Integration of ALL methods from deepread.py ---

    def __init__(self):
        # A dictionary of detection methods that map encoding names to functions
        self.encoders = {
            'base16': self.detect_base16, 'base32': self.detect_base32, 'base45': self.detect_base45,
            'base58': self.detect_base58, 'base64': self.detect_base64, 'base85': self.detect_base85,
            'base91': self.detect_base91, 'base92': self.detect_base92, 'ascii_hex': self.detect_ascii_hex,
            'binary': self.detect_binary, 'octal': self.detect_octal, 'decimal': self.detect_decimal,
            'hex': self.detect_hex, 'url': self.detect_url_encoding, 'double_url': self.detect_double_url,
            'html_entities': self.detect_html_entities, 'html_decimal': self.detect_html_decimal,
            'html_hex': self.detect_html_hex, 'xml_entities': self.detect_xml_entities,
            'caesar': self.detect_caesar, 'rot13': self.detect_rot13, 'rot47': self.detect_rot47,
            'rot5': self.detect_rot5, 'rot18': self.detect_rot18, 'rot8000': self.detect_rot8000,
            'atbash': self.detect_atbash, 'affine': self.detect_affine, 'vigenere': self.detect_vigenere,
            'bacon': self.detect_bacon, 'polybius': self.detect_polybius, 'adfgx': self.detect_adfgx, 
            'rail_fence': self.detect_rail_fence, 'columnar_transposition': self.detect_columnar, 
            'reverse': self.detect_reverse, 'keyboard_qwerty': self.detect_keyboard_qwerty, 
            'keyboard_dvorak': self.detect_keyboard_dvorak, 'keyboard_azerty': self.detect_keyboard_azerty, 
            'morse': self.detect_morse, 'tap_code': self.detect_tap_code, 'quoted_printable': self.detect_quoted_printable,
            'a1z26': self.detect_a1z26, 'leet_speak': self.detect_leet_speak, 'skip_cipher': self.detect_skip_cipher,
            'uuencode': self.detect_uuencode, 'xxencode': self.detect_xxencode, 
        }
        # Dynamically create decoders if a decode_method exists
        self.decoders = {name: getattr(self, f'decode_{name}', None) for name in self.encoders.keys() if hasattr(self, f'decode_{name}')}


    # Helper for English word scoring (used by both detect and decode)
    def score_english(self, text: str) -> float:
        common_words = ['the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'a', 'an', 'is', 'are', 'was', 'were', 'be',    'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'this', 'that', 'i', 'you', 'he', 'she', 'it', 'we', 'they']
        common_digrams = ['th', 'he', 'in', 'er', 'an', 're', 'ed', 'on', 'es', 'st', 'en', 'at', 'to', 'nt', 'ha', 'nd', 'ou', 'de', 'ne', 'ea', 'io', 'ro', 'li', 'ra', 'te', 'co', 'mu', 'ti', 'as', 'hi', 'al', 'ma', 'is']
        score = 0
        text_lower = text.lower()
        
        for word in common_words:
            score += text_lower.count(word) * 2
        for digram in common_digrams:
            score += text_lower.count(digram)

        score -= sum(1 for char in text if not char.isalpha() and not char.isspace() and not char.isdigit()) * 0.8
        
        if len(text) < 10:
            score -= 5
        
        return score

    def has_english_words(self, text: str) -> bool:
        return self.score_english(text) > 5

    def decode_all(self, text: str) -> Dict[str, str]:
        results = {}
        for name, decoder_func in self.decoders.items():
            if decoder_func:
                try:
                    # Attempt decode regardless of formal detection score for deep analysis
                    decoded_text = decoder_func(text)
                    if decoded_text and decoded_text != text and not decoded_text.startswith("Error during decoding") and not decoded_text.startswith("Requires"):
                        # Only return results that show some promise (better English score or contains flag/keyword)
                        if self.score_english(decoded_text) > self.score_english(text) or detect_flags(decoded_text) or any(kw in decoded_text.lower() for kw in SUSP_KEYWORDS):
                            results[name] = decoded_text
                except Exception:
                    continue # Skip failed decodes silently
        return results

    # --- Cipher/Encoding specific functions (helpers for detect/decode) ---
    def caesar_shift(self, text: str, shift: int) -> str:
        result = []
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - ascii_offset + shift) % 26
                result.append(chr(shifted + ascii_offset))
            else:
                result.append(char)
        return ''.join(result)

    def rot47_cipher(self, text: str) -> str:
        result = []
        for char in text:
            char_ord = ord(char)
            if 33 <= char_ord <= 126:
                result.append(chr(33 + (char_ord - 33 + 47) % 94))
            else:
                result.append(char)
        return ''.join(result)

    def rot5_cipher(self, text: str) -> str:
        result = []
        for char in text:
            if char.isdigit():
                result.append(str((int(char) + 5) % 10))
            else:
                result.append(char)
        return ''.join(result)

    def rot18_cipher(self, text: str) -> str:
        temp_text = self.rot5_cipher(text)
        return self.caesar_shift(temp_text, 13)

    def rot8000_cipher(self, text: str) -> str:
        result = []
        for char in text:
            char_ord = ord(char)
            if 0x4e00 <= char_ord <= 0x9fa5:
                result.append(chr(0x4e00 + (char_ord - 0x4e00 + 8000) % (0x9fa5 - 0x4e00 + 1)))
            else:
                result.append(char)
        return ''.join(result)

    def atbash_cipher(self, text: str) -> str:
        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result.append(chr(ord('A') + (ord('Z') - ord(char))))
                else:
                    result.append(chr(ord('a') + (ord('z') - ord(char))))
            else:
                result.append(char)
        return ''.join(result)

    def affine_decrypt(self, text: str, a: int, b: int) -> str:
        def mod_inverse(a_val: int, m: int) -> int:
            for x in range(1, m):
                if (a_val * x) % m == 1:
                    return x
            raise ValueError(f"No modular inverse for {a_val} mod {m}")
    
        a_inv = mod_inverse(a, 26)
        result = []
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                y = ord(char) - ascii_offset
                x = (a_inv * (y - b)) % 26
                result.append(chr(x + ascii_offset))
            else:
                result.append(char)
        return ''.join(result)

    def vigenere_decrypt(self, text: str, key: str) -> str:
        result = []
        key = key.upper()
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                if char.isupper():
                    result.append(chr(ord('A') + (ord(char) - ord('A') - shift) % 26))
                else:
                    result.append(chr(ord('a') + (ord(char) - ord('a') - shift) % 26))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)

    def rail_fence_decrypt(self, text: str, rails: int) -> str:
        if rails <= 1 or len(text) == 0:
            return text
        
        fence = [['\n'] * len(text) for _ in range(rails)]
        
        dir_down = False
        row, col = 0, 0
        for _ in range(len(text)):
            if (row == 0) or (row == rails - 1):
                dir_down = not dir_down
            fence[row][col] = '*'
            col += 1
            if dir_down:
                row += 1
            else:
                row -= 1
        
        index = 0
        for r in range(rails):
            for c in range(len(text)):
                if fence[r][c] == '*':
                    fence[r][c] = text[index]
                    index += 1
        
        result = []
        row, col = 0, 0
        dir_down = False
        for _ in range(len(text)):
            if (row == 0) or (row == rails - 1):
                dir_down = not dir_down
            result.append(fence[row][col])
            if dir_down:
                row += 1
            else:
                row -= 1
            col += 1
        return ''.join(result)

    def columnar_decrypt(self, text: str, key_length: int) -> str:
        if key_length <= 1 or len(text) == 0:
            return text

        num_cols = key_length
        num_rows = math.ceil(len(text) / num_cols)
        
        col_lengths = [num_rows] * num_cols
        remainder = len(text) % num_cols
        if remainder != 0:
            for i in range(remainder, num_cols):
                col_lengths[i] -= 1

        cols = [[] for _ in range(num_cols)]
        current_idx = 0
        for i in range(num_cols):
            cols[i] = list(text[current_idx : current_idx + col_lengths[i]])
            current_idx += col_lengths[i]
        
        plaintext = []
        for r in range(num_rows):
            for c in range(num_cols):
                if r < len(cols[c]):
                    plaintext.append(cols[c][r])
        return ''.join(plaintext)

    def keyboard_shift(self, text: str, layout_name: str) -> str:
        layouts = {
            'qwerty': {'q': 'w', 'w': 'e', 'e': 'r', 'r': 't', 't': 'y', 'y': 'u', 'u': 'i', 'i': 'o', 'o': 'p', 'p': '[', 'a': 's', 's': 'd', 'd': 'f', 'f': 'g', 'g': 'h', 'h': 'j', 'j': 'k', 'k': 'l', 'l': ';', ';': "'", 'z': 'x', 'x': 'c', 'c': 'v', 'v': 'b', 'b': 'n', 'n': 'm', 'm': ',', ',': '.', '.': '/'},
            'dvorak': {'p': 'y', 'y': 'f', 'f': 'g', 'g': 'c', 'c': 'r', 'r': 'l', 'l': 'a', 'a': 'o', 'o': 'e', 'e': 'u', 'u': 'i', 'i': 'd', 'd': 'h', 'h': 't', 't': 'n', 'n': 's', 's': 'q', 'q': 'j', 'j': 'k', 'k': 'x', 'x': 'b', 'b': 'm', 'm': 'w', 'w': 'v', 'v': 'z', 'z': ','},
            'azerty': {'a': 'z', 'z': 'e', 'e': 'r', 'r': 't', 't': 'y', 'y': 'u', 'u': 'i', 'i': 'o', 'o': 'p', 'p': '^', 'q': 's', 's': 'd', 'd': 'f', 'f': 'g', 'g': 'h', 'h': 'j', 'j': 'k', 'k': 'l', 'l': 'm', 'm': 'ù', 'w': 'x', 'x': 'c', 'c': 'v', 'v': 'b', 'b': 'n', 'n': ',', ',': ';', ';': ':'}
        }
        
        shift_map = layouts.get(layout_name, {})
        reverse_shift_map = {v: k for k, v in shift_map.items()}

        result = []
        for char in text.lower():
            result.append(reverse_shift_map.get(char, char))
        return ''.join(result)

    # Generic decoding helper with English scoring
    def decode_with_english_scoring(self, text: str, decoder_func, param_range: Any) -> str:
        best_decoded = ""
        best_score = -1.0
        
        for param in param_range:
            try:
                if decoder_func.__name__ == 'vigenere_decrypt':
                    decoded = decoder_func(text, param)
                elif decoder_func.__name__ == 'skip_cipher_decrypt':
                    decoded = self.skip_cipher_decrypt(text, param)
                elif param is None:
                    decoded = decoder_func(text)
                else:
                    decoded = decoder_func(text, param)
                    
                score = self.score_english(decoded)
                if score > best_score:
                    best_score = score
                    best_decoded = decoded
            except Exception:
                continue
        return best_decoded

    # --- Detection Methods (Minimal implementation, only for structure consistency) ---
    def detect_base16(self, text: str) -> bool: return len(text.strip().replace(' ', '')) >= 2 and len(text.strip().replace(' ', '')) % 2 == 0 and bool(re.match(r'^[0-9A-Fa-f]+$', text.strip().replace(' ', '')))
    def detect_base32(self, text: str) -> bool: return len(text.strip().replace(' ', '')) >= 8 and len(text.strip().replace(' ', '')) % 8 == 0 and bool(re.match(r'^[A-Z2-7]+=*$', text.strip().replace(' ', '').upper()))
    def detect_base45(self, text: str) -> bool: return len(text.strip().replace(' ', '')) >= 2 and bool(re.match(r'^[0-9A-Z $%*+\-./:]+$', text.strip().replace(' ', '')))
    def detect_base58(self, text: str) -> bool: alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; return len(text.strip()) >= 4 and all(c in alphabet for c in text.strip())
    def detect_base64(self, text: str) -> bool: return len(text.strip()) >= 4 and len(text.strip()) % 4 == 0 and bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', text.strip()))
    def detect_base85(self, text: str) -> bool: return len(text.strip().replace(' ', '')) >= 5 and bool(re.match(r'^[!"#$%&\'()*+,\-./0-9:;<=>?@A-Z[\\\]^_`a-z{|}~]+$', text.strip().replace(' ', '')))
    def detect_base91(self, text: str) -> bool: return len(text.strip()) >= 2
    def detect_base92(self, text: str) -> bool: return len(text.strip()) >= 2
    def detect_ascii_hex(self, text: str) -> bool: return bool(re.search(r'\\x[0-9A-Fa-f]{2}', text))
    def detect_binary(self, text: str) -> bool: return len(text.strip().replace(' ', '')) >= 8 and len(text.strip().replace(' ', '')) % 8 == 0 and bool(re.match(r'^[01]+$', text.strip().replace(' ', '')))
    def detect_octal(self, text: str) -> bool: return len(text.strip().replace(' ', '')) >= 3 and len(text.strip().replace(' ', '')) % 3 == 0 and bool(re.match(r'^[0-7]+$', text.strip().replace(' ', '')))
    def detect_decimal(self, text: str) -> bool: parts = text.strip().split(); return len(parts) >= 2 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    def detect_hex(self, text: str) -> bool: return len(text.strip().replace(' ', '').replace('-', '').replace('0x', '')) >= 2 and len(text.strip().replace(' ', '').replace('-', '').replace('0x', '')) % 2 == 0 and bool(re.match(r'^[0-9A-Fa-f]+$', text.strip().replace(' ', '').replace('-', '').replace('0x', '')))
    def detect_url_encoding(self, text: str) -> bool: return '%' in text and bool(re.search(r'%[0-9A-Fa-f]{2}', text))
    def detect_double_url(self, text: str) -> bool: return self.detect_url_encoding(text) and '%25' in text
    def detect_html_entities(self, text: str) -> bool: return bool(re.search(r'&[a-zA-Z]{2,10};', text))
    def detect_html_decimal(self, text: str) -> bool: return bool(re.search(r'&#[0-9]{2,5};', text))
    def detect_html_hex(self, text: str) -> bool: return bool(re.search(r'&#x[0-9A-Fa-f]{2,4};', text))
    def detect_xml_entities(self, text: str) -> bool: return bool(re.search(r'&(amp|lt|gt|quot|apos);', text))
    def detect_caesar(self, text: str) -> bool: return len(''.join(filter(str.isalpha, text))) >= 10
    def detect_rot13(self, text: str) -> bool: return len(''.join(filter(str.isalpha, text))) >= 5
    def detect_rot47(self, text: str) -> bool: return len(''.join(filter(lambda c: 33 <= ord(c) <= 126, text))) >= 5
    def detect_rot5(self, text: str) -> bool: return any(c.isdigit() for c in text)
    def detect_rot18(self, text: str) -> bool: return any(c.isdigit() for c in text) or any(c.isalpha() for c in text)
    def detect_rot8000(self, text: str) -> bool: return any(0x4e00 <= ord(c) <= 0x9fa5 for c in text)
    def detect_atbash(self, text: str) -> bool: return len(''.join(filter(str.isalpha, text))) >= 5
    def detect_affine(self, text: str) -> bool: return len(''.join(filter(str.isalpha, text)).upper()) >= 10
    def detect_vigenere(self, text: str) -> bool: clean_text = re.sub(r'[^A-Za-z]', '', text); return len(clean_text) >= 20 and len(set(clean_text.lower())) > 15
    def detect_bacon(self, text: str) -> bool: clean = re.sub(r'[^A-Za-z]', '', text).upper(); unique_chars = sorted(list(set(clean))); return len(clean) >= 10 and len(unique_chars) == 2 or (len(unique_chars) > 2 and all(c in 'AB' for c in unique_chars))
    def detect_polybius(self, text: str) -> bool: clean = re.sub(r'[^1-5]', '', text); return len(clean) >= 4 and len(clean) % 2 == 0 and bool(re.match(r'^[1-5]+$', clean))
    def detect_adfgx(self, text: str) -> bool: clean = re.sub(r'[^ADFGX]', '', text, flags=re.IGNORECASE); return len(clean) >= 4 and len(clean) % 2 == 0 and bool(re.match(r'^[ADFGX]+$', clean.upper()))
    def detect_rail_fence(self, text: str) -> bool: return len(re.sub(r'[^A-Za-z]', '', text)) >= 10
    def detect_columnar(self, text: str) -> bool: return len(re.sub(r'[^A-Za-z]', '', text)) >= 15
    def detect_reverse(self, text: str) -> bool: return len(text) >= 3
    def detect_keyboard_qwerty(self, text: str) -> bool: return len(text) > 3
    def detect_keyboard_dvorak(self, text: str) -> bool: return len(text) > 3
    def detect_keyboard_azerty(self, text: str) -> bool: return len(text) > 3
    def detect_morse(self, text: str) -> bool: clean = re.sub(r'[^.\-/\s]', '', text); return len(clean) >= 3 and (clean.count('.') + clean.count('-')) > 0
    def detect_tap_code(self, text: str) -> bool: clean = re.sub(r'[^.\s]', '', text); return len(clean) >= 4 and bool(re.match(r'^(\.+ +)+\.+$', clean.strip()))
    def detect_quoted_printable(self, text: str) -> bool: return '=' in text and (bool(re.search(r'=[0-9A-Fa-f]{2}', text)) or '=\n' in text)
    def detect_a1z26(self, text: str) -> bool: parts = re.split(r'[ \-]', text.strip()); numbers = [int(p) for p in parts if p.isdigit()]; valid_nums = sum(1 for n in numbers if 1 <= n <= 26); return len(numbers) > 0 and (valid_nums / len(numbers) > 0.7)
    def detect_leet_speak(self, text: str) -> bool: leet_chars = {'4', '@', '3', '8', '1', '!', '7', '+', '5', '$', '0', '(', '|'}; return any(c in text for c in leet_chars)
    def detect_skip_cipher(self, text: str) -> bool: return len(re.sub(r'[^A-Za-z]', '', text)) >= 15
    def detect_uuencode(self, text: str) -> bool: lines = text.strip().split('\n'); return len(lines) >= 2 and lines[0].startswith('begin ') and lines[-1] == 'end'
    def detect_xxencode(self, text: str) -> bool: lines = text.strip().split('\n'); return len(lines) >= 2 and lines[0].startswith('begin ') and lines[-1] == 'end'
    def detect_playfair(self, text: str) -> bool: return len(re.sub(r'[^A-Za-z]', '', text)) >= 6
    def detect_semaphore(self, text: str) -> bool: return False
    def detect_md5(self, text: str) -> bool: return False
    def detect_sha1(self, text: str) -> bool: return False
    def detect_sha256(self, text: str) -> bool: return False
    def detect_sha512(self, text: str) -> bool: return False
    def detect_whitespace(self, text: str) -> bool: return False
    def detect_zero_width(self, text: str) -> bool: return False
    def detect_brainfuck(self, text: str) -> bool: return False
    def detect_ook(self, text: str) -> bool: return False
    def detect_malbolge(self, text: str) -> bool: return False
    def detect_pigpen(self, text: str) -> bool: return False
    def detect_grille_cipher(self, text: str) -> bool: return False

    # --- Decoding methods (Includes size guards and manual decode placeholders for speed) ---
    def decode_base16(self, text: str) -> str:
        text = text.strip().replace(' ', '')
        return base64.b16decode(text.upper()).decode('utf-8', errors='ignore')

    def decode_base32(self, text: str) -> str:
        text = text.strip().replace(' ', '').upper()
        missing_padding = len(text) % 8
        text += '=' * (8 - missing_padding)
        return base64.b32decode(text).decode('utf-8', errors='ignore')

    def decode_base45(self, text: str) -> str: return "Requires dedicated library."
    
    def decode_base58(self, text: str) -> str:
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        base_count = len(alphabet)
        decoded_int = 0
        
        for char in text:
            if char not in alphabet:
                raise ValueError("Invalid Base58 character")
            decoded_int = decoded_int * base_count + alphabet.index(char)
        
        result_bytes = bytearray()
        while decoded_int > 0:
            result_bytes.append(decoded_int % 256)
            decoded_int //= 256
        result_bytes.reverse()

        for char in text:
            if char == '1':
                result_bytes.insert(0, 0)
            else:
                break
        
        return result_bytes.decode('utf-8', errors='ignore')

    def decode_base64(self, text: str) -> str:
        text = text.strip()
        missing_padding = len(text) % 4
        text += '=' * (4 - missing_padding)
        return base64.b64decode(text).decode('utf-8', errors='ignore')

    def decode_base85(self, text: str) -> str:
        return base64.a85decode(text.encode('ascii'), adobe=False).decode('utf-8', errors='ignore') if not (text.startswith('<~') and text.endswith('~>')) else base64.a85decode(text.encode('ascii')).decode('utf-8', errors='ignore')
    
    def decode_base91(self, text: str) -> str: return "Requires custom implementation."
    def decode_base92(self, text: str) -> str: return "Requires custom implementation."
    def decode_ascii_hex(self, text: str) -> str: return re.sub(r'\\x[0-9A-Fa-f]{2}', lambda match: chr(int(match.group(0)[2:], 16)), text)
    def decode_binary(self, text: str) -> str: text = text.strip().replace(' ', ''); return ''.join(chr(int(text[i:i+8], 2)) for i in range(0, len(text), 8))
    def decode_octal(self, text: str) -> str: text = text.strip().replace(' ', ''); return ''.join(chr(int(text[i:i+3], 8)) for i in range(0, len(text), 3))
    def decode_decimal(self, text: str) -> str: return ''.join(chr(int(part)) for part in text.strip().split())
    def decode_hex(self, text: str) -> str: text = text.strip().replace(' ', '').replace('-', '').replace('0x', ''); return binascii.unhexlify(text).decode('utf-8', errors='ignore')
    def decode_url_encoding(self, text: str) -> str: return urllib.parse.unquote(text)
    def decode_double_url(self, text: str) -> str: return urllib.parse.unquote(urllib.parse.unquote(text))
    def decode_html_entities(self, text: str) -> str: return html.unescape(text)
    def decode_html_decimal(self, text: str) -> str: return html.unescape(text)
    def decode_html_hex(self, text: str) -> str: return html.unescape(text)
    def decode_xml_entities(self, text: str) -> str: return html.unescape(text)
    def decode_rot13(self, text: str) -> str: return self.caesar_shift(text, 13)
    def decode_rot47(self, text: str) -> str: return self.rot47_cipher(text)
    def decode_rot5(self, text: str) -> str: return self.rot5_cipher(text)
    def decode_rot18(self, text: str) -> str: return self.rot18_cipher(text)
    def decode_rot8000(self, text: str) -> str: return self.rot8000_cipher(text)
    def decode_atbash(self, text: str) -> str: return self.atbash_cipher(text)
    def decode_reverse(self, text: str) -> str: return text[::-1]
    def decode_keyboard_qwerty(self, text: str) -> str: return self.keyboard_shift(text, 'qwerty')
    def decode_keyboard_dvorak(self, text: str) -> str: return self.keyboard_shift(text, 'dvorak')
    def decode_keyboard_azerty(self, text: str) -> str: return self.keyboard_shift(text, 'azerty')
    def decode_morse(self, text: str) -> str: return self.decode_with_english_scoring(text, self.decode_morse_logic, [None])
    def decode_tap_code(self, text: str) -> str: return self.decode_with_english_scoring(text, self.decode_tap_code_logic, [None])
    def decode_quoted_printable(self, text: str) -> str: return self.decode_quoted_printable_logic(text)
    def decode_a1z26(self, text: str) -> str: return self.decode_a1z26_logic(text)
    def decode_leet_speak(self, text: str) -> str: return self.decode_leet_speak_logic(text)

    # === OPTIMIZED/PLACEHOLDER SLOW DECODERS ===
    
    def decode_caesar(self, text: str) -> str:
        # Caesar (ROT) is fast enough to run automatically (25 shifts max)
        if len(text) > 5000: return "" # Aggressive size limit
        return self.decode_with_english_scoring(text, self.caesar_shift, range(1, 26))

    def decode_affine(self, text: str) -> str: 
        if len(text) > 5000: 
            return "Requires Manual/External Decode: Affine Cipher (Too slow for mass analysis)"
        if self.detect_affine(text):
            return "Requires Manual/External Decode: Affine Cipher (Too slow for mass analysis)"
        return ""

    def decode_vigenere(self, text: str) -> str: 
        if len(text) > 5000: 
            return "Requires Manual/External Decode: Vigenere Cipher (Key-guessing is slow)"
        if self.detect_vigenere(text):
            return "Requires Manual/External Decode: Vigenere Cipher (Key-guessing is slow)"
        return ""

    def decode_rail_fence(self, text: str) -> str: 
        if len(text) > 10000: 
            return "Requires Manual/External Decode: Rail Fence Cipher (Too slow for mass analysis)"
        if self.detect_rail_fence(text):
            return "Requires Manual/External Decode: Rail Fence Cipher (Too slow for mass analysis)"
        return ""

    def decode_columnar(self, text: str) -> str: 
        if len(text) > 10000: 
            return "Requires Manual/External Decode: Columnar Transposition (Too slow for mass analysis)"
        if self.detect_columnar(text):
            return "Requires Manual/External Decode: Columnar Transposition (Too slow for mass analysis)"
        return ""

    def decode_skip_cipher(self, text: str) -> str: 
        if len(text) > 10000: 
            return "Requires Manual/External Decode: Skip Cipher (Too slow for mass analysis)"
        if self.detect_skip_cipher(text):
            return "Requires Manual/External Decode: Skip Cipher (Too slow for mass analysis)"
        return ""
        
    # === END OPTIMIZED/PLACEHOLDER SLOW DECODERS ===
    
    # Placeholder functions for complex decoders
    def skip_cipher_decrypt(self, text: str, skip: int) -> str:
        clean_text = re.sub(r'[^A-Za-z]', '', text)
        num_groups = skip
        groups = [[] for _ in range(num_groups)]
        for i, char in enumerate(clean_text): groups[i % num_groups].append(char)
        return ''.join(itertools.chain.from_iterable(groups))

    def decode_quoted_printable_logic(self, text: str) -> str:
        decoded_text = text.replace('=\n', '')
        return re.sub(r'=[0-9A-Fa-f]{2}', lambda match: chr(int(match.group()[1:], 16)), decoded_text)
        
    def decode_morse_logic(self, text: str) -> str:
        morse_code_map = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z'}
        words = text.strip().split('   ')
        decoded_words = []
        for word in words:
            letters = word.strip().split(' ')
            decoded_words.append(''.join(morse_code_map.get(letter, '') for letter in letters))
        return ' '.join(decoded_words)
        
    def decode_tap_code_logic(self, text: str) -> str:
        tap_square = [['A', 'B', 'C', 'D', 'E'], ['F', 'G', 'H', 'I', 'J'], ['L', 'M', 'N', 'O', 'P'], ['Q', 'R', 'S', 'T', 'U'], ['V', 'W', 'X', 'Y', 'Z']]
        clean = re.sub(r'[^.\s]', '', text)
        groups = clean.strip().split(' ')
        result = []
        for s in groups:
            sub_groups = s.split('.')
            if len(sub_groups) == 2 and sub_groups[0] and sub_groups[1]:
                row_idx = len(sub_groups[0]) - 1
                col_idx = len(sub_groups[1]) - 1
                if 0 <= row_idx < 5 and 0 <= col_idx < 5:
                    result.append(tap_square[row_idx][col_idx])
                else:
                    result.append('?')
            else:
                result.append('?')
        return ''.join(result)
        
    def decode_a1z26_logic(self, text: str) -> str:
        parts = re.split(r'[ \-]', text.strip())
        return ''.join(chr(ord('A') + int(p) - 1) if p.isdigit() and 1 <= int(p) <= 26 else p for p in parts)
        
    def decode_leet_speak_logic(self, text: str) -> str:
        leet_to_normal_map = {'4': 'a', '@': 'a', '3': 'e', '8': 'b', '1': 'l', '!': 'i', '7': 't', '+': 't', '5': 's', '$': 's', '0': 'o', '(': 'c', '|': 'i'}
        decoded_text = text.lower()
        for lc, nc in sorted(leet_to_normal_map.items(), key=lambda item: len(item[0]), reverse=True):
            decoded_text = decoded_text.replace(lc, nc)
        return decoded_text.capitalize()


# ------------------------------ SHADOW ENGINE ------------------------------
class ShadowEngine:
    def __init__(self, pcap_path: str, basic_scan: bool = False, ctf_mode: bool = False, 
                 auto_solve: bool = False, config_path: Optional[str] = None): # NEW: CTF parameters
        self.pcap = Path(pcap_path)
        self.basic_scan = basic_scan # NEW: Store scan mode
        self.ctf_mode = ctf_mode  # NEW: CTF mode flag
        self.auto_solve = auto_solve  # NEW: Auto-solve flag
        self.config_path = config_path  # NEW: Config file path
        
        scan_type = "Basic Scan (v2.0.0)" if self.basic_scan else "Deep Scan (v5.0.0)"
        version_str = "2.0.0-giga" if self.basic_scan else VERSION
        if self.ctf_mode:
            scan_type += " [CTF Mode]"
        console.print(f"[bold magenta]ShadowParse v{version_str}[/] | {scan_type} | Loading packets, this might take a moment...")
        self.packets = rdpcap(str(self.pcap))
        self.total_packets = len(self.packets)
        console.print(f"[bold green]✓ Loaded {self.total_packets} packets from {self.pcap.name}[/]")

        # Data Structures
        self.traffic = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.dns_queries: List[str] = []
        self.dns_responses: Dict[str, List[str]] = defaultdict(list)
        self.flags: List[str] = []
        self.weird: List[Dict] = []
        self.protocols_summary = Counter()
        self.http_requests: List[Dict] = []
        self.file_extractions: List[Dict] = []
        self.high_entropy_data: List[Dict] = []
        self.deepread_decodes: List[Dict] = [] # Only used in Deep Scan
        self.unique_ports = set() # NEW: To track all unique ports seen
        
        # CTF Mode structures
        self.ctf_solver_results: List[Dict] = []
        self.challenge_category: Optional[Dict] = None
        self.ctf_hints: List[Dict] = []
        
        # Initialize CTF modules if enabled
        if self.ctf_mode and CTF_MODULES_AVAILABLE:
            self.ctf_solver = CTFAutoSolver() if self.auto_solve else None
            self.categorizer = ChallengeCategorizer()
            self.hint_engine = HintEngine()
            self.flag_submitter = FlagSubmitter(config_path) if config_path else None
            console.print("[bold cyan]✓ CTF Mode enabled with auto-solver and hint engine[/]")
        else:
            self.ctf_solver = None
            self.categorizer = None
            self.hint_engine = None
            self.flag_submitter = None

        # Deep Scan only structures
        if not self.basic_scan:
            self.tcp_sessions: Dict[Tuple, bytes] = defaultdict(bytes)
            self.udp_sessions: Dict[Tuple, bytes] = defaultdict(bytes)
            self.suspicious_packet_nums = set() 
            self.deep_decoder = UltimateEncodingDetector()


    # Helper to get flow key (copied for standalone function definition)
    def get_flow_key(self, pkt) -> Tuple[str, int, str, int] | None:
        if not (IP in pkt and (TCP in pkt or UDP in pkt)): return None
        proto = TCP if TCP in pkt else UDP
        src, dst, sport, dport = pkt[IP].src, pkt[IP].dst, pkt[proto].sport, pkt[proto].dport
        a, b = (src, sport), (dst, dport)
        if a > b: a, b = b, a
        return a + b

    # --- Deep Scan Logic (Previously _deep_hunt_attempt) ---
    def _deep_flag_hunt(self, data: bytes, src: str, dst: str, proto_info: str, pkt_num: int, depth: int = 0):
        # CRITICAL PERFORMANCE GUARD: Limit depth to 2, add payload size limit (1MB)
        if depth > 2 or not data or len(data) > 1000000: 
            return
            
        text = data.decode("utf-8", errors="ignore")
        
        def get_timestamp_str(p_num):
            if p_num == -1: return "N/A (Stream)"
            return datetime.fromtimestamp(float(self.packets[p_num].time)).strftime("%Y-%m-%d %H:%M:%S")
        
        timestamp_str = get_timestamp_str(pkt_num)


        # --- 0. High Entropy Check (only on initial call) ---
        if depth == 0 and pkt_num != -1:
            data_entropy = entropy(data) 
            if data_entropy > ENTROPY_THRESHOLD:
                self.high_entropy_data.append({
                    "type": f"{proto_info}_HIGH_ENTROPY", "src": src, "dst": dst, "pkt_num": pkt_num,
                    "note": f"Entropy: {data_entropy:.2f}, Layer: {proto_info}", "payload": data.hex(),
                    "timestamp": timestamp_str
                })
                self.suspicious_packet_nums.add(pkt_num)

        # --- 1. Plain Text/Keyword/Flag Check ---
        flag_list = detect_flags(text) 
        if flag_list:
            self.flags.extend(flag_list)
            for flag in flag_list:
                self.weird.append({"type": f"{proto_info}_TEXT_FLAG_D{depth}", "src": src, "dst": dst, "note": flag, "pkt_num": pkt_num, "timestamp": timestamp_str})
                if pkt_num != -1: self.suspicious_packet_nums.add(pkt_num)
        
        for kw in SUSP_KEYWORDS:
            if kw in text.lower():
                self.weird.append({"type": f"{proto_info}_KEYWORD_D{depth}", "src": src, "dst": dst, "note": f"'{kw}' found (L{depth})", "pkt_num": pkt_num, "timestamp": timestamp_str})
                if pkt_num != -1: self.suspicious_packet_nums.add(pkt_num)
                
        # --- 2. DeepRead Universal Decoder (PERFORMANCE CRITICAL SECTION) ---
        decoded_results = self.deep_decoder.decode_all(text)
        
        best_score = self.deep_decoder.score_english(text)

        for decode_type, decoded_text in decoded_results.items():
            current_score = self.deep_decoder.score_english(decoded_text)
            
            # Log successful deep decodes
            self.deepread_decodes.append({
                "type": f"{proto_info}_{decode_type.upper()}_DECODE_D{depth}", "src": src, "dst": dst, 
                "note": f"Decoded from {decode_type} (L{depth}). Score: {current_score:.2f}. Result: {decoded_text[:100]}...",
                "pkt_num": pkt_num, "timestamp": timestamp_str, "decoded_text": decoded_text
            })
            if pkt_num != -1: self.suspicious_packet_nums.add(pkt_num)

            # Recursive call on the new decoded data
            decoded_bytes = decoded_text.encode("utf-8", errors="ignore")
            # Recurse only if the score is significantly better (pruning the search tree) or contains a flag.
            if current_score > best_score + 10 or detect_flags(decoded_text):
                 self._deep_flag_hunt(decoded_bytes, src, dst, proto_info, pkt_num, depth + 1)
            
        # --- 3. Traditional Decodes (Used as fallbacks for binary types) ---
        
        # base64 (for raw bytes that don't convert to clean text well)
        if depth == 0 and len(data) > 30 and entropy(data) < ENTROPY_THRESHOLD:
            try:
                decoded_b64 = is_base64(data.decode("utf-8", errors="ignore"))
                if decoded_b64 and self.deep_decoder.score_english(decoded_b64) > best_score:
                    self._deep_flag_hunt(decoded_b64.encode("utf-8"), src, dst, proto_info + "_B64", pkt_num, depth + 1)
            except Exception: pass

        # gzip
        if data.startswith(b"\x1f\x8b"):
            try:
                gz_dec = gzip.decompress(data)
                self._deep_flag_hunt(gz_dec, src, dst, proto_info + "_GZIP", pkt_num, depth + 1)
            except Exception: pass
    
    # --- Basic Scan Logic (Renamed from _recursive_flag_hunt in v2.0.0) ---
    def _basic_flag_hunt(self, data: bytes, src: str, dst: str, proto_info: str):
        # This is the original, faster v2.0.0 logic
        text = data.decode("utf-8", errors="ignore")

        # 0. High Entropy Check 
        data_entropy = entropy(data)
        if data_entropy > ENTROPY_THRESHOLD:
            self.high_entropy_data.append({
                "type": f"{proto_info}_HIGH_ENTROPY", "src": src, "dst": dst,
                "note": f"Entropy: {data_entropy:.2f}, Payload: {data[:50].hex()}...",
                "payload": data.hex(),
            })

        # 1. plain text
        for flag in detect_flags(text):
            self.flags.append(flag)
            self.weird.append({"type": f"{proto_info}_TEXT", "src": src, "dst": dst, "note": flag})
        
        # 2. URL-encoded
        try:
            url_dec = urllib.parse.unquote(text)
            if url_dec != text:
                for flag in detect_flags(url_dec):
                    self.flags.append(flag)
                    self.weird.append({"type": f"{proto_info}_URL", "src": src, "dst": dst, "note": flag})
        except Exception:
            pass

        # 3. base64
        for b64_match in re.findall(r"(?:[A-Za-z0-9+/]{" + str(MIN_B64_LEN) + r",})={0,2}", text):
            decoded_b64 = is_base64(b64_match)
            if decoded_b64:
                for flag in detect_flags(decoded_b64):
                    self.flags.append(flag)
                    self.weird.append({"type": f"{proto_info}_B64", "src": src, "dst": dst, "note": flag})
        
        # 4. hex
        for hex_match in re.findall(r"(?:[0-9A-Fa-f]{2}){"+ str(MIN_B64_LEN) + r",}", text):
            try:
                hex_dec = bytes.fromhex(hex_match).decode("utf-8", errors="ignore")
                for flag in detect_flags(hex_dec):
                    self.flags.append(flag)
                    self.weird.append({"type": f"{proto_info}_HEX", "src": src, "dst": dst, "note": flag})
            except Exception:
                pass


    # ---------- dissect ----------
    def dissect(self):
        # Set the appropriate hunter function based on scan mode
        hunter_func = self._basic_flag_hunt if self.basic_scan else self._deep_flag_hunt
        
        # Determine total work for progress bar description
        desc = "[green]Dissecting packets (Basic Scan)..." if self.basic_scan else "[green]Pass 1: Building Streams and Metadata (Deep Scan)..."
        
        for pkt_num, pkt in enumerate(track(self.packets, description=desc)):
            src, dst = "Unknown", "Unknown"
            proto_name = "UNKNOWN"
            app_layer_payload = None
            flow_key = None # Initialize flow_key

            if Ether in pkt:
                self.protocols_summary["ETHERNET"] += 1

            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
                proto_name = pkt[IP].summary().split()[2] if len(pkt[IP].summary().split()) > 2 else "IP"
                self.protocols_summary[proto_name] += 1
            elif ARP in pkt:
                src, dst = pkt[ARP].psrc, pkt[ARP].pdst
                proto_name = "ARP"
                self.protocols_summary[proto_name] += 1
            elif ICMP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst if IP in pkt else "Unknown", "Unknown"
                proto_name = "ICMP"
                self.protocols_summary[proto_name] += 1

            pair = f"{src} -> {dst}"
            self.traffic[pair]["packets"] += 1
            self.traffic[pair]["bytes"] += len(pkt)
            
            # --- Port Tracking ---
            if TCP in pkt:
                self.unique_ports.add(pkt[TCP].sport)
                self.unique_ports.add(pkt[TCP].dport)
            if UDP in pkt:
                self.unique_ports.add(pkt[UDP].sport)
                self.unique_ports.add(pkt[UDP].dport)


            # --- DNS Analysis ---
            if pkt.haslayer(DNS):
                if pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname.decode().rstrip(".")
                    self.dns_queries.append(qname)
                    if self.basic_scan:
                        hunter_func(qname.encode("utf-8"), src, dst, "DNS_QUERY")
                    else: # Deep Scan
                        self._deep_flag_hunt(qname.encode("utf-8"), src, dst, "DNS_QUERY", pkt_num)
                if pkt.haslayer(DNSRR) and self.basic_scan: # Basic scan only runs on RDATA if it's there
                    for i in range(pkt[DNS].ancount):
                        rr = pkt[DNS].an[i]
                        if hasattr(rr, 'rdata') and isinstance(rr.rdata, bytes):
                            hunter_func(rr.rdata, src, dst, "DNS_RESPONSE")


            # --- Application Layer Payload Hunt & Stream Building ---
            if pkt.haslayer(Raw):
                app_layer_payload = bytes(pkt[Raw].load)
            
            if HTTP_LAYERS_AVAILABLE:
                if pkt.haslayer(HTTPRequest):
                    host = pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else "N/A"
                    path = pkt[HTTPRequest].Path.decode() if pkt[HTTPRequest].Path else "N/A"
                    method = pkt[HTTPRequest].Method.decode() if pkt[HTTPRequest].Method else "N/A"
                    
                    if not self.basic_scan: # Deep Scan uses full context
                        user_agent = pkt[HTTPRequest]['User-Agent'].decode() if 'User-Agent' in pkt[HTTPRequest].fields else "N/A"
                        referer = pkt[HTTPRequest]['Referer'].decode() if 'Referer' in pkt[HTTPRequest].fields else "N/A"
                        self.http_requests.append({"src": src, "dst": dst, "method": method, "host": host, "path": path, "ua": user_agent, "ref": referer, "pkt_num": pkt_num})
                        self._deep_flag_hunt(bytes(pkt[HTTPRequest]), src, dst, "HTTP_HEADERS", pkt_num)
                    else: # Basic Scan
                        self.http_requests.append({"src": src, "dst": dst, "method": method, "host": host, "path": path, "pkt_num": pkt_num})
                        hunter_func(bytes(pkt[HTTPRequest]), src, dst, "HTTP_REQUEST")
                        
                    if pkt.haslayer(Raw):
                        if self.basic_scan:
                            hunter_func(app_layer_payload, src, dst, "HTTP_REQUEST_BODY")
                        else:
                            self._deep_flag_hunt(app_layer_payload, src, dst, "HTTP_BODY", pkt_num)

                if pkt.haslayer(HTTPResponse) and app_layer_payload:
                    if self.basic_scan:
                        hunter_func(app_layer_payload, src, dst, "HTTP_RESPONSE_BODY")
                    # Simplified file extraction logic (kept for both modes)
                    if b"Content-Type" in bytes(pkt[HTTPResponse]):
                        content_type_match = re.search(b"Content-Type: ([^\r\n]+)", bytes(pkt[HTTPResponse]))
                        if content_type_match:
                            content_type = content_type_match.group(1).decode("utf-8", errors="ignore").strip()
                            if len(app_layer_payload) > 0:
                                filename_match = re.search(b"filename=[\"']?([^\"';\r\n]+)", bytes(pkt[HTTPResponse]))
                                filename = filename_match.group(1).decode("utf-8", errors="ignore") if filename_match else f"extracted_file_{pkt_num}.{content_type.split('/')[-1].split(';')[0]}"
                                self.file_extractions.append({"filename": filename, "content_type": content_type, "src": src, "dst": dst, "pkt_num": pkt_num, "payload": app_layer_payload})

            # --- Deep Scan: Stream Reconstruction (Deep Scan Only) ---
            if not self.basic_scan and (TCP in pkt or UDP in pkt) and app_layer_payload:
                flow_key = self.get_flow_key(pkt)
                if flow_key:
                    if TCP in pkt: self.tcp_sessions[flow_key] += app_layer_payload
                    elif UDP in pkt: self.udp_sessions[flow_key] += app_layer_payload
            
            # --- Basic Scan: Direct Payload Hunt (Basic Scan Only) ---
            if self.basic_scan and (TCP in pkt or UDP in pkt) and app_layer_payload:
                layer_name = TCP.__name__ if TCP in pkt else UDP.__name__
                sport, dport = pkt[layer_name].sport, pkt[layer_name].dport
                proto_info = f"{layer_name}_{COMMON_PORTS.get(sport, COMMON_PORTS.get(dport, f'{sport}/{dport}'))}"
                hunter_func(app_layer_payload, src, dst, proto_info)

            # --- ICMP Deep Hunt ---
            if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
                if not self.basic_scan:
                    self._deep_flag_hunt(bytes(pkt[Raw].load), src, dst, "ICMP_DATA", pkt_num)


        # --- Pass 2: Analyze Reconstructed Streams (Deep Scan Only) ---
        if not self.basic_scan:
            console.print("[yellow]Pass 2: Analyzing Reconstructed Streams (Deep Hunt)...[/yellow]")
            
            # TCP Stream Analysis
            desc = "[cyan]Analyzing TCP Streams...[/cyan]"
            for flow_key, stream_data in track(self.tcp_sessions.items(), description=desc):
                if len(stream_data) > 0:
                    src_ip, src_port, dst_ip, dst_port = flow_key
                    proto_info = f"TCP_STREAM_{COMMON_PORTS.get(src_port, '') or COMMON_PORTS.get(dst_port, '') or f'{src_port}/{dst_port}'}"
                    self._deep_flag_hunt(stream_data, src_ip, dst_ip, proto_info, -1) 

            # UDP Stream Analysis 
            desc = "[cyan]Analyzing UDP Streams...[/cyan]"
            for flow_key, stream_data in track(self.udp_sessions.items(), description=desc):
                if len(stream_data) > 0:
                    src_ip, src_port, dst_ip, dst_port = flow_key
                    proto_info = f"UDP_STREAM_{COMMON_PORTS.get(src_port, '') or COMMON_PORTS.get(dst_port, '') or f'{src_port}/{dst_port}'}"
                    self._deep_flag_hunt(stream_data, src_ip, dst_ip, proto_info, -1)


    # ---------- outputs & file save enhancements ----------

    def save_flags_json(self, out_dir: Path):
        """NEW: Save a JSON file with only the unique captured flags."""
        out_dir.mkdir(exist_ok=True)
        json_file = out_dir / "flags.json"
        
        flags_data = {"flags": sorted(list(set(self.flags)))}
        
        with open(json_file, "w") as fp:
            json.dump(flags_data, fp, indent=2)
            
        console.print(f"[green]💾 JSON Flags Report saved → {json_file}")


    def save_filtered_pcap(self, out_dir: Path):
        if self.basic_scan:
            console.print("[yellow]Skipping filtered PCAP: Only available in Deep Scan mode.[/yellow]")
            return
            
        filtered_pkts = [self.packets[i] for i in sorted(list(self.suspicious_packet_nums)) if i < len(self.packets)]
        if not filtered_pkts:
            console.print("[yellow]No suspicious packets identified for filtered PCAP export.[/yellow]")
            return

        pcap_file = out_dir / "suspicious_traffic.pcap"
        wrpcap(str(pcap_file), filtered_pkts)
        console.print(f"[green]💾 Filtered PCAP saved ({len(filtered_pkts)} packets) → {pcap_file}")

    def save_decoded_text_file(self, out_dir: Path):
        if self.basic_scan:
            console.print("[yellow]Skipping DeepRead Decoded Text: Only available in Deep Scan mode.[/yellow]")
            return

        decoded_file = out_dir / "deepread_decoded_text.txt"
        
        # ... (rest of the logic for saving deepread_decoded_text.txt remains the same) ...
        with open(decoded_file, "w", encoding="utf-8") as f:
            f.write(f"--- ShadowParse v{VERSION} DeepRead Decoded Text Report ---\n")
            f.write(f"Source PCAP: {self.pcap.name}\n")
            f.write(f"Generated: {datetime.utcnow():%F %T} UTC\n\n")

            if self.deepread_decodes:
                f.write("--- DEEPREAD UNIVERSAL DECODER RESULTS ---\n\n")
                
                # Sort by packet number for easy timeline correlation
                sorted_decodes = sorted(self.deepread_decodes, key=lambda x: x.get('pkt_num', -1))
                
                for i, decode in enumerate(sorted_decodes):
                    pkt_info = f"Pkt #{decode['pkt_num']}" if decode.get('pkt_num', -1) >= 0 else "Stream Data"
                    f.write(f"[{i+1}] {decode['type']} ({pkt_info}) | {decode['timestamp']}\n")
                    f.write(f"Flow: {decode['src']} -> {decode['dst']}\n")
                    f.write(f"Note: {decode['note']}\n")
                    f.write("-" * 5 + " DECODED TEXT " + "-" * 5 + "\n")
                    f.write(decode['decoded_text'] + "\n\n")
            else:
                f.write("No successful deep decodes were found by the DeepRead Universal Decoder.\n")

        console.print(f"[green]💾 Decoded Text Report saved → {decoded_file}")


    def save_high_entropy_payloads(self, out_dir: Path):
        # ... (logic remains the same) ...
        entropy_dir = out_dir / "high_entropy_payloads"
        if not self.high_entropy_data: return
        entropy_dir.mkdir(exist_ok=True)
        count = 0
        for i, data in enumerate(self.high_entropy_data):
            try:
                payload_bytes = bytes.fromhex(data['payload'])
                filename = f"{i:03d}_{data['type']}_{data['pkt_num']}.bin" if not self.basic_scan else f"{i:03d}_{data['type']}.bin"
                with open(entropy_dir / filename, "wb") as f:
                    f.write(payload_bytes)
                count += 1
            except Exception as e:
                console.print(f"[bold red]Error saving high entropy payload {i}:[/bold red] {e}")

        if count > 0: console.print(f"[green]💾 {count} High Entropy Payloads saved → {entropy_dir}")


    def to_df(self) -> pd.DataFrame:
        # ... (logic remains the same) ...
        records = [
            {"Pair": pair, "Packets": stats["packets"], "Bytes": stats["bytes"], "Avg_Packet_Size": stats["bytes"] / stats["packets"] if stats["packets"] > 0 else 0}
            for pair, stats in self.traffic.items()
        ]
        return pd.DataFrame(records).sort_values("Packets", ascending=False)

    def save_json(self, out_dir: Path):
        out_dir.mkdir(exist_ok=True)
        json_file = out_dir / "shadow_report.json"
        
        report_data = {
            "traffic_summary": dict(self.traffic), "protocol_summary": dict(self.protocols_summary),
            "dns_queries": self.dns_queries, "dns_responses": dict(self.dns_responses),
            "flags": list(set(self.flags)), "weird_events": self.weird,
            "http_requests": self.http_requests,
            "high_entropy_data": [{k: v for k, v in item.items() if k != "payload"} for item in self.high_entropy_data], 
            "file_extractions": [{k: v for k, v in item.items() if k != "payload"} for item in self.file_extractions],
            "unique_ports": sorted(list(self.unique_ports)) # NEW: Ports list
        }
        
        if not self.basic_scan:
             report_data["deepread_decodes"] = self.deepread_decodes
             
        with open(json_file, "w") as fp:
            json.dump(report_data, fp, indent=2)
            
        console.print(f"[green]💾 JSON report saved → {json_file}")

    def save_markdown(self, out_dir: Path):
        md_file = out_dir / "shadow_report.md"
        
        scan_type = "Deep Scan" if not self.basic_scan else "Basic Scan"
        md = f"# ShadowParse {scan_type} Report\n"
        md += f"**File:** `{self.pcap.name}`  \n"
        md += f"**Generated:** {datetime.utcnow():%F %T} UTC  \n"
        md += f"**ShadowParse Version:** {VERSION}  \n"
        md += f"**Total Packets Processed:** {self.total_packets}  \n\n"

        md += "## 📊 Global Statistics\n"
        md += f"- **Total Unique Flags:** {len(set(self.flags))}\n"
        md += f"- **Total Weird Events:** {len(self.weird)}\n"
        if not self.basic_scan:
            md += f"- **Total DeepRead Decodes:** {len(self.deepread_decodes)}\n" 
            md += f"- **Total Suspicious Packets (for filtered PCAP):** {len(self.suspicious_packet_nums)}\n"
        md += f"- **Total High Entropy Payloads:** {len(self.high_entropy_data)}\n\n"

        # NEW: Unique Ports List
        md += "## 📡 Unique Transport Ports\n"
        if self.unique_ports:
            # Sort ports numerically and list them, 15 per line
            sorted_ports = sorted(list(self.unique_ports))
            port_list = [str(p) for p in sorted_ports]
            
            md += "```\n"
            for i in range(0, len(port_list), 15):
                md += ", ".join(port_list[i:i+15]) + "\n"
            md += "```\n\n"
        else:
            md += "No TCP/UDP ports observed.\n\n"


        # Protocols Summary (logic remains the same)
        md += "## 🌐 Protocol Distribution\n"
        if self.protocols_summary:
            proto_table = Table(show_header=True, header_style="bold magenta", title="Protocol Breakdown")
            proto_table.add_column("Protocol", style="dim")
            proto_table.add_column("Count", justify="right")
            proto_table.add_column("% Total", justify="right")
            total_pkts_for_proto_calc = sum(self.protocols_summary.values())
            for proto, count in self.protocols_summary.most_common():
                percent = (count / total_pkts_for_proto_calc) * 100 if total_pkts_for_proto_calc > 0 else 0
                proto_table.add_row(proto, str(count), f"{percent:.2f}%")
            console.print(proto_table)
            md += console.export_text() + "\n\n"
        else:
            md += "No protocol data found.\n\n"

        md += "## 📈 Traffic Matrix (Top 20 Source-Destination Pairs)\n"
        traffic_df = self.to_df()
        if not traffic_df.empty:
            tbl = Table(show_header=True, header_style="bold cyan")
            tbl.add_column("Pair", style="dim")
            tbl.add_column("Packets", justify="right")
            tbl.add_column("Bytes", justify="right")
            tbl.add_column("Avg. Pkt Size", justify="right")
            for _, row in traffic_df.head(20).iterrows():
                tbl.add_row(row["Pair"], str(row["Packets"]), str(row["Bytes"]), f"{row['Avg_Packet_Size']:.2f}")
            console.print(tbl)
            md += console.export_text() + "\n\n"
        else:
            md += "No traffic data found.\n\n"


        md += "## 🏁 Flags Captured\n"
        if self.flags:
            for f in sorted(list(set(self.flags))):
                md += f"- [bold green]`{f}`[/bold green]\n"
            md += "\n"
        else:
            md += "No flags captured. Keep hunting!\n\n"

        md += "## 🕵️ High Entropy Payloads (Potential Obfuscation/Encryption)\n"
        if self.high_entropy_data:
            md += f"**(Raw payloads saved to `./high_entropy_payloads/` for manual inspection.)**\n"
            for i, w in enumerate(self.high_entropy_data):
                pkt_info = f"[Pkt #{w['pkt_num']}]" if not self.basic_scan else ""
                md += f"- **[{i+1}] {w['type']}** {pkt_info} {w['src']} → {w['dst']} | Entropy: {w['note'].split(':')[-1].strip()}\n"
                md += f"  * [Payload HEX Sample]: `{w['payload'][:100]}...`\n"
            md += "\n"
        else:
            md += "No high entropy payloads detected.\n\n"

        md += "## 🧨 Weirdness Gallery (Suspicious Activities & Decoded Data)\n"
        if self.weird:
            for i, w in enumerate(sorted(self.weird, key=lambda x: x.get('pkt_num', -1) if not self.basic_scan else 0)):
                pkt_info = f"[Pkt #{w['pkt_num']}]" if not self.basic_scan and w.get('pkt_num', -1) >= 0 else "[Stream Data]" if not self.basic_scan else ""
                md += f"- **[{i+1}] {w['type']}** {pkt_info} {w['src']} → {w['dst']} | {w['note'][:200]}\n"
            md += "\n"
        else:
            md += "No weirdness detected. Clean traffic!\n\n"
            
        if not self.basic_scan:
            md += "## 🔓 DeepRead Universal Decoder Results\n"
            if self.deepread_decodes:
                md += f"**(Full decoded text saved to `./deepread_decoded_text.txt`)**\n"
                for i, d in enumerate(sorted(self.deepread_decodes, key=lambda x: x.get('pkt_num', -1))[:20]):
                    pkt_info = f"[Pkt #{d['pkt_num']}]" if d.get('pkt_num', -1) >= 0 else "[Stream Data]"
                    md += f"- **[{i+1}] {d['type']}** {pkt_info} | {d['note']}\n"
                md += "\n"
            else:
                md += "No successful deep decodes found.\n\n"

        # ... (rest of the sections: DNS, HTTP, Files) ...
        md += "## 🕸️ DNS Analysis\n"
        if self.dns_queries or self.dns_responses:
            md += "### DNS Queries (Top 20)\n"
            if self.dns_queries:
                dns_query_counts = Counter(self.dns_queries)
                for q, count in dns_query_counts.most_common(20):
                    md += f"- `{q}` ({count} queries)\n"
            else:
                md += "No DNS queries observed.\n"

            md += "\n### DNS Responses (Associated IPs/Data)\n"
            if self.dns_responses:
                for qname, rdata_list in list(self.dns_responses.items())[:20]:
                    md += f"- **Query:** `{qname}`\n"
                    for rdata in set(rdata_list):
                        md += f"  - **Response:** `{rdata}`\n"
            else:
                md += "No DNS responses observed.\n"
            md += "\n"
        else:
            md += "No DNS traffic found.\n\n"

        md += "## 🌐 HTTP Activity\n"
        if self.http_requests:
            md += "### HTTP Requests (Top 20)\n"
            http_req_table = Table(show_header=True, header_style="bold yellow", title="HTTP Requests")
            http_req_table.add_column("Packet #", justify="right")
            http_req_table.add_column("Source", style="dim")
            http_req_table.add_column("Destination", style="dim")
            http_req_table.add_column("Method", style="cyan")
            http_req_table.add_column("Host", style="magenta")
            http_req_table.add_column("Path")
            for req in self.http_requests[:20]:
                http_req_table.add_row(str(req['pkt_num']), req['src'], req['dst'], req['method'], req['host'], req['path'][:70])
            console.print(http_req_table)
            md += console.export_text() + "\n\n"
        else:
            md += "No HTTP requests observed.\n\n"

        md += "## 💾 Extracted Files (HTTP Payloads)\n"
        if self.file_extractions:
            file_table = Table(show_header=True, header_style="bold green", title="Extracted Files")
            file_table.add_column("Packet #", justify="right")
            file_table.add_column("Filename")
            file_table.add_column("Content Type")
            file_table.add_column("Size (bytes)", justify="right")
            extracted_files_dir = out_dir / "extracted_files"
            extracted_files_dir.mkdir(exist_ok=True)

            for i, file_data in enumerate(self.file_extractions):
                original_filename = file_data['filename']
                safe_filename = "".join([c if c.isalnum() or c in ('.', '_', '-') else '_' for c in original_filename])
                if not safe_filename.strip():
                    safe_filename = f"unnamed_file_{file_data['pkt_num']}_{i}"
                if not '.' in safe_filename and '.' in file_data['content_type']:
                     safe_filename += f".{file_data['content_type'].split('/')[-1].split(';')[0]}"


                file_path = extracted_files_dir / safe_filename
                with open(file_path, "wb") as f:
                    f.write(file_data['payload'])
                md += f"- [bold green]`{original_filename}`[/bold green] (Type: `{file_data['content_type']}`, Size: {len(file_data['payload'])} bytes) saved to `{file_path.name}`\n"
                file_table.add_row(str(file_data['pkt_num']), original_filename[:70], file_data['content_type'], str(len(file_data['payload'])))
            console.print(file_table)
            md += console.export_text() + "\n\n"
            md += f"All extracted files saved to `{extracted_files_dir}`\n\n"
        else:
            md += "No files extracted from HTTP traffic.\n\n"
            
        with open(md_file, "w", encoding="utf-8") as fp:
            fp.write(md)
        console.print(f"[green]📝 Markdown report saved → {md_file}")


    def run(self, out: str, show_hints: bool = False, submit_flags: bool = False):
        out_path = Path(out)
        self.dissect()
        
        # Run CTF analysis if enabled
        if self.ctf_mode and CTF_MODULES_AVAILABLE:
            self._run_ctf_analysis(submit_flags)
        
        # Save all the new enriched data
        self.save_json(out_path)
        self.save_markdown(out_path)
        self.save_flags_json(out_path) # NEW: Save flags only JSON
        self.save_high_entropy_payloads(out_path)
        
        if not self.basic_scan:
            self.save_filtered_pcap(out_path)
            self.save_decoded_text_file(out_path)
        
        # Save CTF-specific outputs
        if self.ctf_mode and CTF_MODULES_AVAILABLE:
            self._save_ctf_outputs(out_path, show_hints)

        console.print(Panel(Text("🎉 ShadowParse Scan Complete!", justify="center", style="bold green reverse"),
                            border_style="green", expand=False))
        
        absolute_path = out_path.absolute()
        console.print(f"[bold white]Results saved to folder:[/bold white] [underline blue]{absolute_path}[/underline blue]")
    
    def _run_ctf_analysis(self, submit_flags: bool = False):
        """Run CTF-specific analysis"""
        console.print("[bold cyan]Running CTF Analysis...[/]")
        
        # Run auto-solver on high entropy data and extracted files
        if self.auto_solve and self.ctf_solver:
            console.print("[cyan]Running auto-solvers...[/]")
            for entry in self.high_entropy_data[:10]:  # Limit to top 10
                try:
                    data = bytes.fromhex(entry['payload'][:2000])  # Limit size
                    results = self.ctf_solver.run_all_solvers(data)
                    if results:
                        self.ctf_solver_results.append({
                            'source': f"High entropy packet {entry['pkt_num']}",
                            'results': results
                        })
                except Exception:
                    pass
            
            # Run solvers on extracted files
            for file_data in self.file_extractions[:5]:  # Limit to 5 files
                try:
                    payload = file_data.get('payload', b'')
                    if len(payload) > 0 and len(payload) < 100000:  # Max 100KB
                        results = self.ctf_solver.run_all_solvers(payload)
                        if results:
                            self.ctf_solver_results.append({
                                'source': f"File: {file_data.get('filename', 'unknown')}",
                                'results': results
                            })
                except Exception:
                    pass
        
        # Categorize the challenge
        if self.categorizer:
            analysis_data = self._prepare_analysis_data()
            self.challenge_category = self.categorizer.analyze_and_categorize(analysis_data)
            console.print(f"[green]✓ Challenge categorized as: {self.challenge_category['primary_category']} "
                         f"(confidence: {self.challenge_category['primary_confidence']:.2f})[/]")
        
        # Generate hints
        if self.hint_engine:
            analysis_data = self._prepare_analysis_data()
            self.ctf_hints = self.hint_engine.generate_hints(analysis_data)
            console.print(f"[green]✓ Generated {len(self.ctf_hints)} contextual hints[/]")
        
        # Submit flags if enabled
        if submit_flags and self.flag_submitter and self.flag_submitter.is_enabled():
            console.print("[cyan]Submitting flags...[/]")
            for flag in self.flags[:5]:  # Limit submissions
                result = self.flag_submitter.submit_flag(flag, require_confirmation=False)
                if result['success']:
                    console.print(f"[green]✓ Flag accepted: {flag}[/]")
                else:
                    console.print(f"[yellow]✗ Flag submission failed: {result.get('message')}[/]")
    
    def _prepare_analysis_data(self) -> Dict[str, Any]:
        """Prepare data for CTF analysis"""
        # Count keywords
        keywords = {}
        for entry in self.weird:
            note = entry.get('note', '').lower()
            for keyword in SUSP_KEYWORDS:
                if keyword in note:
                    keywords[keyword] = keywords.get(keyword, 0) + 1
        
        # Detect patterns
        sql_patterns = ['union', 'select', 'or 1=1']
        xss_patterns = ['<script>', 'javascript:']
        
        sql_detected = any(any(p in entry.get('note', '').lower() for p in sql_patterns) for entry in self.weird)
        xss_detected = any(any(p in entry.get('note', '').lower() for p in xss_patterns) for entry in self.weird)
        
        # Count file types
        image_files = sum(1 for f in self.file_extractions if 'image' in f.get('content_type', '').lower())
        audio_files = sum(1 for f in self.file_extractions if 'audio' in f.get('content_type', '').lower())
        executable_files = sum(1 for f in self.file_extractions 
                              if any(ext in f.get('filename', '').lower() 
                                    for ext in ['.exe', '.dll', '.so', '.elf']))
        
        return {
            'high_entropy_count': len(self.high_entropy_data),
            'flags_found': len(self.flags),
            'keywords': keywords,
            'base64_patterns': sum(1 for d in self.deepread_decodes if 'base64' in d.get('encoding', '').lower()),
            'hex_patterns': sum(1 for d in self.deepread_decodes if 'hex' in d.get('encoding', '').lower()),
            'encoding_layers': max((d.get('depth', 0) for d in self.deepread_decodes), default=0),
            'files_extracted': len(self.file_extractions),
            'suspicious_packets': len(self.weird),
            'protocols_count': len(self.protocols_summary),
            'http_requests': len(self.http_requests),
            'sql_injection_detected': sql_detected,
            'xss_detected': xss_detected,
            'dns_queries': len(self.dns_queries),
            'unusual_dns': len([q for q in self.dns_queries if len(q) > 50 or '.' not in q[-10:]]),
            'unusual_ports': [p for p in self.unique_ports if p > 1024 and p not in COMMON_PORTS],
            'image_files': image_files,
            'audio_files': audio_files,
            'executable_files': executable_files,
            'successful_decodes': len([d for d in self.deepread_decodes if d.get('success', False)]),
            'base64_non_printable': any('base64' in d.get('encoding', '').lower() and 
                                       not all(c in string.printable for c in d.get('decoded', '')[:100])
                                       for d in self.deepread_decodes),
        }
    
    def _save_ctf_outputs(self, out_path: Path, show_hints: bool):
        """Save CTF-specific output files"""
        out_path.mkdir(exist_ok=True)
        
        # Save auto-solver results
        if self.ctf_solver_results:
            solver_file = out_path / "auto_solver_results.txt"
            with open(solver_file, 'w') as f:
                f.write("=== Auto-Solver Results ===\n\n")
                for result in self.ctf_solver_results:
                    f.write(f"Source: {result['source']}\n")
                    f.write("-" * 60 + "\n")
                    for method, findings in result['results'].items():
                        f.write(f"\n{method}:\n")
                        for finding in findings[:3]:  # Top 3 per method
                            f.write(f"  - Result: {finding.get('result', '')[:200]}\n")
                            f.write(f"    Confidence: {finding.get('confidence', 0):.2f}\n")
                    f.write("\n" + "=" * 60 + "\n\n")
        
        # Save CTF analysis
        ctf_analysis_file = out_path / "ctf_analysis.md"
        with open(ctf_analysis_file, 'w') as f:
            f.write("# CTF Challenge Analysis\n\n")
            
            if self.challenge_category:
                f.write("## Challenge Category\n\n")
                f.write(f"**Primary Category:** {self.challenge_category['primary_category']} ")
                f.write(f"(Confidence: {self.challenge_category['primary_confidence']:.2%})\n\n")
                if self.challenge_category['secondary_category']:
                    f.write(f"**Secondary Category:** {self.challenge_category['secondary_category']} ")
                    f.write(f"(Confidence: {self.challenge_category['secondary_confidence']:.2%})\n\n")
                
                f.write(f"\n{self.categorizer.get_category_description(self.challenge_category['primary_category'])}\n\n")
            
            if show_hints and self.ctf_hints:
                f.write("## Progressive Hints\n\n")
                for i, hint in enumerate(self.ctf_hints, 1):
                    level_emoji = {"basic": "💡", "intermediate": "🔍", "advanced": "🎯"}
                    emoji = level_emoji.get(hint.get('level', 'basic'), '💡')
                    f.write(f"{i}. {emoji} **[{hint.get('level', 'basic').upper()}]** {hint.get('hint', '')}\n\n")
            
            if self.challenge_category:
                f.write("## Recommended Tools\n\n")
                tools = self.hint_engine.get_tool_recommendations(self.challenge_category['primary_category'])
                for tool in tools:
                    f.write(f"- {tool}\n")
                f.write("\n")
        
        # Save tool recommendations
        if self.challenge_category:
            tools_file = out_path / "suggested_tools.txt"
            with open(tools_file, 'w') as f:
                f.write(f"Recommended Tools for {self.challenge_category['primary_category']}:\n\n")
                tools = self.hint_engine.get_tool_recommendations(self.challenge_category['primary_category'])
                for tool in tools:
                    f.write(f"- {tool}\n")
        
        # Save flag submission log
        if self.flag_submitter:
            self.flag_submitter.save_submission_log(out_path)


# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(
        description=f"ShadowParse – The Luxe PCAP Forensics Engine. "
                    "Unleash the power of deep packet inspection for CTFs and network analysis!"
    )
    parser.add_argument("-f", "--file", required=True, help="PCAP file to analyse")
    parser.add_argument("-o", "--output", default="shadow_deepscan_report", 
                        help="Output folder name. Use an absolute path (e.g., /media/user/DriveName/report) "
                             "to save to external storage. (default: shadow_deepscan_report)") # Storage help added
    parser.add_argument("-b", "--basic-scan", action="store_true",
                        help="Run in fast Basic Scan mode, skipping full TCP reconstruction and deep cipher analysis.") # New feature
    
    # CTF Mode arguments
    parser.add_argument("--ctf-mode", action="store_true",
                        help="Enable CTF-specific features (categorization, hints, enhanced reporting)")
    parser.add_argument("--auto-solve", action="store_true",
                        help="Run auto-solver tools (ROT, XOR, substitution ciphers, etc.)")
    parser.add_argument("--submit-flags", action="store_true",
                        help="Enable flag submission to CTF platforms (requires --config)")
    parser.add_argument("--hints", action="store_true",
                        help="Show progressive hints based on findings")
    parser.add_argument("--config", type=str, default=None,
                        help="Path to CTF configuration file (ctf_config.yaml)")
    
    args = parser.parse_args()

    # --- Basic Input Validation (PCAP) ---
    pcap_path = Path(args.file)
    if not pcap_path.exists():
        console.print(f"[bold red]Error:[/bold red] PCAP file '{args.file}' not found.")
        sys.exit(1)
    if not pcap_path.is_file():
        console.print(f"[bold red]Error:[/bold red] '{args.file}' is not a file.") 
        sys.exit(1)
        
    # --- Output Path Validation (Storage Check) ---
    out_path = Path(args.output)
    
    if out_path.is_absolute():
        if not out_path.parent.exists():
            console.print(f"[bold red]Error:[/bold red] The parent directory for the output path does not exist: '{out_path.parent}'. "
                          "Ensure your external drive is mounted and the path is correct (e.g., /media/user/DriveName).")
            sys.exit(1)
        
        try:
            os.makedirs(out_path, exist_ok=True)
        except OSError as e:
            console.print(f"[bold red]Error:[/bold red] Cannot write to the output path '{out_path}'. "
                          f"Check permissions or ensure the drive is not mounted read-only. Details: {e}")
            sys.exit(1)

    # Create config template if needed
    if args.ctf_mode and args.config and not Path(args.config).exists():
        console.print(f"[yellow]Config file not found. Creating template at {args.config}[/yellow]")
        if CTF_MODULES_AVAILABLE:
            create_config_template(Path(args.config).parent)

    # Run the engine (passing CTF parameters)
    engine = ShadowEngine(
        args.file, 
        basic_scan=args.basic_scan,
        ctf_mode=args.ctf_mode or args.auto_solve or args.hints,  # Enable CTF mode if any CTF flag is set
        auto_solve=args.auto_solve,
        config_path=args.config
    )
    engine.run(args.output, show_hints=args.hints, submit_flags=args.submit_flags)


if __name__ == "__main__":
    main()