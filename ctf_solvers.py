#!/usr/bin/env python3
"""
CTF Auto-Solver Library
Integrates popular CTF solving techniques and tools
"""
import base64
import binascii
import re
import string
from collections import Counter
from typing import List, Dict, Optional, Tuple, Any
import itertools

# Optional imports with graceful degradation
try:
    from PIL import Image
    import io
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False

try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

try:
    from pwn import disasm, context
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False


class CTFAutoSolver:
    """Auto-solver for common CTF challenges"""
    
    def __init__(self):
        self.results = []
        
    def rot_all(self, text: str) -> List[Dict[str, Any]]:
        """Try all ROT variations (ROT1-ROT25)"""
        results = []
        if not text or not text.strip():
            return results
            
        for shift in range(1, 26):
            decoded = self._rot_n(text, shift)
            if decoded != text and self._looks_readable(decoded):
                results.append({
                    'method': f'ROT{shift}',
                    'result': decoded,
                    'confidence': self._calculate_readability_score(decoded)
                })
        
        return sorted(results, key=lambda x: x['confidence'], reverse=True)
    
    def _rot_n(self, text: str, n: int) -> str:
        """Apply ROT-N cipher"""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + n) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + n) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    def xor_bruteforce(self, data: bytes, max_key_length: int = 4) -> List[Dict[str, Any]]:
        """Bruteforce single and multi-byte XOR keys"""
        results = []
        
        # Single-byte XOR
        for key in range(1, 256):
            try:
                decoded = bytes([b ^ key for b in data])
                decoded_str = decoded.decode('utf-8', errors='ignore')
                if self._looks_readable(decoded_str):
                    results.append({
                        'method': f'XOR_single_byte',
                        'key': hex(key),
                        'result': decoded_str,
                        'confidence': self._calculate_readability_score(decoded_str)
                    })
            except Exception:
                continue
        
        # Multi-byte XOR (2-4 bytes)
        if len(data) >= 20 and max_key_length > 1:
            for key_len in range(2, min(max_key_length + 1, 5)):
                best_key = self._find_repeating_xor_key(data, key_len)
                if best_key:
                    try:
                        decoded = bytes([data[i] ^ best_key[i % len(best_key)] for i in range(len(data))])
                        decoded_str = decoded.decode('utf-8', errors='ignore')
                        if self._looks_readable(decoded_str):
                            results.append({
                                'method': f'XOR_{key_len}_byte',
                                'key': best_key.hex(),
                                'result': decoded_str,
                                'confidence': self._calculate_readability_score(decoded_str)
                            })
                    except Exception:
                        continue
        
        return sorted(results, key=lambda x: x['confidence'], reverse=True)[:5]
    
    def _find_repeating_xor_key(self, data: bytes, key_length: int) -> Optional[bytes]:
        """Find repeating XOR key using frequency analysis"""
        if len(data) < key_length * 4:
            return None
            
        key = []
        for i in range(key_length):
            # Extract bytes at positions i, i+key_length, i+2*key_length, ...
            block = bytes([data[j] for j in range(i, len(data), key_length)])
            # Most common English letter is 'e' (0x65) or space (0x20)
            # Try XORing with space
            freq = Counter(block)
            most_common = freq.most_common(1)[0][0]
            key.append(most_common ^ ord(' '))
        
        return bytes(key)
    
    def substitution_cipher_solver(self, text: str) -> List[Dict[str, Any]]:
        """Attempt to solve substitution ciphers using frequency analysis"""
        results = []
        
        if not text or len(text) < 50:
            return results
        
        # English letter frequency (most to least common)
        eng_freq = 'etaoinshrdlcumwfgypbvkjxqz'
        
        # Get frequency of letters in ciphertext
        text_lower = ''.join(c.lower() for c in text if c.isalpha())
        if len(text_lower) < 50:
            return results
            
        freq = Counter(text_lower)
        cipher_freq = ''.join([item[0] for item in freq.most_common()])
        
        # Create simple substitution map
        subst_map = {}
        for i, cipher_char in enumerate(cipher_freq[:len(eng_freq)]):
            if i < len(eng_freq):
                subst_map[cipher_char] = eng_freq[i]
        
        # Apply substitution
        decoded = []
        for char in text:
            if char.lower() in subst_map:
                new_char = subst_map[char.lower()]
                decoded.append(new_char.upper() if char.isupper() else new_char)
            else:
                decoded.append(char)
        
        decoded_str = ''.join(decoded)
        
        if self._looks_readable(decoded_str):
            results.append({
                'method': 'Substitution_Cipher_Frequency_Analysis',
                'result': decoded_str,
                'mapping': subst_map,
                'confidence': self._calculate_readability_score(decoded_str)
            })
        
        return results
    
    def detect_qr_code(self, image_data: bytes) -> List[Dict[str, Any]]:
        """Detect and decode QR codes from image data"""
        results = []
        
        if not PIL_AVAILABLE or not PYZBAR_AVAILABLE:
            return results
        
        try:
            image = Image.open(io.BytesIO(image_data))
            decoded_objects = pyzbar_decode(image)
            
            for obj in decoded_objects:
                results.append({
                    'method': 'QR_Code_Decode',
                    'type': obj.type,
                    'data': obj.data.decode('utf-8', errors='ignore'),
                    'confidence': 1.0
                })
        except Exception as e:
            pass
        
        return results
    
    def detect_barcode(self, image_data: bytes) -> List[Dict[str, Any]]:
        """Detect and decode barcodes from image data"""
        results = []
        
        if not PIL_AVAILABLE or not PYZBAR_AVAILABLE:
            return results
        
        try:
            image = Image.open(io.BytesIO(image_data))
            decoded_objects = pyzbar_decode(image)
            
            for obj in decoded_objects:
                if obj.type != 'QRCODE':  # Already handled by detect_qr_code
                    results.append({
                        'method': 'Barcode_Decode',
                        'type': obj.type,
                        'data': obj.data.decode('utf-8', errors='ignore'),
                        'confidence': 1.0
                    })
        except Exception as e:
            pass
        
        return results
    
    def detect_shellcode(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect potential shellcode patterns"""
        results = []
        
        # Common shellcode indicators
        indicators = [
            b'\xeb',  # jmp short
            b'\x90' * 4,  # NOP sled
            b'\x31\xc0',  # xor eax, eax
            b'\x50',  # push eax
            b'\xcc',  # int3 (breakpoint)
        ]
        
        score = 0
        for indicator in indicators:
            if indicator in data:
                score += 1
        
        if score >= 2 and len(data) > 20:
            results.append({
                'method': 'Shellcode_Detection',
                'result': 'Potential shellcode detected',
                'indicators_found': score,
                'confidence': min(score / len(indicators), 1.0)
            })
        
        return results
    
    def disassemble_binary(self, data: bytes, arch: str = 'i386') -> List[Dict[str, Any]]:
        """Disassemble binary data"""
        results = []
        
        if not PWNTOOLS_AVAILABLE or len(data) > 1024:
            return results
        
        try:
            context.arch = arch
            context.bits = 32 if arch == 'i386' else 64
            
            disassembly = disasm(data)
            if disassembly:
                results.append({
                    'method': f'Disassembly_{arch}',
                    'result': disassembly[:1000],  # Limit output
                    'confidence': 0.7
                })
        except Exception:
            pass
        
        return results
    
    def cyberchef_magic(self, data: bytes) -> List[Dict[str, Any]]:
        """CyberChef-like magic auto-detection and decoding"""
        results = []
        text = data.decode('utf-8', errors='ignore')
        
        # Chain 1: Base64 -> Gunzip -> From Hex
        try:
            decoded = base64.b64decode(text)
            import gzip
            decompressed = gzip.decompress(decoded)
            hex_decoded = binascii.unhexlify(decompressed)
            decoded_text = hex_decoded.decode('utf-8', errors='ignore')
            if self._looks_readable(decoded_text):
                results.append({
                    'method': 'CyberChef_Chain_Base64_Gunzip_Hex',
                    'result': decoded_text,
                    'confidence': self._calculate_readability_score(decoded_text)
                })
        except Exception:
            pass
        
        # Chain 2: Hex -> Base64 -> UTF-8
        try:
            hex_decoded = binascii.unhexlify(text.replace(' ', ''))
            b64_decoded = base64.b64decode(hex_decoded)
            decoded_text = b64_decoded.decode('utf-8', errors='ignore')
            if self._looks_readable(decoded_text):
                results.append({
                    'method': 'CyberChef_Chain_Hex_Base64',
                    'result': decoded_text,
                    'confidence': self._calculate_readability_score(decoded_text)
                })
        except Exception:
            pass
        
        # Chain 3: URL decode -> Base64
        try:
            import urllib.parse
            url_decoded = urllib.parse.unquote(text)
            b64_decoded = base64.b64decode(url_decoded)
            decoded_text = b64_decoded.decode('utf-8', errors='ignore')
            if self._looks_readable(decoded_text):
                results.append({
                    'method': 'CyberChef_Chain_URL_Base64',
                    'result': decoded_text,
                    'confidence': self._calculate_readability_score(decoded_text)
                })
        except Exception:
            pass
        
        return results
    
    def _looks_readable(self, text: str, min_printable_ratio: float = 0.7) -> bool:
        """Check if text looks readable (has high ratio of printable characters)"""
        if not text or len(text) < 4:
            return False
        
        printable = sum(1 for c in text if c in string.printable)
        ratio = printable / len(text)
        
        # Also check for common English words
        common_words = ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it']
        text_lower = text.lower()
        word_count = sum(1 for word in common_words if word in text_lower)
        
        return ratio >= min_printable_ratio or word_count >= 2
    
    def _calculate_readability_score(self, text: str) -> float:
        """Calculate readability score (0-1)"""
        if not text:
            return 0.0
        
        score = 0.0
        
        # Printable ratio
        printable = sum(1 for c in text if c in string.printable)
        score += (printable / len(text)) * 0.3
        
        # Letter ratio
        letters = sum(1 for c in text if c.isalpha())
        if len(text) > 0:
            score += (letters / len(text)) * 0.2
        
        # Space ratio (natural language has ~15-20% spaces)
        spaces = text.count(' ')
        space_ratio = spaces / len(text) if len(text) > 0 else 0
        if 0.1 <= space_ratio <= 0.3:
            score += 0.2
        
        # Common English words
        common_words = ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it', 'flag', 'ctf']
        text_lower = text.lower()
        word_count = sum(1 for word in common_words if word in text_lower)
        score += min(word_count / len(common_words), 1.0) * 0.3
        
        return min(score, 1.0)
    
    def run_all_solvers(self, data: bytes) -> Dict[str, List[Dict[str, Any]]]:
        """Run all auto-solvers on the data"""
        all_results = {}
        
        text = data.decode('utf-8', errors='ignore')
        
        # ROT all
        rot_results = self.rot_all(text)
        if rot_results:
            all_results['ROT_variations'] = rot_results[:3]  # Top 3
        
        # XOR bruteforce
        xor_results = self.xor_bruteforce(data)
        if xor_results:
            all_results['XOR_bruteforce'] = xor_results[:3]  # Top 3
        
        # Substitution cipher
        sub_results = self.substitution_cipher_solver(text)
        if sub_results:
            all_results['Substitution_cipher'] = sub_results
        
        # CyberChef magic
        magic_results = self.cyberchef_magic(data)
        if magic_results:
            all_results['CyberChef_chains'] = magic_results
        
        # Shellcode detection
        shellcode_results = self.detect_shellcode(data)
        if shellcode_results:
            all_results['Shellcode'] = shellcode_results
        
        # Binary disassembly (if looks like binary)
        if len(data) <= 512 and not text.isprintable():
            disasm_results = self.disassemble_binary(data)
            if disasm_results:
                all_results['Disassembly'] = disasm_results
        
        return all_results
