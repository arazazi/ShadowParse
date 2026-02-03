#!/usr/bin/env python3
"""
Challenge Categorization System
Intelligently categorizes PCAP analysis into CTF challenge types
"""
from typing import Dict, List, Tuple, Any
from collections import Counter
import re


class ChallengeCategorizer:
    """Categorize CTF challenges based on PCAP analysis"""
    
    CATEGORIES = [
        'Cryptography',
        'Forensics',
        'Steganography',
        'Web Exploitation',
        'Network Analysis',
        'Reverse Engineering'
    ]
    
    def __init__(self):
        self.category_scores = {cat: 0.0 for cat in self.CATEGORIES}
    
    def analyze_and_categorize(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data and return categorization results"""
        self.category_scores = {cat: 0.0 for cat in self.CATEGORIES}
        
        # Cryptography indicators
        self._score_cryptography(analysis_data)
        
        # Forensics indicators
        self._score_forensics(analysis_data)
        
        # Steganography indicators
        self._score_steganography(analysis_data)
        
        # Web Exploitation indicators
        self._score_web_exploitation(analysis_data)
        
        # Network Analysis indicators
        self._score_network_analysis(analysis_data)
        
        # Reverse Engineering indicators
        self._score_reverse_engineering(analysis_data)
        
        # Normalize scores to 0-1 range
        max_score = max(self.category_scores.values()) if any(self.category_scores.values()) else 1
        normalized_scores = {
            cat: score / max_score if max_score > 0 else 0
            for cat, score in self.category_scores.items()
        }
        
        # Get primary and secondary categories
        sorted_categories = sorted(
            normalized_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        primary_category = sorted_categories[0] if sorted_categories else ('Unknown', 0)
        secondary_category = sorted_categories[1] if len(sorted_categories) > 1 and sorted_categories[1][1] > 0.3 else None
        
        return {
            'primary_category': primary_category[0],
            'primary_confidence': primary_category[1],
            'secondary_category': secondary_category[0] if secondary_category else None,
            'secondary_confidence': secondary_category[1] if secondary_category else 0,
            'all_scores': normalized_scores
        }
    
    def _score_cryptography(self, data: Dict[str, Any]):
        """Score cryptography indicators"""
        score = 0.0
        
        # High entropy data
        if data.get('high_entropy_count', 0) > 0:
            score += 3.0 * min(data['high_entropy_count'] / 10, 1.0)
        
        # Encoded data patterns
        if data.get('base64_patterns', 0) > 0:
            score += 2.0
        
        if data.get('hex_patterns', 0) > 0:
            score += 1.5
        
        # Cipher keywords
        crypto_keywords = ['cipher', 'encrypt', 'decrypt', 'key', 'aes', 'rsa', 'xor', 'rot', 'crypto', 'hash']
        for keyword in crypto_keywords:
            if data.get('keywords', {}).get(keyword, 0) > 0:
                score += 0.5
        
        # Multiple encoding layers
        if data.get('encoding_layers', 0) > 2:
            score += 2.0
        
        self.category_scores['Cryptography'] = score
    
    def _score_forensics(self, data: Dict[str, Any]):
        """Score forensics indicators"""
        score = 0.0
        
        # File extractions
        if data.get('files_extracted', 0) > 0:
            score += 3.0 * min(data['files_extracted'] / 5, 1.0)
        
        # Suspicious traffic patterns
        if data.get('suspicious_packets', 0) > 0:
            score += 2.0
        
        # Multiple protocols
        if data.get('protocols_count', 0) > 5:
            score += 1.5
        
        # Large payloads
        if data.get('large_payloads', 0) > 0:
            score += 1.0
        
        # Forensics keywords
        forensics_keywords = ['forensic', 'evidence', 'hidden', 'carve', 'extract', 'recover']
        for keyword in forensics_keywords:
            if data.get('keywords', {}).get(keyword, 0) > 0:
                score += 0.5
        
        self.category_scores['Forensics'] = score
    
    def _score_steganography(self, data: Dict[str, Any]):
        """Score steganography indicators"""
        score = 0.0
        
        # Image files
        if data.get('image_files', 0) > 0:
            score += 4.0
        
        # Audio files
        if data.get('audio_files', 0) > 0:
            score += 3.0
        
        # LSB patterns (if detected)
        if data.get('lsb_patterns', False):
            score += 3.0
        
        # Stego keywords
        stego_keywords = ['steg', 'hide', 'hidden', 'embed', 'watermark', 'lsb']
        for keyword in stego_keywords:
            if data.get('keywords', {}).get(keyword, 0) > 0:
                score += 1.0
        
        # Small modifications to images
        if data.get('similar_images', 0) > 1:
            score += 2.0
        
        self.category_scores['Steganography'] = score
    
    def _score_web_exploitation(self, data: Dict[str, Any]):
        """Score web exploitation indicators"""
        score = 0.0
        
        # HTTP traffic
        if data.get('http_requests', 0) > 0:
            score += 3.0
        
        # SQL injection patterns
        sql_patterns = ['union', 'select', 'or 1=1', 'drop table', 'exec', '--', '/*', '*/']
        if data.get('sql_injection_detected', False):
            score += 4.0
        
        # XSS patterns
        xss_patterns = ['<script>', 'javascript:', 'onerror', 'onload', 'alert(']
        if data.get('xss_detected', False):
            score += 4.0
        
        # Common web paths
        if data.get('web_paths', 0) > 0:
            score += 1.5
        
        # POST requests with data
        if data.get('post_requests', 0) > 0:
            score += 1.0
        
        # Cookie manipulation
        if data.get('cookie_manipulation', False):
            score += 2.0
        
        # Web keywords
        web_keywords = ['cookie', 'session', 'admin', 'login', 'auth', 'token', 'jwt', 'api']
        for keyword in web_keywords:
            if data.get('keywords', {}).get(keyword, 0) > 0:
                score += 0.5
        
        self.category_scores['Web Exploitation'] = score
    
    def _score_network_analysis(self, data: Dict[str, Any]):
        """Score network analysis indicators"""
        score = 0.0
        
        # DNS queries
        if data.get('dns_queries', 0) > 10:
            score += 2.0
        
        # Unusual DNS patterns
        if data.get('unusual_dns', False):
            score += 3.0
        
        # DNS tunneling indicators
        if data.get('dns_tunneling', False):
            score += 4.0
        
        # Covert channels
        if data.get('covert_channel', False):
            score += 4.0
        
        # Protocol abuse
        if data.get('protocol_abuse', False):
            score += 3.0
        
        # ICMP data
        if data.get('icmp_data', 0) > 0:
            score += 2.0
        
        # Unusual ports
        if data.get('unusual_ports', []):
            score += 1.5 * min(len(data['unusual_ports']) / 5, 1.0)
        
        # Network keywords
        network_keywords = ['tunnel', 'exfil', 'covert', 'channel', 'beacon', 'c2']
        for keyword in network_keywords:
            if data.get('keywords', {}).get(keyword, 0) > 0:
                score += 1.0
        
        self.category_scores['Network Analysis'] = score
    
    def _score_reverse_engineering(self, data: Dict[str, Any]):
        """Score reverse engineering indicators"""
        score = 0.0
        
        # Executable files
        if data.get('executable_files', 0) > 0:
            score += 4.0
        
        # Shellcode detected
        if data.get('shellcode_detected', False):
            score += 4.0
        
        # Binary data
        if data.get('binary_payloads', 0) > 0:
            score += 2.0
        
        # Obfuscated code
        if data.get('obfuscated_code', False):
            score += 3.0
        
        # Assembly instructions
        if data.get('assembly_detected', False):
            score += 3.0
        
        # Reverse engineering keywords
        re_keywords = ['disasm', 'decompile', 'binary', 'shellcode', 'exploit', 'payload', 'rop', 'overflow']
        for keyword in re_keywords:
            if data.get('keywords', {}).get(keyword, 0) > 0:
                score += 0.5
        
        self.category_scores['Reverse Engineering'] = score
    
    def get_category_description(self, category: str) -> str:
        """Get description for a category"""
        descriptions = {
            'Cryptography': 'This challenge involves decoding, decryption, or breaking cryptographic algorithms.',
            'Forensics': 'This challenge requires analyzing data, recovering files, or finding hidden information.',
            'Steganography': 'This challenge involves finding data hidden in images, audio, or other media files.',
            'Web Exploitation': 'This challenge involves exploiting web vulnerabilities like SQL injection or XSS.',
            'Network Analysis': 'This challenge requires analyzing network traffic patterns and protocols.',
            'Reverse Engineering': 'This challenge involves analyzing binary executables or shellcode.'
        }
        return descriptions.get(category, 'Unknown challenge category.')
