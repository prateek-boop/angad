"""
NetGuard - TLS Parser
Real SNI extraction and JA3/JA4 fingerprint generation
"""

import hashlib
import struct
import logging
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass

# TLS Constants
TLS_RECORD_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_EXTENSION_SNI = 0x0000
TLS_EXTENSION_SUPPORTED_VERSIONS = 0x002B
TLS_EXTENSION_ELLIPTIC_CURVES = 0x000A
TLS_EXTENSION_EC_POINT_FORMATS = 0x000B

# GREASE values (should be ignored in JA3)
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}


@dataclass
class TLSClientHello:
    """Parsed TLS ClientHello data"""
    tls_version: str
    cipher_suites: List[int]
    extensions: List[int]
    elliptic_curves: List[int]
    ec_point_formats: List[int]
    sni: Optional[str]
    ja3_hash: str
    ja3_string: str


class TLSParser:
    """
    Parser for TLS ClientHello packets.
    Extracts SNI (Server Name Indication) and computes JA3 fingerprints.
    
    JA3 Fingerprint Format:
    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    
    Example: 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11-35-13-15,23-24-25,0
    """
    
    def __init__(self):
        self.logger = logging.getLogger("TLS_PARSER")
    
    def parse_client_hello(self, data: bytes) -> Optional[TLSClientHello]:
        """
        Parse a TLS ClientHello message and extract all relevant fields.
        
        Args:
            data: Raw bytes of the TLS record (starting with record header)
            
        Returns:
            TLSClientHello object with parsed data, or None if parsing fails
        """
        try:
            return self._parse_client_hello_impl(data)
        except Exception as e:
            self.logger.debug(f"TLS parse error: {e}")
            return None
    
    def _parse_client_hello_impl(self, data: bytes) -> Optional[TLSClientHello]:
        """Internal implementation of ClientHello parsing"""
        if len(data) < 5:
            return None
        
        # TLS Record Header
        # [ContentType:1][Version:2][Length:2][Payload]
        content_type = data[0]
        if content_type != TLS_RECORD_HANDSHAKE:
            return None
        
        record_version = struct.unpack("!H", data[1:3])[0]
        record_length = struct.unpack("!H", data[3:5])[0]
        
        if len(data) < 5 + record_length:
            return None
        
        # Handshake Header
        # [HandshakeType:1][Length:3][ClientHello...]
        handshake = data[5:5+record_length]
        
        if len(handshake) < 4:
            return None
        
        handshake_type = handshake[0]
        if handshake_type != TLS_HANDSHAKE_CLIENT_HELLO:
            return None
        
        handshake_length = struct.unpack("!I", b'\x00' + handshake[1:4])[0]
        if handshake_length + 4 > len(handshake):
            return None
        handshake = handshake[:handshake_length + 4]
        
        # ClientHello structure
        # [Version:2][Random:32][SessionIDLen:1][SessionID:var][CipherSuitesLen:2][CipherSuites:var]
        # [CompressionLen:1][Compression:var][ExtensionsLen:2][Extensions:var]
        
        pos = 4  # After handshake header
        
        # Client Version
        if pos + 2 > len(handshake):
            return None
        client_version = struct.unpack("!H", handshake[pos:pos+2])[0]
        pos += 2
        
        # Random (32 bytes)
        if pos + 32 > len(handshake):
            return None
        pos += 32
        
        # Session ID
        if pos + 1 > len(handshake):
            return None
        session_id_len = handshake[pos]
        pos += 1
        if pos + session_id_len > len(handshake):
            return None
        pos += session_id_len
        
        # Cipher Suites
        if pos + 2 > len(handshake):
            return None
        cipher_suites_len = struct.unpack("!H", handshake[pos:pos+2])[0]
        pos += 2
        if cipher_suites_len % 2 or pos + cipher_suites_len > len(handshake):
            return None
        
        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            cs = struct.unpack("!H", handshake[pos:pos+2])[0]
            pos += 2
            if cs not in GREASE_VALUES:
                cipher_suites.append(cs)
        
        # Compression Methods
        if pos + 1 > len(handshake):
            return None
        compression_len = handshake[pos]
        pos += 1
        if pos + compression_len > len(handshake):
            return None
        pos += compression_len
        
        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        sni = None
        supported_versions = []
        
        if pos + 2 <= len(handshake):
            extensions_len = struct.unpack("!H", handshake[pos:pos+2])[0]
            pos += 2
            
            ext_end = pos + extensions_len
            if ext_end != len(handshake):
                return None
            
            while pos + 4 <= ext_end and pos + 4 <= len(handshake):
                ext_type = struct.unpack("!H", handshake[pos:pos+2])[0]
                ext_len = struct.unpack("!H", handshake[pos+2:pos+4])[0]
                pos += 4
                if pos + ext_len > ext_end:
                    return None
                
                ext_data = handshake[pos:pos+ext_len]
                pos += ext_len
                
                # Skip GREASE extensions
                if ext_type in GREASE_VALUES:
                    continue
                
                extensions.append(ext_type)
                
                # Parse specific extensions
                if ext_type == TLS_EXTENSION_SNI:
                    sni = self._parse_sni_extension(ext_data)
                elif ext_type == TLS_EXTENSION_SUPPORTED_VERSIONS:
                    supported_versions = self._parse_supported_versions(ext_data)
                elif ext_type == TLS_EXTENSION_ELLIPTIC_CURVES:
                    elliptic_curves = self._parse_elliptic_curves(ext_data)
                elif ext_type == TLS_EXTENSION_EC_POINT_FORMATS:
                    ec_point_formats = self._parse_ec_point_formats(ext_data)
        
        # Determine TLS version
        if supported_versions:
            tls_version = self._version_to_string(max(supported_versions))
        else:
            tls_version = self._version_to_string(client_version)
        
        # Compute JA3
        ja3_string = self._compute_ja3_string(
            client_version, cipher_suites, extensions, 
            elliptic_curves, ec_point_formats
        )
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        
        return TLSClientHello(
            tls_version=tls_version,
            cipher_suites=cipher_suites,
            extensions=extensions,
            elliptic_curves=elliptic_curves,
            ec_point_formats=ec_point_formats,
            sni=sni,
            ja3_hash=ja3_hash,
            ja3_string=ja3_string
        )
    
    def _parse_sni_extension(self, data: bytes) -> Optional[str]:
        """Extract hostname from SNI extension"""
        try:
            if len(data) < 5:
                return None
            
            list_len = struct.unpack("!H", data[0:2])[0]
            if list_len != len(data) - 2:
                return None
            
            # SNI Entry: [Type:1][Length:2][Name:var]
            name_type = data[2]
            name_len = struct.unpack("!H", data[3:5])[0]
            if name_len == 0 or 5 + name_len != len(data):
                return None

            if name_type == 0:  # host_name
                hostname = data[5:5+name_len].decode('ascii')
                if any(not label or len(label) > 63 for label in hostname.split('.')):
                    return None
                return hostname.lower().rstrip('.')
            
            return None
        except:
            return None
    
    def _parse_supported_versions(self, data: bytes) -> List[int]:
        """Parse supported_versions extension"""
        versions = []
        try:
            if len(data) < 1:
                return versions
            
            # In ClientHello: [Length:1][Versions:var]
            vers_len = data[0]
            for i in range(1, min(1 + vers_len, len(data)), 2):
                if i + 2 <= len(data):
                    v = struct.unpack("!H", data[i:i+2])[0]
                    if v not in GREASE_VALUES:
                        versions.append(v)
        except:
            pass
        return versions
    
    def _parse_elliptic_curves(self, data: bytes) -> List[int]:
        """Parse supported_groups (elliptic_curves) extension"""
        curves = []
        try:
            if len(data) < 2:
                return curves
            
            curves_len = struct.unpack("!H", data[0:2])[0]
            for i in range(2, min(2 + curves_len, len(data)), 2):
                if i + 2 <= len(data):
                    c = struct.unpack("!H", data[i:i+2])[0]
                    if c not in GREASE_VALUES:
                        curves.append(c)
        except:
            pass
        return curves
    
    def _parse_ec_point_formats(self, data: bytes) -> List[int]:
        """Parse ec_point_formats extension"""
        formats = []
        try:
            if len(data) < 1:
                return formats
            
            fmt_len = data[0]
            for i in range(1, min(1 + fmt_len, len(data))):
                formats.append(data[i])
        except:
            pass
        return formats
    
    def _compute_ja3_string(self, version: int, ciphers: List[int], 
                           extensions: List[int], curves: List[int],
                           formats: List[int]) -> str:
        """
        Compute JA3 fingerprint string.
        Format: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
        """
        return ','.join([
            str(version),
            '-'.join(str(c) for c in ciphers),
            '-'.join(str(e) for e in extensions),
            '-'.join(str(c) for c in curves),
            '-'.join(str(f) for f in formats)
        ])
    
    def _version_to_string(self, version: int) -> str:
        """Convert TLS version number to string"""
        versions = {
            0x0300: "SSL 3.0",
            0x0301: "TLS 1.0",
            0x0302: "TLS 1.1",
            0x0303: "TLS 1.2",
            0x0304: "TLS 1.3",
        }
        return versions.get(version, f"Unknown (0x{version:04x})")
    
    def quick_extract_sni(self, data: bytes) -> Optional[str]:
        """
        Quick extraction of just SNI without full parsing.
        More efficient for high-throughput scenarios.
        """
        hello = self.parse_client_hello(data)
        return hello.sni if hello else None
    
    def get_ja3_from_hello(self, data: bytes) -> Optional[str]:
        """Extract just JA3 hash from ClientHello"""
        result = self.parse_client_hello(data)
        return result.ja3_hash if result else None
    
    def to_dict(self, hello: TLSClientHello) -> Dict:
        """Convert TLSClientHello to dictionary"""
        return {
            "tls_version": hello.tls_version,
            "sni": hello.sni,
            "ja3": hello.ja3_hash,
            "ja3_full": hello.ja3_string,
            "cipher_count": len(hello.cipher_suites),
            "extension_count": len(hello.extensions),
        }
