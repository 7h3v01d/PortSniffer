import logging
from scapy.all import load_layer

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

try:
    from scapy.layers.tls.all import *
    TLS_AVAILABLE = True
except ImportError:
    try:
        load_layer("tls")
        from scapy.layers.tls.all import *
        TLS_AVAILABLE = True
    except ImportError:
        TLS_AVAILABLE = False

try:
    load_layer("http")
    from scapy.layers.http import HTTPRequest
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False

def analyze_headers(packet):
    try:
        if not hasattr(packet, 'summary'):
            return "No packet summary available"
        
        if packet.haslayer("TCP"):
            sport = packet['TCP'].sport
            dport = packet['TCP'].dport
            logging.debug(f"Processing TCP packet on port {dport}: {packet.summary()}")
            
            if HTTP_AVAILABLE and packet.haslayer("HTTPRequest"):
                try:
                    http_layer = packet['HTTPRequest']
                    method = http_layer.Method.decode('utf-8', errors='ignore') if isinstance(http_layer.Method, bytes) else str(http_layer.Method)
                    path = http_layer.Path.decode('utf-8', errors='ignore') if isinstance(http_layer.Path, bytes) else str(http_layer.Path)
                    host = http_layer.Host.decode('utf-8', errors='ignore') if isinstance(http_layer.Host, bytes) else str(http_layer.Host)
                    headers = []
                    headers.append(f"HTTP Request: {method} {path}")
                    headers.append(f"Host: {host}")
                    for field, value in http_layer.fields.items():
                        if field not in ["Method", "Path", "Host"]:
                            if isinstance(value, bytes):
                                value = value.decode('utf-8', errors='ignore')
                            headers.append(f"{field}: {value}")
                    return "\n".join(headers)
                except Exception as e:
                    logging.error(f"Error analyzing HTTP headers: {e}, Packet: {packet.summary()}")
                    return "Error in HTTP header analysis"
            
            if TLS_AVAILABLE and packet.haslayer("TLS") and (dport == 443 or sport == 443):
                try:
                    tls_layer = packet['TLS']
                    headers = []
                    headers.append(f"TLS Version: {tls_layer.version}")
                    if hasattr(tls_layer, 'cipher_suite') and tls_layer.cipher_suite:
                        headers.append(f"Cipher Suite: {tls_layer.cipher_suite}")
                    else:
                        headers.append("Cipher Suite: Not specified")
                    if packet.haslayer(TLSClientHello):
                        headers.append("TLS Packet Type: ClientHello")
                    elif packet.haslayer(TLSServerHello):
                        headers.append("TLS Packet Type: ServerHello")
                    elif hasattr(tls_layer, 'msg') and tls_layer.msg:
                        packet_type = tls_layer.msg[0].__class__.__name__
                        headers.append(f"TLS Packet Type: {packet_type}")
                    else:
                        headers.append("TLS Packet Type: Unknown")
                    return "\n".join(headers)
                except Exception as e:
                    logging.error(f"Error analyzing TLS headers: {e}, Packet: {packet.summary()}")
                    return "Error in TLS header analysis"
        
        return "Unknown Protocol"
    except Exception as e:
        logging.error(f"Error analyzing headers: {e}, Packet: {packet.summary()}")
        return "Error in header analysis"

def get_payload_summary(packet):
    try:
        if packet.haslayer("Raw"):
            payload = packet['Raw'].load
            try:
                decoded = payload.decode('utf-8', errors='ignore')
                if decoded.isprintable() and decoded.strip():
                    logging.debug(f"Payload decoded: {decoded}")
                    return decoded
                else:
                    hex_str = payload.hex()
                    logging.debug(f"Payload hex: {hex_str}")
                    return f"Binary payload (hex: {hex_str})"
            except UnicodeDecodeError:
                hex_str = payload.hex()
                logging.debug(f"Payload hex: {hex_str}")
                return f"Binary payload (hex: {hex_str})"
        logging.debug("No payload in packet")
        return "No payload"
    except Exception as e:
        logging.error(f"Error in get_payload_summary: {e}")
        return "Error in payload summary"