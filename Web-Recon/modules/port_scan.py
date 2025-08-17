# modules/port_scan.py
import nmap
import socket
from typing import Dict, Any, List
from utils.logger import logger
from datetime import datetime

class PortScanner:
    """Enhanced port scanner with Nmap integration"""
    
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform comprehensive port scan"""
        result = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "open_ports": [],
            "os_guess": None,
            "error": None
        }

        try:
            logger.info(f"Scanning {target} on ports {ports}")
            self.scanner.scan(target, ports=ports, arguments="-sS -sV -T4")
            
            if target not in self.scanner.all_hosts():
                result["error"] = "Target did not respond"
                return result

            host = self.scanner[target]
            
            # Process open ports
            for proto in host.all_protocols():
                for port, port_data in host[proto].items():
                    if port_data["state"] == "open":
                        result["open_ports"].append({
                            "port": port,
                            "protocol": proto,
                            "service": port_data["name"],
                            "product": port_data.get("product", ""),
                            "version": port_data.get("version", "")
                        })

            # OS detection
            if "osmatch" in host and host["osmatch"]:
                result["os_guess"] = host["osmatch"][0]["name"]

            logger.info(f"Scan completed for {target}")
            
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Scan failed for {target}: {e}")

        return result

def scan_ports(target: str, ports: str = "1-1000") -> Dict[str, Any]:
    """Public interface for port scanning"""
    scanner = PortScanner()
    return scanner.scan(target, ports)

# Backward compatibility
def run_nmap_scan(ip_address: str, ports: str = "1-1000") -> dict:
    """Legacy function name for backward compatibility"""
    return scan_ports(ip_address, ports)