# modules/shodan_search.py
import requests
import os
from typing import Dict, Any, List
from utils.logger import logger
from datetime import datetime

class ShodanClient:
    """Enhanced Shodan API client with error handling"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('SHODAN_API_KEY')
        self.base_url = "https://api.shodan.io"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "RapidRecon/2.0",
            "Accept": "application/json"
        })
        
        if not self.api_key:
            logger.error("Shodan API key not configured")
            raise ValueError("Shodan API key is required")

    def host_search(self, ip: str) -> Dict[str, Any]:
        """Get comprehensive host information"""
        endpoint = f"/shodan/host/{ip}"
        data = self._api_request(endpoint)
        
        if "error" in data:
            return data
            
        return {
            "ip": data.get("ip_str"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "organization": data.get("org", "N/A"),
            "isp": data.get("isp", "N/A"),
            "services": self._parse_services(data.get("data", [])),
            "vulnerabilities": data.get("vulns", []),
            "timestamp": datetime.utcnow().isoformat()
        }

    def _api_request(self, endpoint: str, params: dict = None) -> Dict[str, Any]:
        """Make API request with error handling"""
        try:
            params = params or {}
            params["key"] = self.api_key
            
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                params=params,
                timeout=30
            )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Shodan API error: {str(e)}")
            return {"error": f"Shodan API error: {str(e)}"}

    def _parse_services(self, services: List[Dict]) -> List[Dict]:
        """Parse service information"""
        return [{
            "port": s.get("port"),
            "service": s.get("product", "unknown"),
            "version": s.get("version", "unknown"),
            "cpe": s.get("cpe", [])
        } for s in services]

def shodan_lookup(target: str, target_type: str = "ip") -> Dict[str, Any]:
    """Public interface for Shodan lookups"""
    try:
        client = ShodanClient()
        if target_type == "ip":
            return client.host_search(target)
        else:
            return {"error": "Only IP lookups currently supported"}
    except Exception as e:
        return {"error": str(e)}

# For backward compatibility
def perform_shodan_search(target: str, target_type: str = "ip") -> Dict[str, Any]:
    """Legacy function name for backward compatibility"""
    return shodan_lookup(target, target_type)