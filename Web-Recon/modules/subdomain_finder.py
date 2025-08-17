# modules/subdomain_finder.py
import dns.resolver
import requests
import concurrent.futures
import socket
from typing import List, Dict, Any
from utils.logger import logger
from datetime import datetime

class SubdomainFinder:
    """Comprehensive subdomain discovery"""
    
    def __init__(self):
        self.wordlist = self._load_wordlist()

    def find_subdomains(self, domain: str) -> Dict[str, Any]:
        """Find subdomains using multiple methods"""
        result = {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat(),
            "subdomains": [],
            "methods": {
                "dns": 0,
                "certificate": 0,
                "bruteforce": 0
            }
        }

        # DNS-based discovery
        dns_subs = self._dns_enumeration(domain)
        result["methods"]["dns"] = len(dns_subs)
        
        # Certificate transparency
        cert_subs = self._certificate_search(domain)
        result["methods"]["certificate"] = len(cert_subs)
        
        # Brute-force
        brute_subs = self._bruteforce(domain)
        result["methods"]["bruteforce"] = len(brute_subs)
        
        # Combine and deduplicate
        all_subs = list(set(dns_subs + cert_subs + brute_subs))
        result["subdomains"] = [{"subdomain": sub} for sub in sorted(all_subs)]
        result["total"] = len(all_subs)
        
        return result

    def _dns_enumeration(self, domain: str) -> List[str]:
        """Find subdomains via DNS"""
        subdomains = []
        for sub in self.wordlist:
            try:
                answers = dns.resolver.resolve(f"{sub}.{domain}", 'A')
                if answers:
                    subdomains.append(f"{sub}.{domain}")
            except:
                continue
        return subdomains

    def _certificate_search(self, domain: str) -> List[str]:
        """Find subdomains via certificate transparency"""
        try:
            response = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10
            )
            data = response.json()
            return list(set(
                entry['name_value'].lower().strip()
                for entry in data
                if domain in entry['name_value'] and '*' not in entry['name_value']
            ))
        except:
            return []

    def _bruteforce(self, domain: str) -> List[str]:
        """Brute-force subdomains with threading"""
        subdomains = []
        
        def check(sub: str):
            try:
                socket.gethostbyname(f"{sub}.{domain}")
                return f"{sub}.{domain}"
            except:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(check, self.wordlist)
            subdomains = [r for r in results if r]
            
        return subdomains

    def _load_wordlist(self) -> List[str]:
        """Load default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'webmail', 'admin', 'api',
            'dev', 'test', 'staging', 'secure', 'portal'
        ]

def find_subdomains(domain: str) -> Dict[str, Any]:
    """Public interface for subdomain discovery"""
    finder = SubdomainFinder()
    return finder.find_subdomains(domain)