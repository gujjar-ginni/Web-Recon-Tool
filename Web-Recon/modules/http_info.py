# modules/http_info.py
import requests
from urllib.parse import urlparse
from typing import Dict, Union, Optional, List, Any
from utils.logger import logger
import ssl
from datetime import datetime
import json

class HTTPAnalyzer:
    """Comprehensive HTTP analysis with security checks"""
    
    def __init__(self):
        self.session = requests.Session()
        self.security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy',
            'Permissions-Policy',
            'X-XSS-Protection'
        ]
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        }

    def analyze(self, url: str) -> Dict[str, Any]:
        """Comprehensive HTTP analysis"""
        url = self._normalize_url(url)
        result = {
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'error': None
        }

        try:
            response = self.session.get(
                url,
                headers=self.default_headers,
                timeout=15,
                allow_redirects=True
            )
            
            result.update({
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'security_headers': self._check_security_headers(response.headers),
                'final_url': response.url,
                'response_time_ms': response.elapsed.total_seconds() * 1000,
                'content_length': int(response.headers.get('Content-Length', 0)),
                'redirects': [resp.url for resp in response.history] if response.history else []
            })

            logger.info(f"HTTP analysis successful for {url}")
            
        except requests.RequestException as e:
            logger.error(f"HTTP analysis failed for {url}: {str(e)}")
            result['error'] = str(e)
        except Exception as e:
            logger.error(f"Unexpected error analyzing {url}: {str(e)}")
            result['error'] = f"Unexpected error: {str(e)}"

        return result

    def _normalize_url(self, url: str) -> str:
        """Ensure URL has proper scheme"""
        parsed = urlparse(url)
        if not parsed.scheme:
            return f"https://{url}"
        return url

    def _check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Analyze security headers"""
        results = {}
        for header in self.security_headers:
            if header in headers:
                results[header] = {
                    'present': True,
                    'value': headers[header],
                    'recommendation': self._get_header_recommendation(header, headers[header])
                }
            else:
                results[header] = {
                    'present': False,
                    'recommendation': self._get_header_recommendation(header, None)
                }
        return results

    def _get_header_recommendation(self, header: str, value: Optional[str]) -> str:
        """Provide recommendations for security headers"""
        recommendations = {
            'Strict-Transport-Security': 'Recommended: max-age=63072000; includeSubDomains; preload',
            'Content-Security-Policy': 'Recommended: default-src \'self\'',
            'X-Frame-Options': 'Recommended: DENY or SAMEORIGIN',
            'X-Content-Type-Options': 'Recommended: nosniff',
            'Referrer-Policy': 'Recommended: no-referrer-when-downgrade',
            'Permissions-Policy': 'Recommended: full control over feature permissions',
            'X-XSS-Protection': 'Recommended: 1; mode=block'
        }
        if not value:
            return f"Missing. {recommendations.get(header, '')}"
        return recommendations.get(header, 'No specific recommendation')

def fetch_http_info(url: str) -> Dict[str, Any]:
    """Public interface for HTTP analysis"""
    analyzer = HTTPAnalyzer()
    return analyzer.analyze(url)