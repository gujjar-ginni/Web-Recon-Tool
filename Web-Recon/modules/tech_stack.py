# modules/tech_stack.py

try:
    from urllib.parse import urlparse
    import builtwith
    from wappalyzer import Wappalyzer, WebPage
    import requests
    from requests.exceptions import RequestException
except ImportError as e:
    from utils.logger import logger
    logger.error(f"Missing dependency: {e}. Please install required modules.")
    raise
from utils.logger import logger
from datetime import datetime

class TechStackDetector:
    """Enhanced technology stack detection using multiple methods"""
    
    def __init__(self):
        try:
            self.wappalyzer = Wappalyzer.latest()
        except Exception as e:
            logger.warning(f"Wappalyzer initialization failed: {e}")
            self.wappalyzer = None

    def detect_with_builtwith(self, url: str) -> dict:
        """Detect technologies using BuiltWith"""
        try:
            return builtwith.parse(url)
        except Exception as e:
            logger.error(f"BuiltWith detection failed: {e}")
            return {"error": f"BuiltWith detection failed: {str(e)}"}

    def detect_with_wappalyzer(self, url: str) -> dict:
        """Detect technologies using Wappalyzer"""
        if not self.wappalyzer:
            return {"error": "Wappalyzer not initialized"}
            
        try:
            response = requests.get(url, timeout=10, verify=False)
            webpage = WebPage(url, response.text, headers=response.headers)
            return self.wappalyzer.analyze(webpage)
        except RequestException as e:
            logger.error(f"Wappalyzer request failed: {e}")
            return {"error": f"Wappalyzer request failed: {str(e)}"}
        except Exception as e:
            logger.error(f"Wappalyzer detection failed: {e}")
            return {"error": f"Wappalyzer detection failed: {str(e)}"}

    def normalize_results(self, builtwith_data: dict, wappalyzer_data: dict) -> dict:
        """Normalize results from both detectors"""
        results = {
            "technologies": {},
            "categories": {},
            "confidence": {},
            "detection_methods": {
                "builtwith": bool(builtwith_data and not isinstance(builtwith_data, dict) and "error" not in builtwith_data),
                "wappalyzer": bool(wappalyzer_data and not isinstance(wappalyzer_data, dict) and "error" not in wappalyzer_data)
            }
        }
        
        # Process BuiltWith data
        if results["detection_methods"]["builtwith"]:
            for tech_type, tech_list in builtwith_data.items():
                results["technologies"][tech_type] = tech_list
                results["confidence"][tech_type] = "high"

        # Process Wappalyzer data
        if results["detection_methods"]["wappalyzer"]:
            for tech_name, tech_data in wappalyzer_data.items():
                version = tech_data.get('versions', ['unknown'])[0] if tech_data.get('versions') else 'unknown'
                confidence = tech_data.get('confidence', 'medium')
                
                results["technologies"][tech_name] = {
                    "version": version,
                    "confidence": confidence
                }
                
                for category in tech_data.get('categories', []):
                    if category not in results["categories"]:
                        results["categories"][category] = []
                    results["categories"][category].append(tech_name)

        return results

def detect_tech_stack(url: str) -> dict:
    """
    Enhanced technology stack detection using both BuiltWith and Wappalyzer.
    
    Args:
        url (str): The website URL (e.g., https://example.com)

    Returns:
        dict: Dictionary of detected technologies with versions and confidence levels
    """
    detector = TechStackDetector()
    
    # Ensure the URL has a scheme
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'https://' + url

    # Get results from both detectors
    builtwith_data = detector.detect_with_builtwith(url)
    wappalyzer_data = detector.detect_with_wappalyzer(url)
    
    # Normalize and combine results
    results = detector.normalize_results(builtwith_data, wappalyzer_data)
    
    # Add metadata
    results["url"] = url
    results["timestamp"] = datetime.now().isoformat()
    
    if not results["technologies"]:
        results["info"] = "No technologies detected or the site may be unreachable."
        logger.info(f"No technologies detected for {url}")
    else:
        logger.info(f"Technologies detected for {url}: {list(results['technologies'].keys())}")
    
    return results