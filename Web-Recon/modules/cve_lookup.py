# modules/cve_lookup.py

"""
CVE Lookup Module for Rapid Recon
Searches for Common Vulnerabilities and Exposures (CVEs) related to detected technologies
"""

import requests
from typing import Dict, Any, List
import os
from utils.logger import logger


class CVEngine:
    """CVE lookup for detected technologies"""

    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cve_cache = {}

    def search_cves(self, technology: str, version: str = None) -> Dict[str, Any]:
        """Search for CVEs related to a specific technology"""
        cache_key = f"{technology}:{version}"
        if cache_key in self.cve_cache:
            return self.cve_cache[cache_key]

        try:
            query = technology
            if version:
                query += f" {version}"

            params = {
                "keywordSearch": query,
                "resultsPerPage": 20,
                "startIndex": 0
            }

            response = requests.get(self.nvd_api_url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            vulnerabilities = self._parse_vulnerabilities(data)

            result = {
                "technology": technology,
                "version": version,
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "critical_count": len([v for v in vulnerabilities if v.get("severity") == "CRITICAL"]),
                "high_count": len([v for v in vulnerabilities if v.get("severity") == "HIGH"]),
                "medium_count": len([v for v in vulnerabilities if v.get("severity") == "MEDIUM"]),
                "low_count": len([v for v in vulnerabilities if v.get("severity") == "LOW"])
            }

            self.cve_cache[cache_key] = result
            logger.info(f"CVE search completed for {cache_key}")
            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during CVE search for {cache_key}: {e}")
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            logger.error(f"Unexpected error during CVE search for {cache_key}: {e}")
            return {"error": f"Unexpected error: {str(e)}"}

    def _parse_vulnerabilities(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from NVD API response"""
        vulnerabilities = []

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "N/A")

            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "UNKNOWN"

            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("severity", "UNKNOWN")

            references = [{"url": ref.get("url", ""), "source": ref.get("source", "")} for ref in cve.get("references", [])]

            vulnerabilities.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "published": cve.get("published", ""),
                "lastModified": cve.get("lastModified", ""),
                "references": references
            })

        return vulnerabilities

    def analyze_tech_stack(self, tech_stack: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze detected technologies for CVEs"""
        results = {"total_technologies": 0, "total_vulnerabilities": 0, "technologies": {}}

        if not tech_stack or "technologies" not in tech_stack:
            return results

        technologies = tech_stack["technologies"]
        results["total_technologies"] = len(technologies)

        for tech in technologies:
            name = tech.get("name", "")
            version = tech.get("version", "")
            if name:
                cve_result = self.search_cves(name, version)
                results["technologies"][name] = cve_result
                results["total_vulnerabilities"] += cve_result.get("total_vulnerabilities", 0)

        return results

    def get_exploit_info(self, cve_id: str) -> Dict[str, Any]:
        """Get exploit information for a specific CVE"""
        try:
            metasploit_modules = self._search_metasploit_modules(cve_id)
            return {
                "cve_id": cve_id,
                "exploitdb_available": False,  # Placeholder
                "metasploit_modules": metasploit_modules,
                "exploit_count": len(metasploit_modules),
                "sources": []
            }
        except Exception as e:
            logger.error(f"Failed to get exploit info for {cve_id}: {e}")
            return {"error": f"Failed to get exploit info: {str(e)}"}

    def _search_metasploit_modules(self, cve_id: str) -> List[str]:
        """Search for Metasploit modules related to CVE (placeholder)"""
        return []

    def generate_risk_report(self, tech_stack: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive risk report"""
        cve_analysis = self.analyze_tech_stack(tech_stack)
        risk_score = 0
        critical_cves = []
        high_cves = []

        for tech_data in cve_analysis["technologies"].values():
            if isinstance(tech_data, dict):
                for vuln in tech_data.get("vulnerabilities", []):
                    sev = vuln.get("severity", "").upper()
                    if sev == "CRITICAL":
                        critical_cves.append(vuln)
                        risk_score += 10
                    elif sev == "HIGH":
                        high_cves.append(vuln)
                        risk_score += 5

        if risk_score >= 50:
            risk_level = "CRITICAL"
        elif risk_score >= 30:
            risk_level = "HIGH"
        elif risk_score >= 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "critical_vulnerabilities": len(critical_cves),
            "high_vulnerabilities": len(high_cves),
            "total_vulnerabilities": cve_analysis["total_vulnerabilities"],
            "critical_cves": critical_cves,
            "high_cves": high_cves,
            "recommendations": self._generate_recommendations(critical_cves, high_cves)
        }

    def _generate_recommendations(self, critical_cves: List[Dict], high_cves: List[Dict]) -> List[str]:
        """Generate security recommendations based on CVEs"""
        recommendations = []

        if critical_cves:
            recommendations.extend([
                "IMMEDIATE ACTION REQUIRED: Critical vulnerabilities detected",
                "Consider taking affected systems offline",
                "Apply security patches immediately"
            ])
        if high_cves:
            recommendations.extend([
                "HIGH PRIORITY: Update affected software components",
                "Review and apply security patches",
                "Consider implementing additional security controls"
            ])
        recommendations.extend([
            "Regularly update all software components",
            "Implement vulnerability management program",
            "Monitor for new CVEs affecting your technology stack"
        ])
        return recommendations

def check_cves(tech_stack: Dict[str, Any]) -> Dict[str, Any]:    
    """Main function to perform CVE lookup for detected technologies"""
    engine = CVEngine()
    return engine.generate_risk_report(tech_stack)
