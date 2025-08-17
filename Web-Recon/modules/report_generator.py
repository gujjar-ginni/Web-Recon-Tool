# modules/report_generator.py
import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from utils.logger import logger
import uuid
import re
from flask import render_template_string

class ReportGenerator:
    """Enhanced report generator with comprehensive analysis and formatting"""
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, target: str, results: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate comprehensive security report in multiple formats
        Returns paths to generated report files
        """
        try:
            # Add metadata and analysis
            report_data = self._prepare_report_data(target, results)
            
            # Generate reports
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = f"scan_{self._sanitize_filename(target)}_{timestamp}"
            
            return {
                "html": self._generate_html_report(report_data, base_name),
                "json": self._generate_json_report(report_data, base_name),
                "pdf": self._generate_pdf_report(report_data, base_name)
            }
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            raise

    def _prepare_report_data(self, target: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance raw scan data with analysis and formatting"""
        report_data = {
            "metadata": {
                "target": target,
                "scan_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat(),
                "formatted_date": datetime.now().strftime("%B %d, %Y %H:%M:%S")
            },
            "results": results,
            "analysis": {
                "risk_assessment": self._analyze_risks(results),
                "security_rating": self._calculate_security_score(results),
                "recommendations": self._generate_recommendations(results)
            }
        }
        return report_data

    def _generate_html_report(self, report_data: Dict[str, Any], base_name: str) -> str:
        """Generate HTML version of the report"""
        try:
            # Load template from file
            template_path = Path("templates") / "report_template.html"
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
            
            # Render template with report data
            html_content = render_template_string(template, scan_data=report_data)
            
            # Save report
            report_path = self.output_dir / f"{base_name}.html"
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            logger.info(f"Generated HTML report: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"HTML report generation failed: {str(e)}")
            raise

    def _generate_json_report(self, report_data: Dict[str, Any], base_name: str) -> str:
        """Generate JSON version of the report"""
        try:
            report_path = self.output_dir / f"{base_name}.json"
            
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
                
            logger.info(f"Generated JSON report: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"JSON report generation failed: {str(e)}")
            raise

    def _generate_pdf_report(self, report_data: Dict[str, Any], base_name: str) -> str:
        """Generate PDF version of the report"""
        try:
            import pdfkit
            
            # First generate HTML content
            html_report_path = self._generate_html_report(report_data, base_name)
            with open(html_report_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            # Generate PDF
            report_path = self.output_dir / f"{base_name}.pdf"
            
            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'quiet': ''
            }
            
            pdfkit.from_string(html_content, str(report_path), options=options)
            logger.info(f"Generated PDF report: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"PDF report generation failed: {str(e)}")
            raise

    def _analyze_risks(self, results: Dict[str, Any]) -> Dict[str, List[str]]:
        """Perform comprehensive risk analysis"""
        risks = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "informational": []
        }
        
        # HTTP Security Headers Analysis
        http_headers = results.get("http_info", {}).get("headers", {})
        if not http_headers.get("Strict-Transport-Security"):
            risks["critical"].append("Missing HSTS header - leaves site vulnerable to SSL stripping attacks")
        if not http_headers.get("Content-Security-Policy"):
            risks["high"].append("Missing CSP header - increases XSS attack surface")
        if not http_headers.get("X-Frame-Options"):
            risks["medium"].append("Missing X-Frame-Options - vulnerable to clickjacking")
        
        # Open Ports Analysis
        open_ports = results.get("port_scan", {}).get("open_ports", [])
        if 22 in open_ports:
            risks["critical"].append("SSH port (22) exposed - ensure strong authentication is configured")
        if 21 in open_ports:
            risks["high"].append("FTP port (21) exposed - consider disabling or securing with FTPS")
        if 80 in open_ports and not 443 in open_ports:
            risks["high"].append("HTTP available without HTTPS - enforce secure connections")
        
        # Technology Stack Analysis
        tech_stack = results.get("tech_stack", {})
        if "WordPress" in tech_stack.get("cms", []):
            risks["medium"].append("WordPress detected - ensure regular updates and hardening")
        if "PHP" in tech_stack.get("programming_languages", []):
            risks["medium"].append("PHP detected - ensure secure configuration and updates")
        
        return risks

    def _calculate_security_score(self, results: Dict[str, Any]) -> str:
        """Calculate overall security rating"""
        risk_analysis = self._analyze_risks(results)
        
        if risk_analysis["critical"]:
            return "Critical"
        elif risk_analysis["high"]:
            return "High Risk"
        elif risk_analysis["medium"]:
            return "Medium Risk"
        elif risk_analysis["low"]:
            return "Low Risk"
        else:
            return "Secure"

    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        risks = self._analyze_risks(results)
        
        # Critical recommendations
        if risks["critical"]:
            recommendations.append("Immediate Action Required: Address critical vulnerabilities first")
        
        # HTTP Header recommendations
        http_headers = results.get("http_info", {}).get("headers", {})
        if not http_headers.get("Strict-Transport-Security"):
            recommendations.append("Add HSTS header with 'max-age=63072000; includeSubDomains; preload'")
        if not http_headers.get("Content-Security-Policy"):
            recommendations.append("Implement Content Security Policy to mitigate XSS attacks")
        
        # Port-related recommendations
        open_ports = results.get("port_scan", {}).get("open_ports", [])
        if 22 in open_ports:
            recommendations.append("Restrict SSH access or implement key-based authentication")
        if 21 in open_ports:
            recommendations.append("Disable FTP or enforce FTPS with strong encryption")
        
        # Technology recommendations
        tech_stack = results.get("tech_stack", {})
        if "WordPress" in tech_stack.get("cms", []):
            recommendations.append("Update WordPress core, themes, and plugins to latest versions")
        
        return recommendations or ["No critical security recommendations at this time"]

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize string for safe filename use"""
        return re.sub(r'[\\/*?:"<>|]', "_", filename)

def generate_report(target: str, results: dict) -> Dict[str, str]:
    """Wrapper function for compatibility with web.py"""
    generator = ReportGenerator()
    return generator.generate_report(target, results)

def generate_html_report(target: str, results: dict, output_path: str) -> None:
    """Legacy function for backward compatibility"""
    generator = ReportGenerator()
    report = generator.generate_report(target, results)
    if report.get('html'):
        try:
            with open(report['html'], 'r', encoding='utf-8') as src:
                with open(output_path, 'w', encoding='utf-8') as dest:
                    dest.write(src.read())
            logger.info(f"HTML report copied to {output_path}")
        except Exception as e:
            logger.error(f"Failed to copy HTML report: {e}")