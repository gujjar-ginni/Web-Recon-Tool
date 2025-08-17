"""
Enhanced Export Manager for Rapid Recon
Handles PDF, JSON, HTML exports and email reports with improved formatting
"""

import os
import json
import logging
import smtplib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from jinja2 import Environment, FileSystemLoader
import pdfkit
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, 
    Paragraph, 
    Spacer, 
    Table, 
    TableStyle,
    PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ExportManager:
    """Enhanced export manager with comprehensive reporting capabilities"""
    
    def __init__(self, output_dir: str = "output", templates_dir: str = "templates"):
        self.output_dir = Path(output_dir)
        self.templates_dir = Path(templates_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
    
    def export_report(self, scan_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate comprehensive security report in multiple formats
        Returns paths to generated report files
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = f"scan_{self._sanitize_filename(scan_data.get('target', 'unknown'))}_{timestamp}"
            
            return {
                "html": self._export_html(scan_data, base_name),
                "pdf": self._export_pdf(scan_data, base_name),
                "json": self._export_json(scan_data, base_name)
            }
            
        except Exception as e:
            logger.error(f"Report export failed: {str(e)}")
            raise

    def _export_html(self, scan_data: Dict[str, Any], base_name: str) -> str:
        """Generate HTML version of the report"""
        try:
            template = self.jinja_env.get_template("report_template.html")
            html_content = template.render(
                scan_data=scan_data,
                timestamp=datetime.now().strftime("%B %d, %Y %H:%M:%S")
            )
            
            report_path = self.output_dir / f"{base_name}.html"
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            logger.info(f"Generated HTML report: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"HTML export failed: {str(e)}")
            raise

    def _export_pdf(self, scan_data: Dict[str, Any], base_name: str) -> str:
        """Generate PDF version of the report"""
        try:
            report_path = self.output_dir / f"{base_name}.pdf"
            
            # Create PDF document
            doc = SimpleDocTemplate(
                str(report_path),
                pagesize=letter,
                title=f"Security Report - {scan_data.get('target', 'Unknown')}",
                author="Rapid Recon"
            )
            
            styles = self._get_pdf_styles()
            story = self._build_pdf_story(scan_data, styles)
            
            # Build the PDF document
            doc.build(story)
            
            logger.info(f"Generated PDF report: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"PDF export failed: {str(e)}")
            raise

    def _export_json(self, scan_data: Dict[str, Any], base_name: str) -> str:
        """Generate JSON version of the report"""
        try:
            report_path = self.output_dir / f"{base_name}.json"
            
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(scan_data, f, indent=2, ensure_ascii=False)
                
            logger.info(f"Generated JSON report: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"JSON export failed: {str(e)}")
            raise

    def send_email_report(
        self,
        scan_data: Dict[str, Any],
        recipient: str,
        sender: str,
        password: str,
        smtp_server: str = "smtp.gmail.com",
        smtp_port: int = 587
    ) -> bool:
        """Send comprehensive email report with all attachments"""
        try:
            # Generate all report formats
            reports = self.export_report(scan_data)
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = recipient
            msg['Subject'] = f"Security Report - {scan_data.get('target', 'Unknown')}"
            
            # Add HTML body
            with open(reports['html'], 'r', encoding='utf-8') as f:
                html_body = f.read()
            msg.attach(MIMEText(html_body, 'html'))
            
            # Attach all report formats
            for fmt, path in reports.items():
                with open(path, 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename=security_report_{scan_data.get("scan_id", "")}.{fmt}'
                    )
                    msg.attach(part)
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender, password)
                server.send_message(msg)
            
            logger.info(f"Email report sent to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email report: {str(e)}")
            return False

    def _get_pdf_styles(self) -> Dict[str, ParagraphStyle]:
        """Define styles for PDF document"""
        styles = getSampleStyleSheet()
        
        # Custom styles
        styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=20,
            alignment=1,  # Center
            textColor=colors.HexColor('#283e51')
        ))
        
        styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=10,
            textColor=colors.HexColor('#485563')
        ))
        
        return styles

    def _build_pdf_story(self, scan_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """Construct the PDF document content"""
        story = []
        
        # Add title
        story.append(Paragraph("Security Assessment Report", styles['ReportTitle']))
        story.append(Spacer(1, 20))
        
        # Add metadata table
        story.extend(self._create_metadata_table(scan_data, styles))
        story.append(Spacer(1, 30))
        
        # Add executive summary
        story.append(Paragraph("Executive Summary", styles['SectionHeader']))
        story.append(Spacer(1, 10))
        story.extend(self._create_summary_content(scan_data, styles))
        story.append(PageBreak())
        
        # Add detailed findings
        story.append(Paragraph("Detailed Findings", styles['SectionHeader']))
        story.append(Spacer(1, 10))
        story.extend(self._create_findings_content(scan_data, styles))
        
        return story

    def _create_metadata_table(self, scan_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """Create PDF metadata table"""
        metadata = [
            ["Target", scan_data.get('target', 'N/A')],
            ["Scan ID", scan_data.get('scan_id', 'N/A')],
            ["Date", scan_data.get('timestamp', 'N/A')],
            ["IP Address", scan_data.get('ip_address', 'N/A')],
            ["Security Rating", scan_data.get('analysis', {}).get('security_rating', 'N/A')]
        ]
        
        table = Table(metadata, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#283e51')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6'))
        ]))
        
        return [table]

    def _create_summary_content(self, scan_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """Create PDF executive summary content"""
        analysis = scan_data.get('analysis', {})
        risks = analysis.get('risk_assessment', {})
        
        content = [
            Paragraph(f"<b>Security Rating:</b> {analysis.get('security_rating', 'N/A')}", styles['Normal']),
            Spacer(1, 15),
            Paragraph("<b>Risk Summary:</b>", styles['Normal']),
        ]
        
        # Add risk counts
        for severity, findings in risks.items():
            if findings:
                content.append(Paragraph(
                    f"• {severity.title()}: {len(findings)} findings", 
                    styles['Normal']
                ))
        
        # Add top recommendations
        content.extend([
            Spacer(1, 15),
            Paragraph("<b>Key Recommendations:</b>", styles['Normal'])
        ])
        
        for rec in analysis.get('recommendations', [])[:3]:
            content.append(Paragraph(f"• {rec}", styles['Normal']))
        
        return content

    def _create_findings_content(self, scan_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> List[Any]:
        """Create PDF detailed findings content"""
        content = []
        
        for module, data in scan_data.get('results', {}).items():
            if not data:
                continue
                
            content.append(Paragraph(module.replace('_', ' ').title(), styles['Heading3']))
            
            if isinstance(data, dict):
                table_data = [["Parameter", "Value"]]
                table_data.extend([[k, str(v)] for k, v in data.items()])
                
                table = Table(table_data, colWidths=[2*inch, 4*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6c757d')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white)
                ]))
                
                content.append(table)
                content.append(Spacer(1, 15))
            else:
                content.append(Paragraph(str(data), styles['Normal']))
                content.append(Spacer(1, 15))
        
        return content

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize string for safe filename use"""
        import re
        return re.sub(r'[\\/*?:"<>|]', "_", filename)

# Legacy compatibility
def export_to_html(scan_data: Dict[str, Any], output_path: str) -> None:
    """Legacy function for backward compatibility"""
    exporter = ExportManager()
    report = exporter.export_report(scan_data)
    if report.get('html'):
        try:
            with open(report['html'], 'r', encoding='utf-8') as src:
                with open(output_path, 'w', encoding='utf-8') as dest:
                    dest.write(src.read())
            logger.info(f"HTML report copied to {output_path}")
        except Exception as e:
            logger.error(f"Failed to copy HTML report: {e}")

# modules/export_manager.py
# Add this at the bottom:
def export_to_pdf(scan_data: Dict[str, Any], output_path: str) -> None:
    """Legacy function for backward compatibility"""
    exporter = ExportManager()
    report = exporter.export_report(scan_data)
    if report.get('pdf'):
        try:
            with open(report['pdf'], 'rb') as src:
                with open(output_path, 'wb') as dest:
                    dest.write(src.read())
            logger.info(f"PDF report copied to {output_path}")
        except Exception as e:
            logger.error(f"Failed to copy PDF report: {e}")

def export_to_html(scan_data: Dict[str, Any], output_path: str) -> None:
    """Legacy function for backward compatibility"""
    exporter = ExportManager()
    report = exporter.export_report(scan_data)
    if report.get('html'):
        try:
            with open(report['html'], 'r', encoding='utf-8') as src:
                with open(output_path, 'w', encoding='utf-8') as dest:
                    dest.write(src.read())
            logger.info(f"HTML report copied to {output_path}")
        except Exception as e:
            logger.error(f"Failed to copy HTML report: {e}")