"""
Content Filtering for Sensitive Data

This module implements content filtering to prevent the bot from returning
sensitive information like passwords, API keys, and other confidential data.
"""

import re
import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SensitivePattern:
    """Represents a pattern for detecting sensitive data."""
    name: str
    pattern: str
    description: str
    severity: str  # 'high', 'medium', 'low'

class ContentFilter:
    """
    Filters content to detect and prevent exposure of sensitive information.
    """
    
    def __init__(self, custom_patterns: Optional[List[SensitivePattern]] = None):
        """
        Initialize the content filter with default and custom patterns.
        
        Args:
            custom_patterns: Optional list of custom sensitive data patterns
        """
        self.default_patterns = self._get_default_patterns()
        self.custom_patterns = custom_patterns or []
        self.all_patterns = self.default_patterns + self.custom_patterns
        
        logger.info(f"Content filter initialized with {len(self.all_patterns)} patterns")
    
    def _get_default_patterns(self) -> List[SensitivePattern]:
        """Get default patterns for common sensitive data types."""
        return [
            # API Keys and Tokens
            SensitivePattern(
                name="api_key",
                pattern=r'\b[A-Za-z0-9]{32,}\b',
                description="Potential API key or token",
                severity="high"
            ),
            SensitivePattern(
                name="slack_token",
                pattern=r'\b(xox[p|b|o|a]-[A-Za-z0-9-]+)\b',
                description="Slack token",
                severity="high"
            ),
            SensitivePattern(
                name="aws_key",
                pattern=r'\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b',
                description="AWS access key",
                severity="high"
            ),
            
            # Passwords and Credentials
            SensitivePattern(
                name="password",
                pattern=r'\b(password|passwd|pwd)\s*[:=]\s*\S+',
                description="Password in text",
                severity="high"
            ),
            SensitivePattern(
                name="credential",
                pattern=r'\b(credential|secret|key)\s*[:=]\s*\S+',
                description="Credential information",
                severity="high"
            ),
            
            # Personal Information
            SensitivePattern(
                name="email",
                pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                description="Email address",
                severity="medium"
            ),
            SensitivePattern(
                name="phone",
                pattern=r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                description="Phone number",
                severity="medium"
            ),
            SensitivePattern(
                name="ssn",
                pattern=r'\b\d{3}-\d{2}-\d{4}\b',
                description="Social Security Number",
                severity="high"
            ),
            
            # URLs and Endpoints
            SensitivePattern(
                name="internal_url",
                pattern=r'\b(https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|localhost|127\.0\.0\.1))',
                description="Internal URL or localhost",
                severity="medium"
            ),
            
            # Database Connections
            SensitivePattern(
                name="db_connection",
                pattern=r'\b(mysql|postgresql|mongodb)://[^\\s]+',
                description="Database connection string",
                severity="high"
            ),
            
            # File Paths
            SensitivePattern(
                name="file_path",
                pattern=r'\b(/etc/|/var/|/home/|C:\\|D:\\)[^\\s]*',
                description="System file path",
                severity="low"
            ),
        ]
    
    def scan_content(self, content: str) -> List[Dict]:
        """
        Scan content for sensitive information.
        
        Args:
            content: Text content to scan
            
        Returns:
            List[Dict]: List of detected sensitive patterns with details
        """
        findings = []
        
        for pattern in self.all_patterns:
            matches = re.finditer(pattern.pattern, content, re.IGNORECASE)
            for match in matches:
                # Extract a snippet around the match for context
                start = max(0, match.start() - 20)
                end = min(len(content), match.end() + 20)
                context = content[start:end]
                
                # Mask the sensitive part
                masked_content = content[:match.start()] + "[REDACTED]" + content[match.end():]
                
                findings.append({
                    'pattern_name': pattern.name,
                    'description': pattern.description,
                    'severity': pattern.severity,
                    'match_text': match.group(),
                    'context': context,
                    'position': (match.start(), match.end()),
                    'masked_content': masked_content
                })
                
                logger.warning(f"Sensitive content detected: {pattern.name} - {pattern.description}")
        
        return findings
    
    def filter_content(self, content: str) -> Tuple[str, List[Dict]]:
        """
        Filter content by removing or masking sensitive information.
        
        Args:
            content: Text content to filter
            
        Returns:
            Tuple[str, List[Dict]]: (filtered_content, findings)
        """
        findings = self.scan_content(content)
        filtered_content = content
        
        # Apply filters in reverse order to maintain positions
        for finding in reversed(findings):
            start, end = finding['position']
            filtered_content = filtered_content[:start] + "[REDACTED]" + filtered_content[end:]
        
        return filtered_content, findings
    
    def should_block_response(self, findings: List[Dict]) -> bool:
        """
        Determine if a response should be blocked due to sensitive content.
        
        Args:
            findings: List of content scan findings
            
        Returns:
            bool: True if response should be blocked, False otherwise
        """
        # Block if any high severity findings are present
        high_severity_findings = [f for f in findings if f['severity'] == 'high']
        return len(high_severity_findings) > 0
    
    def get_filter_summary(self, findings: List[Dict]) -> str:
        """
        Generate a summary of filtered content.
        
        Args:
            findings: List of content scan findings
            
        Returns:
            str: Summary message
        """
        if not findings:
            return "No sensitive content detected."
        
        severity_counts = {}
        for finding in findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary_parts = []
        for severity in ['high', 'medium', 'low']:
            if severity in severity_counts:
                summary_parts.append(f"{severity_counts[severity]} {severity} severity")
        
        return f"Content filtered: {', '.join(summary_parts)} items redacted."

def create_content_filter(custom_patterns: Optional[List[SensitivePattern]] = None) -> ContentFilter:
    """
    Factory function to create a ContentFilter instance.
    
    Args:
        custom_patterns: Optional list of custom sensitive data patterns
        
    Returns:
        ContentFilter: Configured content filter instance
    """
    return ContentFilter(custom_patterns)
