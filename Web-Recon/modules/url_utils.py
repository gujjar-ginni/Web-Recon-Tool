"""
URL utility functions for normalizing and validating URLs across the application
"""

from urllib.parse import urlparse, urljoin
import re


def normalize_url(url: str) -> str:
    """
    Normalize a URL by ensuring it has a proper scheme (http/https)
    
    Args:
        url (str): The URL to normalize
        
    Returns:
        str: Normalized URL with proper scheme
    """
    if not url:
        return ""
    
    # Remove common prefixes if they exist
    url = url.strip()
    
    # Check if URL already has a scheme
    parsed = urlparse(url)
    if parsed.scheme:
        return url
    
    # Add https scheme if missing
    return f"https://{url}"


def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid
    
    Args:
        url (str): The URL to validate
        
    Returns:
        bool: True if URL is valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def extract_domain(url: str) -> str:
    """
    Extract the domain from a URL
    
    Args:
        url (str): The URL to extract domain from
        
    Returns:
        str: The extracted domain
    """
    try:
        parsed = urlparse(normalize_url(url))
        return parsed.netloc
    except:
        return url


def clean_target(target: str) -> str:
    """
    Clean and normalize a target input
    
    Args:
        target (str): The target to clean
        
    Returns:
        str: Cleaned target
    """
    # Remove protocol if present
    target = re.sub(r'^https?://', '', target)
    # Remove www. prefix
    target = re.sub(r'^www\.', '', target)
    # Remove trailing slashes
    target = target.rstrip('/')
    return target.strip()
