"""Utility functions for JSEye."""

import hashlib
import re
import base64
import urllib.parse
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse
import tldextract


def normalize_url(url: str, base_url: str = None) -> str:
    """Normalize and clean URL."""
    if not url:
        return ""
    
    # Handle relative URLs
    if base_url and not url.startswith(('http://', 'https://')):
        url = urljoin(base_url, url)
    
    # Parse and reconstruct
    parsed = urlparse(url)
    
    # Remove fragments and normalize
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    
    return normalized


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"
    except Exception:
        parsed = urlparse(url)
        return parsed.netloc


def calculate_sha256(content: str) -> str:
    """Calculate SHA256 hash of content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def decode_base64(encoded: str) -> Optional[str]:
    """Safely decode base64 string."""
    try:
        # Handle URL-safe base64
        encoded = encoded.replace('-', '+').replace('_', '/')
        
        # Add padding if needed
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
        
        decoded = base64.b64decode(encoded).decode('utf-8')
        return decoded
    except Exception:
        return None


def decode_hex(hex_string: str) -> Optional[str]:
    """Safely decode hex string."""
    try:
        # Remove common prefixes
        hex_string = hex_string.replace('0x', '').replace('\\x', '')
        decoded = bytes.fromhex(hex_string).decode('utf-8')
        return decoded
    except Exception:
        return None


def decode_uri_component(encoded: str) -> str:
    """Decode URI component."""
    try:
        return urllib.parse.unquote(encoded)
    except Exception:
        return encoded


def extract_js_strings(content: str) -> List[str]:
    """Extract string literals from JavaScript content."""
    strings = []
    
    # Single quoted strings
    single_quote_pattern = r"'([^'\\]|\\.)*'"
    strings.extend(re.findall(single_quote_pattern, content))
    
    # Double quoted strings
    double_quote_pattern = r'"([^"\\\\]|\\\\.)*"'
    strings.extend(re.findall(double_quote_pattern, content))
    
    # Template literals
    template_pattern = r'`([^`\\\\]|\\\\.)*`'
    strings.extend(re.findall(template_pattern, content))
    
    # Clean up strings
    cleaned_strings = []
    for s in strings:
        # Remove quotes
        if s.startswith(("'", '"', '`')) and s.endswith(("'", '"', '`')):
            s = s[1:-1]
        
        # Skip empty or very short strings
        if len(s) > 3:
            cleaned_strings.append(s)
    
    return cleaned_strings


def extract_urls_from_string(text: str) -> List[str]:
    """Extract URLs from text content."""
    url_pattern = r'https?://[^\s<>"\'`]+|www\.[^\s<>"\'`]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\'`]*'
    urls = re.findall(url_pattern, text)
    
    normalized_urls = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            if url.startswith('www.'):
                url = 'https://' + url
            elif '.' in url:
                url = 'https://' + url
        
        normalized_urls.append(url)
    
    return normalized_urls


def is_js_file(url: str) -> bool:
    """Check if URL points to a JavaScript file."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    # Direct .js files
    if path.endswith('.js'):
        return True
    
    # Common JS file patterns
    js_patterns = [
        r'\.js$',
        r'\.js\?',
        r'/js/',
        r'javascript',
        r'\.min\.js',
        r'\.bundle\.js'
    ]
    
    for pattern in js_patterns:
        if re.search(pattern, url.lower()):
            return True
    
    return False


def is_map_file(url: str) -> bool:
    """Check if URL points to a source map file."""
    return url.lower().endswith('.map') or '.js.map' in url.lower()


def extract_endpoints_from_js(content: str) -> List[str]:
    """Extract potential API endpoints from JavaScript content."""
    endpoints = []
    
    # Common API patterns
    patterns = [
        r'["\']([/][a-zA-Z0-9/_-]+)["\']',  # Absolute paths
        r'["\']([a-zA-Z0-9/_-]+\.php)["\']',  # PHP files
        r'["\']([a-zA-Z0-9/_-]+\.asp[x]?)["\']',  # ASP files
        r'["\']([a-zA-Z0-9/_-]+\.jsp)["\']',  # JSP files
        r'["\']([a-zA-Z0-Z/_-]+/api/[a-zA-Z0-9/_-]+)["\']',  # API paths
        r'["\']([a-zA-Z0-9/_-]+/v\d+/[a-zA-Z0-9/_-]+)["\']',  # Versioned APIs
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        endpoints.extend(matches)
    
    # Remove duplicates and filter
    unique_endpoints = list(set(endpoints))
    filtered_endpoints = []
    
    for endpoint in unique_endpoints:
        # Skip very short or invalid endpoints
        if len(endpoint) > 3 and not endpoint.startswith(('http', 'ftp')):
            filtered_endpoints.append(endpoint)
    
    return filtered_endpoints


def clean_js_content(content: str) -> str:
    """Clean and prepare JavaScript content for analysis."""
    # Remove comments
    content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    
    # Normalize whitespace
    content = re.sub(r'\s+', ' ', content)
    
    return content.strip()


def extract_secrets_context(content: str, secret_match: str, context_size: int = 50) -> str:
    """Extract context around a secret match."""
    try:
        start_pos = content.find(secret_match)
        if start_pos == -1:
            return secret_match
        
        start = max(0, start_pos - context_size)
        end = min(len(content), start_pos + len(secret_match) + context_size)
        
        context = content[start:end]
        return context.strip()
    except Exception:
        return secret_match


def mask_secret(secret: str, show_chars: int = 4) -> str:
    """Mask secret value for safe display."""
    if len(secret) <= show_chars * 2:
        return '*' * len(secret)
    
    return secret[:show_chars] + '*' * (len(secret) - show_chars * 2) + secret[-show_chars:]


def is_valid_domain(domain: str) -> bool:
    """Check if domain is valid."""
    try:
        extracted = tldextract.extract(domain)
        return bool(extracted.domain and extracted.suffix)
    except Exception:
        return False


def deduplicate_by_hash(items: List[Dict[str, Any]], hash_key: str = 'hash') -> List[Dict[str, Any]]:
    """Remove duplicates based on hash value."""
    seen_hashes = set()
    unique_items = []
    
    for item in items:
        item_hash = item.get(hash_key)
        if item_hash and item_hash not in seen_hashes:
            seen_hashes.add(item_hash)
            unique_items.append(item)
    
    return unique_items


def extract_subdomains_from_js(content: str, target_domain: str) -> Set[str]:
    """Extract subdomains related to target domain from JS content."""
    subdomains = set()
    
    # Extract the main domain
    main_domain = extract_domain(target_domain)
    
    # Pattern to find subdomains
    subdomain_pattern = rf'([a-zA-Z0-9.-]+\.{re.escape(main_domain)})'
    
    matches = re.findall(subdomain_pattern, content, re.IGNORECASE)
    
    for match in matches:
        if is_valid_domain(match):
            subdomains.add(match.lower())
    
    return subdomains


def extract_parameters_from_url(url: str) -> List[str]:
    """Extract parameter names from URL."""
    parsed = urlparse(url)
    if not parsed.query:
        return []
    
    params = []
    for param_pair in parsed.query.split('&'):
        if '=' in param_pair:
            param_name = param_pair.split('=')[0]
            if param_name:
                params.append(param_name)
    
    return params