"""Entropy calculation for secret detection."""

import math
import re
from typing import Dict, Tuple
from collections import Counter


class EntropyAnalyzer:
    """Calculate entropy and analyze strings for potential secrets."""
    
    def __init__(self):
        self.min_entropy = 3.5
        self.min_length = 8
        self.max_length = 200
    
    def calculate_shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text)
        text_length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_string(self, text: str) -> Dict[str, any]:
        """Analyze string for entropy and characteristics."""
        if not text or len(text) < self.min_length:
            return {
                'entropy': 0.0,
                'is_high_entropy': False,
                'length': len(text) if text else 0,
                'char_diversity': 0.0,
                'has_mixed_case': False,
                'has_numbers': False,
                'has_special_chars': False
            }
        
        entropy = self.calculate_shannon_entropy(text)
        unique_chars = len(set(text))
        char_diversity = unique_chars / len(text) if text else 0
        
        # Character analysis
        has_upper = bool(re.search(r'[A-Z]', text))
        has_lower = bool(re.search(r'[a-z]', text))
        has_numbers = bool(re.search(r'[0-9]', text))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', text))
        
        return {
            'entropy': entropy,
            'is_high_entropy': entropy >= self.min_entropy,
            'length': len(text),
            'char_diversity': char_diversity,
            'has_mixed_case': has_upper and has_lower,
            'has_numbers': has_numbers,
            'has_special_chars': has_special,
            'unique_chars': unique_chars
        }
    
    def is_potential_secret(self, text: str) -> Tuple[bool, float, str]:
        """Determine if string is potentially a secret."""
        if not text or len(text) < self.min_length or len(text) > self.max_length:
            return False, 0.0, "Length out of range"
        
        analysis = self.analyze_string(text)
        entropy = analysis['entropy']
        
        # Base entropy check
        if entropy < self.min_entropy:
            return False, entropy, "Low entropy"
        
        # Additional heuristics
        score = entropy
        reasons = []
        
        # Bonus for character diversity
        if analysis['char_diversity'] > 0.7:
            score += 0.5
            reasons.append("High character diversity")
        
        # Bonus for mixed case
        if analysis['has_mixed_case']:
            score += 0.3
            reasons.append("Mixed case")
        
        # Bonus for numbers
        if analysis['has_numbers']:
            score += 0.2
            reasons.append("Contains numbers")
        
        # Bonus for special characters
        if analysis['has_special_chars']:
            score += 0.2
            reasons.append("Contains special chars")
        
        # Penalty for common patterns
        if self._is_common_pattern(text):
            score -= 1.0
            reasons.append("Common pattern detected")
        
        # Penalty for repeated characters
        if self._has_repeated_chars(text):
            score -= 0.5
            reasons.append("Repeated characters")
        
        is_secret = score >= self.min_entropy
        reason = "; ".join(reasons) if reasons else "High entropy"
        
        return is_secret, score, reason
    
    def _is_common_pattern(self, text: str) -> bool:
        """Check if text matches common non-secret patterns."""
        common_patterns = [
            r'^[a-f0-9]{32}$',  # MD5 hash (but could be secret)
            r'^[a-f0-9]{40}$',  # SHA1 hash
            r'^[a-f0-9]{64}$',  # SHA256 hash
            r'^[0-9]{10,}$',    # Long numbers (timestamps, IDs)
            r'^[A-Z]{2,}_[A-Z_]+$',  # Constants
            r'^[a-z]+[0-9]+$',  # Simple alphanumeric
            r'^(true|false|null|undefined)$',  # Literals
        ]
        
        for pattern in common_patterns:
            if re.match(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def _has_repeated_chars(self, text: str, threshold: float = 0.3) -> bool:
        """Check if text has too many repeated characters."""
        if len(text) < 4:
            return False
        
        char_counts = Counter(text)
        max_count = max(char_counts.values())
        
        # If any character appears more than threshold of total length
        return max_count / len(text) > threshold
    
    def classify_entropy_level(self, entropy: float) -> str:
        """Classify entropy level."""
        if entropy < 2.0:
            return "Very Low"
        elif entropy < 3.0:
            return "Low"
        elif entropy < 4.0:
            return "Medium"
        elif entropy < 5.0:
            return "High"
        else:
            return "Very High"
    
    def extract_high_entropy_strings(self, content: str) -> list:
        """Extract all high entropy strings from content."""
        # Extract potential strings using various patterns
        patterns = [
            r'["\']([A-Za-z0-9+/=]{20,})["\']',  # Base64-like
            r'["\']([A-Za-z0-9_-]{20,})["\']',   # General alphanumeric
            r'["\']([A-Fa-f0-9]{32,})["\']',     # Hex strings
            r'(?:key|token|secret|password|auth)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',  # Key-value pairs
        ]
        
        high_entropy_strings = []
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                is_secret, score, reason = self.is_potential_secret(match)
                if is_secret:
                    high_entropy_strings.append({
                        'value': match,
                        'entropy': score,
                        'reason': reason,
                        'length': len(match)
                    })
        
        # Remove duplicates and sort by entropy
        seen = set()
        unique_strings = []
        for item in high_entropy_strings:
            if item['value'] not in seen:
                seen.add(item['value'])
                unique_strings.append(item)
        
        return sorted(unique_strings, key=lambda x: x['entropy'], reverse=True)