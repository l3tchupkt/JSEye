"""Enhanced secret detection engine v2 with multi-factor scoring and validation."""

import json
import re
import os
import base64
from typing import List, Dict, Any, Optional, Tuple
from .entropy import EntropyAnalyzer
from .utils import mask_secret, extract_secrets_context
from .logging import get_logger

from .logging import get_logger

logger = get_logger(__name__)

def v3_mask_secret(secret_val: str) -> str:
    """Mask value except for first 4 and last 4 characters."""
    if not secret_val or len(secret_val) <= 8:
        return "********"
    return f"{secret_val[:4]}{'*' * (len(secret_val) - 8)}{secret_val[-4:]}"


class SecretDetector:
    """Enhanced secret detector with multi-factor scoring and validation."""
    
    def __init__(self):
        self.entropy_analyzer = EntropyAnalyzer()
        self.patterns = self._load_patterns()
        self.min_confidence = 0.4  # Lowered for better detection
        self.logger = get_logger(__name__)
    
    def _load_patterns(self) -> Dict[str, Any]:
        """Load regex patterns from JSON file."""
        try:
            patterns_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'regex_patterns.json')
            with open(patterns_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load patterns file: {e}")
            # Enhanced fallback patterns
            return {
                "secrets": {
                    "aws_access_key": {
                        "pattern": "AKIA[0-9A-Z]{16}",
                        "description": "AWS Access Key ID",
                        "severity": "high",
                        "confidence": 0.95
                    },
                    "generic_api_key": {
                        "pattern": "(?i)(?:api[_-]?key|apikey)\\s*[:=]\\s*['\"]?([a-zA-Z0-9_\\-]{16,})['\"]?",
                        "description": "Generic API Key",
                        "severity": "medium",
                        "confidence": 0.6
                    }
                }
            }
    
    def detect_secrets(self, content: str, source_file: str = "") -> List[Dict[str, Any]]:
        """Detect all secrets with enhanced multi-factor scoring."""
        secrets = []
        
        try:
            # Pattern-based detection
            pattern_secrets = self._detect_pattern_secrets(content, source_file)
            secrets.extend(pattern_secrets)
            
            # Entropy-based detection
            entropy_secrets = self._detect_entropy_secrets(content, source_file)
            secrets.extend(entropy_secrets)
            
            # Enhanced scoring with context analysis
            for secret in secrets:
                enhanced_score = self._calculate_enhanced_score(secret, content)
                secret.update(enhanced_score)
                
                # Add risk analysis
                risk_analysis = self.analyze_secret_risk(secret)
                secret.update(risk_analysis)
            
            # Validation pass
            validated_secrets = []
            for secret in secrets:
                if self._validate_secret(secret):
                    validated_secrets.append(secret)
                else:
                    self.logger.debug(f"Secret validation failed: {secret.get('type', 'unknown')}")
            
            # Deduplicate and sort by confidence
            validated_secrets = self._deduplicate_secrets(validated_secrets)
            validated_secrets.sort(key=lambda x: x.get('enhanced_confidence', x.get('confidence', 0)), reverse=True)
            
            return validated_secrets
            
        except Exception as e:
            self.logger.error(f"Secret detection failed for {source_file}: {e}")
            return []
    
    def _detect_pattern_secrets(self, content: str, source_file: str) -> List[Dict[str, Any]]:
        """Detect secrets using regex patterns."""
        secrets = []
        
        for secret_type, pattern_info in self.patterns.get('secrets', {}).items():
            pattern = pattern_info['pattern']
            description = pattern_info['description']
            severity = pattern_info['severity']
            confidence = pattern_info.get('confidence', 0.7)
            context_required = pattern_info.get('context_required', [])
            
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    secret_value = match.group(1) if match.groups() else match.group(0)
                    
                    # Skip if too short or too long
                    if len(secret_value) < 4 or len(secret_value) > 500:
                        continue
                    
                    # Check context requirements
                    if context_required and not self._check_context(content, match.start(), context_required):
                        confidence *= 0.5  # Reduce confidence if context not found
                    
                    # Skip if confidence too low
                    if confidence < self.min_confidence:
                        continue
                    
                    # Extract context around the match
                    context = extract_secrets_context(content, secret_value)
                    
                    secret = {
                        'type': secret_type,
                        'description': description,
                        'value': secret_value,
                        'masked_value': v3_mask_secret(secret_value),
                        'confidence_score': float(confidence),
                        'severity': severity,
                        'confidence': confidence,
                        'source': 'pattern_match',
                        'file_or_url': source_file,
                        'source_file': source_file,
                        'context': context,
                        'validated': False,
                        'used_in_request': False
                    }
                    
                    secrets.append(secret)
                    
            except re.error as e:
                # Skip invalid regex patterns
                continue
        
        return secrets
    
    def _detect_entropy_secrets(self, content: str, source_file: str) -> List[Dict[str, Any]]:
        """Detect secrets using entropy analysis."""
        secrets = []
        
        # Extract high entropy strings
        high_entropy_strings = self.entropy_analyzer.extract_high_entropy_strings(content)
        
        for entropy_data in high_entropy_strings:
            entropy_str = entropy_data['value']
            entropy_score = entropy_data['entropy']
            metrics = entropy_data['metrics']
            
            # Skip if already detected by patterns
            if self._is_already_detected(entropy_str, secrets):
                continue
            
            # Calculate confidence based on entropy and characteristics
            confidence = min(0.9, entropy_score / 6.0)  # Normalize to 0-0.9
            
            if confidence < self.min_confidence:
                continue
            
            # Determine severity based on entropy
            if entropy_score >= 5.0:
                severity = "high"
            elif entropy_score >= 4.0:
                severity = "medium"
            else:
                severity = "low"
            
            context = extract_secrets_context(content, entropy_str)
            
            secret = {
                'type': 'high_entropy_string',
                'description': 'High entropy string (potential secret)',
                'value': entropy_str,
                'masked_value': v3_mask_secret(entropy_str),
                'confidence_score': float(confidence),
                'severity': 'medium',
                'confidence': confidence,
                'source': 'entropy_analysis',
                'file_or_url': source_file,
                'source_file': source_file,
                'context': extract_secrets_context(content, entropy_str),
                'metrics': metrics,
                'validated': False,
                'used_in_request': False
            }
            secrets.append(secret)
        
        return secrets
    
    def _check_context(self, content: str, position: int, required_terms: List[str]) -> bool:
        """Check if required context terms are present around the match."""
        # Extract context around position (±200 characters)
        start = max(0, position - 200)
        end = min(len(content), position + 200)
        context = content[start:end].lower()
        
        # Check if any required term is present
        for term in required_terms:
            if term.lower() in context:
                return True
        
        return False
    
    def _is_already_detected(self, value: str, existing_secrets: List[Dict[str, Any]]) -> bool:
        """Check if a secret value was already detected."""
        for secret in existing_secrets:
            if secret['value'] == value:
                return True
        return False
    
    def _deduplicate_secrets(self, secrets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate secrets based on value."""
        seen_values = set()
        unique_secrets = []
        
        for secret in secrets:
            value = secret['value']
            if value not in seen_values:
                seen_values.add(value)
                unique_secrets.append(secret)
        
        return unique_secrets
    
    def _calculate_enhanced_score(self, secret: Dict[str, Any], content: str) -> Dict[str, Any]:
        """Calculate enhanced confidence score using multi-factor analysis."""
        base_confidence = secret.get('confidence', 0.5)
        enhanced_confidence = base_confidence
        scoring_factors = []
        
        secret_value = secret.get('value', '')
        secret_type = secret.get('type', '')
        context = secret.get('context', '')
        
        # Factor 1: Variable name context
        var_name_boost = self._analyze_variable_name_context(context)
        enhanced_confidence += var_name_boost
        if var_name_boost > 0:
            scoring_factors.append(f"Variable name context (+{var_name_boost:.2f})")
        
        # Factor 2: Usage in fetch/axios calls
        fetch_usage_boost = self._analyze_fetch_usage(secret_value, content)
        enhanced_confidence += fetch_usage_boost
        if fetch_usage_boost > 0:
            scoring_factors.append(f"Used in HTTP requests (+{fetch_usage_boost:.2f})")
            secret['used_in_request'] = True
        
        # Factor 3: Authorization header usage
        auth_header_boost = self._analyze_auth_header_usage(secret_value, content)
        enhanced_confidence += auth_header_boost
        if auth_header_boost > 0:
            scoring_factors.append(f"Used in auth headers (+{auth_header_boost:.2f})")
            secret['used_in_request'] = True
        
        # Factor 4: External domain usage
        external_domain_boost = self._analyze_external_domain_usage(secret_value, content)
        enhanced_confidence += external_domain_boost
        if external_domain_boost > 0:
            scoring_factors.append(f"Used with external domains (+{external_domain_boost:.2f})")
            secret['used_in_request'] = True
        
        # Factor 5: Format validation
        format_validation_boost = self._validate_secret_format(secret_type, secret_value)
        enhanced_confidence += format_validation_boost
        if format_validation_boost > 0:
            scoring_factors.append(f"Valid format (+{format_validation_boost:.2f})")
        
        # Penalty for common false positives
        false_positive_penalty = self._check_false_positive_patterns(secret_value, context)
        enhanced_confidence -= false_positive_penalty
        if false_positive_penalty > 0:
            scoring_factors.append(f"False positive patterns (-{false_positive_penalty:.2f})")
        
        # Cap confidence at 1.0
        enhanced_confidence = min(enhanced_confidence, 1.0)
        
        return {
            'enhanced_confidence': enhanced_confidence,
            'scoring_factors': scoring_factors,
            'confidence_boost': enhanced_confidence - base_confidence
        }
    
    def _analyze_variable_name_context(self, context: str) -> float:
        """Analyze variable name context for secret indicators."""
        secret_indicators = [
            'api_key', 'apikey', 'secret', 'token', 'password', 'passwd', 'pwd',
            'auth', 'authorization', 'bearer', 'key', 'credential', 'cred'
        ]
        
        context_lower = context.lower()
        boost = 0.0
        
        for indicator in secret_indicators:
            if indicator in context_lower:
                boost += 0.1
        
        return min(boost, 0.3)  # Cap at 0.3
    
    def _analyze_fetch_usage(self, secret_value: str, content: str) -> float:
        """Check if secret is used in fetch/axios calls."""
        # Look for the secret value in fetch/axios contexts
        # Use a shorter substring to improve matching
        secret_substr = secret_value[:8] if len(secret_value) > 8 else secret_value
        
        fetch_patterns = [
            rf'fetch\s*\([^)]*{re.escape(secret_substr)}[^)]*\)',
            rf'axios\.[a-z]+\s*\([^)]*{re.escape(secret_substr)}[^)]*\)',
            rf'XMLHttpRequest[^}}]*{re.escape(secret_substr)}',
            # Also check for variable usage in fetch
            rf'fetch\s*\([^)]*apiKey[^)]*\)',
            rf'axios\.[a-z]+\s*\([^)]*apiKey[^)]*\)',
            rf'headers[^}}]*{re.escape(secret_substr)}',
            rf'Authorization[^}}]*{re.escape(secret_substr)}',
        ]
        
        for pattern in fetch_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return 0.2
        
        return 0.0
    
    def _analyze_auth_header_usage(self, secret_value: str, content: str) -> float:
        """Check if secret is used in authorization headers."""
        auth_patterns = [
            rf'["\']Authorization["\']:\s*["\'][^"\']*{re.escape(secret_value[:10])}',
            rf'["\']Bearer\s+{re.escape(secret_value[:10])}',
            rf'setRequestHeader\s*\(\s*["\']Authorization["\'][^)]*{re.escape(secret_value[:10])}',
        ]
        
        for pattern in auth_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return 0.25
        
        return 0.0
    
    def _analyze_external_domain_usage(self, secret_value: str, content: str) -> float:
        """Check if secret is used with external domain calls."""
        # Look for secret used with external URLs
        external_patterns = [
            rf'https?://[^/\s]+[^}}]*{re.escape(secret_value[:10])}',
            rf'{re.escape(secret_value[:10])}[^}}]*https?://[^/\s]+',
        ]
        
        for pattern in external_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return 0.15
        
        return 0.0
    
    def _validate_secret_format(self, secret_type: str, secret_value: str) -> float:
        """Validate secret format for known types."""
        validators = {
            'aws_access_key': self._validate_aws_key,
            'jwt_token': self._validate_jwt,
            'stripe_key': self._validate_stripe_key,
            'slack_token': self._validate_slack_token,
        }
        
        validator = validators.get(secret_type)
        if validator and validator(secret_value):
            return 0.2
        
        return 0.0
    
    def _validate_aws_key(self, value: str) -> bool:
        """Validate AWS access key format."""
        return bool(re.match(r'^AKIA[0-9A-Z]{16}$', value))
    
    def _validate_jwt(self, value: str) -> bool:
        """Validate JWT token structure."""
        parts = value.split('.')
        if len(parts) != 3:
            return False
        
        try:
            # Try to decode header and payload (not signature)
            header = base64.b64decode(parts[0] + '==')
            payload = base64.b64decode(parts[1] + '==')
            
            # Check if they're valid JSON
            json.loads(header)
            json.loads(payload)
            return True
        except Exception:
            return False
    
    def _validate_stripe_key(self, value: str) -> bool:
        """Validate Stripe key format."""
        return bool(re.match(r'^(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{24}$', value))
    
    def _validate_slack_token(self, value: str) -> bool:
        """Validate Slack token format."""
        return bool(re.match(r'^xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}$', value))
    
    def _check_false_positive_patterns(self, secret_value: str, context: str) -> float:
        """Check for common false positive patterns."""
        penalty = 0.0
        
        # Common false positives
        false_positive_patterns = [
            r'^(test|example|demo|sample|placeholder|dummy)',
            r'^(your|my|the)[-_]?(api|key|token|secret)',
            r'^(insert|add|put|enter)[-_]?(your|api|key|token)',
            r'^[a-z]{1,3}$',  # Very short strings
            r'^(true|false|null|undefined)$',
            r'^\d+$',  # Pure numbers
            r'^[0-9a-f]{32}$',  # MD5 hashes (common in examples)
        ]
        
        value_lower = secret_value.lower()
        context_lower = context.lower()
        
        for pattern in false_positive_patterns:
            if re.match(pattern, value_lower):
                penalty += 0.3
                break
        
        # Check context for test/example indicators
        test_indicators = ['test', 'example', 'demo', 'sample', 'placeholder', 'mock', 'fake']
        for indicator in test_indicators:
            if indicator in context_lower:
                penalty += 0.2
                break
        
        return min(penalty, 0.5)  # Cap penalty
    
    def _validate_secret(self, secret: Dict[str, Any]) -> bool:
        """Enhanced validation layer returning bool. Also sets 'validated' flag."""
        is_valid = self._perform_validation_check(secret)
        secret['validated'] = is_valid
        return is_valid

    def _perform_validation_check(self, secret: Dict[str, Any]) -> bool:
        """Perform actual format validation checks."""
        secret_type = secret.get('type', '')
        value = secret.get('value', '')
        enhanced_confidence = secret.get('enhanced_confidence', secret.get('confidence', 0))
        
        # Minimum confidence threshold
        if enhanced_confidence < self.min_confidence:
            return False
        
        # Length checks
        secret_value = secret.get('value', '')
        if len(secret_value) < 4 or len(secret_value) > 500:
            return False
        
        # Skip very common patterns
        if secret_value.lower() in ['test', 'example', 'demo', 'sample', 'key', 'token', 'secret']:
            return False
        
        return True
    
    def analyze_secret_risk(self, secret: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced risk analysis with v2 scoring model."""
        risk_score = 0
        risk_factors = []
        
        # Base score from severity
        severity_scores = {
            'critical': 40,  # Increased base scores
            'high': 30,
            'medium': 20,
            'low': 10
        }
        risk_score += severity_scores.get(secret['severity'], 10)
        
        # Enhanced confidence factor
        enhanced_confidence = secret.get('enhanced_confidence', secret.get('confidence', 0))
        risk_score += enhanced_confidence * 25  # Increased weight
        
        # Type-specific factors (enhanced)
        secret_type = secret['type']
        
        if 'aws' in secret_type:
            risk_score += 20  # Increased from 15
            risk_factors.append("AWS credentials provide cloud infrastructure access")
        
        if 'private_key' in secret_type:
            risk_score += 25  # Increased from 20
            risk_factors.append("Private keys provide cryptographic access")
        
        if 'stripe' in secret_type and 'live' in secret_type:
            risk_score += 20  # Increased from 15
            risk_factors.append("Live payment processing credentials")
        
        if 'github' in secret_type:
            risk_score += 15  # Increased from 10
            risk_factors.append("Source code repository access")
        
        if 'jwt' in secret_type:
            risk_score += 12  # Increased from 10
            risk_factors.append("Authentication token")
        
        # New factors for v2
        if 'slack' in secret_type:
            risk_score += 10
            risk_factors.append("Team communication access")
        
        if 'firebase' in secret_type:
            risk_score += 15
            risk_factors.append("Database and backend access")
        
        # Context factors (enhanced)
        context = secret.get('context', '').lower()
        if 'production' in context or 'prod' in context:
            risk_score += 15  # Increased from 10
            risk_factors.append("Production environment")
        
        if 'live' in context:
            risk_score += 15  # Increased from 10
            risk_factors.append("Live environment")
        
        if 'admin' in context:
            risk_score += 12
            risk_factors.append("Administrative access")
        
        # Usage context factors (new in v2)
        scoring_factors = secret.get('scoring_factors', [])
        for factor in scoring_factors:
            if 'HTTP requests' in factor:
                risk_score += 8
                risk_factors.append("Used in network requests")
            elif 'auth headers' in factor:
                risk_score += 10
                risk_factors.append("Used in authentication headers")
            elif 'external domains' in factor:
                risk_score += 6
                risk_factors.append("Used with external services")
        
        # Entropy factor for high entropy strings
        if secret.get('entropy', 0) > 5.0:
            risk_score += 8  # Increased from 5
            risk_factors.append("Very high entropy")
        
        # Format validation bonus
        if secret.get('confidence_boost', 0) > 0.15:
            risk_score += 5
            risk_factors.append("Valid secret format detected")
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        # Determine risk level with updated thresholds
        if risk_score >= 76:
            risk_level = "Critical"
        elif risk_score >= 51:
            risk_level = "High"
        elif risk_score >= 26:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }
    
    def get_remediation_advice(self, secret: Dict[str, Any]) -> str:
        """Get remediation advice for a detected secret."""
        secret_type = secret['type']
        
        advice_map = {
            'aws_access_key': "Rotate AWS credentials immediately. Use IAM roles or environment variables.",
            'aws_secret_key': "Rotate AWS credentials immediately. Use IAM roles or environment variables.",
            'stripe_key': "Rotate Stripe API keys. Use environment variables and restrict key permissions.",
            'github_token': "Revoke GitHub token and generate new one. Use GitHub Secrets for CI/CD.",
            'jwt_token': "Invalidate JWT token. Implement proper token rotation and short expiry times.",
            'private_key': "Rotate private key immediately. Use secure key management systems.",
            'bearer_token': "Revoke and regenerate bearer token. Implement proper token management.",
            'basic_auth': "Remove hardcoded credentials. Use secure authentication mechanisms.",
            'high_entropy_string': "Review if this is a secret. If so, move to environment variables."
        }
        
        specific_advice = advice_map.get(secret_type, 
            "Remove hardcoded secret from source code. Use environment variables or secure vaults.")
        
        general_advice = """
General recommendations:
1. Use environment variables for secrets
2. Implement secret scanning in CI/CD
3. Use secret management tools (HashiCorp Vault, AWS Secrets Manager)
4. Rotate secrets regularly
5. Implement least privilege access
"""
        
        return f"{specific_advice}\n{general_advice}"


# ---------------------------------------------------------------------------
# Backward-compat alias: test suite and older callers use SecretEngine.
# ---------------------------------------------------------------------------
class SecretEngine(SecretDetector):
    """Backward-compatible alias for SecretDetector.

    Adds ``scan_content()`` as an alias for ``detect_secrets()`` so that
    callers using the old SecretEngine API continue to work.
    """

    def scan_content(self, content: str, source_file: str = "") -> list:
        """Alias for detect_secrets() for backward compatibility."""
        return self.detect_secrets(content, source_file)
