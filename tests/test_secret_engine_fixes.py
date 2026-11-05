"""Tests for SecretDetector fixes: entropy KeyError, JWT decoding, and validation semantics."""

import base64
import json

from jseye.core.secret_engine import SecretDetector


def test_entropy_secrets_no_key_error():
    # Crucial bug fix: high entropy strings returned without 'metrics' key must not raise KeyError
    detector = SecretDetector()
    # High entropy base64 string
    content = """
    const apiKey = "dGhpcy1pcy1hLXZlcnktaGlnaC1lbnRyb3B5LXNlY3JldC1zdHJpbmctZm9yLXRlc3Rpbmc=";
    const sessionToken = "xK9#mQ2$pL5!vN8&wR1*jZ4@tB7^yC0%";
    """
    secrets = detector.detect_secrets(content, "test.js")
    # Must succeed without throwing KeyError: 'metrics'
    assert isinstance(secrets, list)
    for s in secrets:
        if s.get('type') == 'high_entropy_string':
            assert "metrics" in s
        assert "validated" in s


def test_jwt_validation_urlsafe_and_padding():
    detector = SecretDetector()

    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "1234567890", "name": "John Doe", "admin": True}).encode()).decode().rstrip("=")
    signature = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    valid_jwt = f"{header}.{payload}.{signature}"
    assert detector._validate_jwt(valid_jwt) is True

    # Malformed parts
    assert detector._validate_jwt("not.a.jwt") is False
    assert detector._validate_jwt("header.invalid_base64!@#$.sig") is False
    assert detector._validate_jwt("only_one_part") is False


def test_secret_validation_semantics_not_fake():
    # Crucial security fix: static detection should not claim 'validated: True' without live API probe
    detector = SecretDetector()
    content = """
    const awsKey = "AKIAIOSFODNN7EXAMPLE";
    """
    secrets = detector.detect_secrets(content, "config.js")
    assert len(secrets) > 0
    aws_secret = secrets[0]
    # format_valid is True because structure matches AKIA...
    assert aws_secret.get("format_valid") is True
    # validated must remain False because no live AWS STS call verified it
    assert aws_secret.get("validated") is False
