# Security utilities for webhook authentication

import hmac
import hashlib
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def verify_webhook_signature(
    payload: bytes,
    signature: str,
    secret: Optional[str] = None,
    algorithm: str = "sha256"
) -> bool:
    """
    Generic webhook signature verification using HMAC.

    Args:
        payload: Raw request payload bytes
        signature: Signature from request header (e.g., 'sha256=abc...')
        secret: Secret key for HMAC verification
        algorithm: Hash algorithm to use ('sha256', 'sha1', etc.)

    Returns:
        bool: True if signature is valid or verification is disabled
    """
    if not secret:
        logger.debug("No webhook secret configured, skipping signature verification")
        return True

    try:
        hash_func = getattr(hashlib, algorithm)
        expected_signature = hmac.new(
            secret.encode(),
            payload,
            hash_func
        ).hexdigest()

        expected_header = f"{algorithm}={expected_signature}"

        is_valid = hmac.compare_digest(expected_header, signature)

        if not is_valid:
            logger.warning(f"Invalid webhook signature using {algorithm}")

        return is_valid

    except Exception as e:
        logger.error(f"Error verifying webhook signature: {str(e)}")
        return False

def get_github_webhook_secret() -> Optional[str]:
    """Get GitHub webhook secret from environment"""
    return os.getenv("GITHUB_WEBHOOK_SECRET")

def get_slack_signing_secret() -> Optional[str]:
    """Get Slack signing secret from environment (for future use)"""
    return os.getenv("SLACK_SIGNING_SECRET")
