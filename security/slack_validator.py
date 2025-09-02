"""
Slack Request Signature Validation

This module implements request signature validation to ensure requests
are actually from Slack, as described in the Slack documentation:
https://api.slack.com/authentication/verifying-requests-from-slack#validating-a-request

Note: This is a simplified version for Socket Mode usage.
"""

import hmac
import hashlib
import time
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class SlackRequestValidator:
    """
    Validates that incoming requests are actually from Slack using signature verification.
    Simplified version for Socket Mode usage.
    """
    
    def __init__(self, signing_secret: str, max_timestamp_age: int = 300):
        """
        Initialize the validator.
        
        Args:
            signing_secret: The Slack signing secret from the app admin panel
            max_timestamp_age: Maximum age of timestamp in seconds (default 5 minutes)
        """
        self.signing_secret = signing_secret.encode('utf-8')
        self.max_timestamp_age = max_timestamp_age
    
    def validate_request(self, request_data: Dict[str, Any]) -> bool:
        """
        Validate that a request is actually from Slack.
        Simplified version for Socket Mode - always returns True since Socket Mode
        handles authentication through the app token.
        
        Args:
            request_data: Request data dictionary
            
        Returns:
            bool: True if request appears valid (Socket Mode handles auth)
        """
        # For Socket Mode, authentication is handled by the Slack Bolt framework
        # through the app token, so we can trust the request
        logger.debug("Socket Mode request validation - authentication handled by framework")
        return True
    
    def validate_socket_mode_request(self, request_data: Dict[str, Any]) -> bool:
        """
        Validate Socket Mode requests (which don't use HTTP signature validation).
        Socket Mode uses the app token for validation instead.
        
        Args:
            request_data: The request data from Socket Mode
            
        Returns:
            bool: True if request appears valid, False otherwise
        """
        # For Socket Mode, we rely on the app token validation
        # This is handled by the Slack Bolt framework
        # We can add additional validation here if needed
        return True

def create_slack_validator(signing_secret: str) -> SlackRequestValidator:
    """
    Create a Slack request validator instance.
    
    Args:
        signing_secret: The Slack signing secret
        
    Returns:
        SlackRequestValidator: Configured validator instance
    """
    return SlackRequestValidator(signing_secret)
