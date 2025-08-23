"""
Slack Request Signature Validation

This module implements request signature validation to ensure requests
are actually coming from Slack, as described in the Slack documentation:
https://api.slack.com/authentication/verifying-requests-from-slack#validating-a-request
"""

import hmac
import hashlib
import time
import logging
from typing import Optional, Dict, Any
from flask import Request

logger = logging.getLogger(__name__)

class SlackRequestValidator:
    """
    Validates that incoming requests are actually from Slack using signature verification.
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
    
    def validate_request(self, request: Request) -> bool:
        """
        Validate that a request is actually from Slack.
        
        Args:
            request: Flask request object
            
        Returns:
            bool: True if request is valid, False otherwise
        """
        try:
            # Step 1: Extract the timestamp header
            timestamp = request.headers.get('X-Slack-Request-Timestamp')
            if not timestamp:
                logger.warning("Missing X-Slack-Request-Timestamp header")
                return False
            
            # Step 2: Check timestamp is recent (within 5 minutes)
            current_time = int(time.time())
            request_time = int(timestamp)
            
            if abs(current_time - request_time) > self.max_timestamp_age:
                logger.warning(f"Request timestamp too old: {request_time}, current: {current_time}")
                return False
            
            # Step 3: Get the raw request body
            request_body = request.get_data()
            
            # Step 4: Create the signature base string
            sig_basestring = f"v0:{timestamp}:{request_body.decode('utf-8')}"
            
            # Step 5: Create the expected signature
            expected_signature = f"v0={hmac.new(self.signing_secret, sig_basestring.encode('utf-8'), hashlib.sha256).hexdigest()}"
            
            # Step 6: Get the actual signature from headers
            actual_signature = request.headers.get('X-Slack-Signature')
            if not actual_signature:
                logger.warning("Missing X-Slack-Signature header")
                return False
            
            # Step 7: Compare signatures using hmac.compare_digest for timing attack protection
            if hmac.compare_digest(expected_signature, actual_signature):
                logger.debug("Request signature validation successful")
                return True
            else:
                logger.warning("Request signature validation failed")
                return False
                
        except Exception as e:
            logger.error(f"Error validating Slack request: {e}")
            return False
    
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
    Factory function to create a SlackRequestValidator instance.
    
    Args:
        signing_secret: The Slack signing secret
        
    Returns:
        SlackRequestValidator: Configured validator instance
    """
    return SlackRequestValidator(signing_secret)
