"""
Email Whitelist Management

This module handles email-based access control for the AutoBot application.
Only users with whitelisted email addresses can access the bot.
"""

import logging
from typing import List, Set, Optional
from config import Config

logger = logging.getLogger(__name__)

class EmailWhitelist:
    """
    Manages email-based access control for the AutoBot application.
    """
    
    def __init__(self, whitelisted_emails: List[str]):
        """
        Initialize the email whitelist manager.
        
        Args:
            whitelisted_emails: List of email addresses that have access to the bot
        """
        # Convert to lowercase for case-insensitive comparison
        self.whitelisted_emails: Set[str] = set(email.lower().strip() for email in whitelisted_emails if email.strip())
        logger.info(f"Email whitelist initialized with {len(self.whitelisted_emails)} whitelisted emails")
        
        # Log whitelisted domains for debugging (without exposing full emails)
        domains = set()
        for email in self.whitelisted_emails:
            if '@' in email:
                domain = email.split('@')[1]
                domains.add(domain)
        if domains:
            logger.info(f"Whitelisted domains: {', '.join(sorted(domains))}")
    
    def is_email_allowed(self, email: str) -> bool:
        """
        Check if an email address is whitelisted.
        
        Args:
            email: Email address to check
            
        Returns:
            bool: True if email is whitelisted, False otherwise
        """
        if not email:
            logger.debug("Empty email provided for whitelist check")
            return False
            
        email_lower = email.lower().strip()
        is_allowed = email_lower in self.whitelisted_emails
        
        if is_allowed:
            logger.debug(f"Email access granted: {email}")
        else:
            logger.warning(f"Email access denied: {email}")
            
        return is_allowed
    
    def require_whitelisted_email(self, email: str) -> bool:
        """
        Require whitelisted email for an operation.
        
        Args:
            email: Email address to check
            
        Returns:
            bool: True if email is whitelisted, False otherwise
        """
        if not self.is_email_allowed(email):
            logger.warning(f"Whitelisted email required but denied for: {email}")
            return False
        return True
    
    def get_whitelisted_emails(self) -> List[str]:
        """
        Get list of whitelisted email addresses.
        
        Returns:
            List[str]: List of whitelisted email addresses
        """
        return list(self.whitelisted_emails)
    
    def add_email(self, email: str) -> bool:
        """
        Add a new email to the whitelist.
        
        Args:
            email: Email address to add to whitelist
            
        Returns:
            bool: True if added successfully, False if already exists
        """
        email_lower = email.lower().strip()
        if email_lower in self.whitelisted_emails:
            logger.warning(f"Email {email} is already whitelisted")
            return False
        
        self.whitelisted_emails.add(email_lower)
        logger.info(f"Added email {email} to whitelist")
        return True
    
    def remove_email(self, email: str) -> bool:
        """
        Remove an email from the whitelist.
        
        Args:
            email: Email address to remove from whitelist
            
        Returns:
            bool: True if removed successfully, False if not found
        """
        email_lower = email.lower().strip()
        if email_lower not in self.whitelisted_emails:
            logger.warning(f"Email {email} is not in whitelist")
            return False
        
        self.whitelisted_emails.remove(email_lower)
        logger.info(f"Removed email {email} from whitelist")
        return True
    
    def get_whitelist_count(self) -> int:
        """
        Get the number of whitelisted emails.
        
        Returns:
            int: Number of whitelisted emails
        """
        return len(self.whitelisted_emails)
    
    def is_enabled(self) -> bool:
        """
        Check if email whitelisting is enabled (has at least one email).
        
        Returns:
            bool: True if whitelist is enabled, False otherwise
        """
        return len(self.whitelisted_emails) > 0

def create_email_whitelist(config: Config) -> EmailWhitelist:
    """
    Factory function to create an EmailWhitelist instance from configuration.
    
    Args:
        config: Application configuration object
        
    Returns:
        EmailWhitelist: Configured email whitelist instance
    """
    whitelisted_emails = []
    if hasattr(config, 'WHITELISTED_EMAILS') and config.WHITELISTED_EMAILS:
        # Parse comma-separated list of email addresses
        whitelisted_emails = [email.strip() for email in config.WHITELISTED_EMAILS.split(',') if email.strip()]
    
    return EmailWhitelist(whitelisted_emails)