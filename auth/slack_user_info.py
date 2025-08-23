"""
Slack User Information Retrieval

This module handles retrieving user information from Slack API,
specifically for getting user email addresses for access control.
"""

import logging
from typing import Optional
from slack_sdk.errors import SlackApiError

logger = logging.getLogger(__name__)

class SlackUserInfoManager:
    """
    Manages retrieval of user information from Slack API.
    """
    
    def __init__(self):
        """
        Initialize the Slack user info manager.
        """
        # Cache for user info to avoid repeated API calls
        self._user_cache = {}
        logger.debug("Slack user info manager initialized")
    
    def get_user_email(self, client, user_id: str) -> Optional[str]:
        """
        Get user email address from Slack API.
        
        Args:
            client: Slack client instance
            user_id: Slack user ID
            
        Returns:
            Optional[str]: User email address if found, None otherwise
        """
        if not user_id:
            logger.debug("Empty user_id provided for email lookup")
            return None
        
        # Check cache first
        if user_id in self._user_cache:
            logger.debug(f"Using cached email for user {user_id}")
            return self._user_cache[user_id].get('email')
        
        try:
            logger.debug(f"Fetching user info for user_id: {user_id}")
            response = client.users_info(user=user_id)
            
            if response["ok"]:
                user_info = response["user"]
                profile = user_info.get("profile", {})
                email = profile.get("email")
                
                # Cache the user info
                self._user_cache[user_id] = {
                    'email': email,
                    'real_name': profile.get('real_name'),
                    'display_name': profile.get('display_name')
                }
                
                logger.debug(f"Retrieved email for user {user_id}: {email}")
                return email
            else:
                logger.warning(f"Failed to get user info for {user_id}: {response.get('error', 'Unknown error')}")
                return None
                
        except SlackApiError as e:
            error_code = e.response.get('error', 'unknown_error')
            logger.error(f"Slack API error getting user info for {user_id}: {error_code}")
            
            # Log specific permission errors for debugging
            if error_code in ['missing_scope', 'not_authed', 'invalid_auth']:
                logger.error(f"Permission error: Bot may be missing 'users:read' or 'users:read.email' scopes")
            
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting user info for {user_id}: {str(e)}")
            return None
    
    def get_user_display_name(self, client, user_id: str) -> Optional[str]:
        """
        Get user display name from Slack API.
        
        Args:
            client: Slack client instance
            user_id: Slack user ID
            
        Returns:
            Optional[str]: User display name if found, None otherwise
        """
        if user_id in self._user_cache:
            return self._user_cache[user_id].get('display_name') or self._user_cache[user_id].get('real_name')
        
        # This will populate the cache
        self.get_user_email(client, user_id)
        
        if user_id in self._user_cache:
            return self._user_cache[user_id].get('display_name') or self._user_cache[user_id].get('real_name')
        
        return None
    
    def clear_cache(self):
        """
        Clear the user info cache.
        """
        self._user_cache.clear()
        logger.debug("User info cache cleared")
    
    def get_cache_size(self) -> int:
        """
        Get the current size of the user cache.
        
        Returns:
            int: Number of cached users
        """
        return len(self._user_cache)

def create_slack_user_info_manager() -> SlackUserInfoManager:
    """
    Factory function to create a SlackUserInfoManager instance.
    
    Returns:
        SlackUserInfoManager: Configured user info manager instance
    """
    return SlackUserInfoManager()