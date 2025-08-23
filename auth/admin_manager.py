"""
Admin User Management

This module handles admin user authentication and authorization for
privileged operations in the AutoBot application.
"""

import logging
from typing import List, Set, Optional
from config import Config

logger = logging.getLogger(__name__)

class AdminManager:
    """
    Manages admin users and their permissions for the AutoBot application.
    """
    
    def __init__(self, admin_users: List[str]):
        """
        Initialize the admin manager.
        
        Args:
            admin_users: List of Slack user IDs that have admin privileges
        """
        self.admin_users: Set[str] = set(admin_users) if admin_users else set()
        logger.info(f"Admin manager initialized with {len(self.admin_users)} admin users")
    
    def is_admin(self, user_id: str) -> bool:
        """
        Check if a user has admin privileges.
        
        Args:
            user_id: Slack user ID to check
            
        Returns:
            bool: True if user is an admin, False otherwise
        """
        is_admin = user_id in self.admin_users
        if is_admin:
            logger.debug(f"Admin access granted to user {user_id}")
        else:
            logger.debug(f"Admin access denied to user {user_id}")
        return is_admin
    
    def require_admin(self, user_id: str) -> bool:
        """
        Require admin privileges for an operation.
        
        Args:
            user_id: Slack user ID to check
            
        Returns:
            bool: True if user is an admin, False otherwise
        """
        if not self.is_admin(user_id):
            logger.warning(f"Admin privileges required but denied to user {user_id}")
            return False
        return True
    
    def get_admin_users(self) -> List[str]:
        """
        Get list of admin user IDs.
        
        Returns:
            List[str]: List of admin user IDs
        """
        return list(self.admin_users)
    
    def add_admin(self, user_id: str) -> bool:
        """
        Add a new admin user.
        
        Args:
            user_id: Slack user ID to add as admin
            
        Returns:
            bool: True if added successfully, False if already exists
        """
        if user_id in self.admin_users:
            logger.warning(f"User {user_id} is already an admin")
            return False
        
        self.admin_users.add(user_id)
        logger.info(f"Added user {user_id} as admin")
        return True
    
    def remove_admin(self, user_id: str) -> bool:
        """
        Remove an admin user.
        
        Args:
            user_id: Slack user ID to remove from admins
            
        Returns:
            bool: True if removed successfully, False if not found
        """
        if user_id not in self.admin_users:
            logger.warning(f"User {user_id} is not an admin")
            return False
        
        self.admin_users.remove(user_id)
        logger.info(f"Removed user {user_id} from admins")
        return True
    
    def get_admin_count(self) -> int:
        """
        Get the number of admin users.
        
        Returns:
            int: Number of admin users
        """
        return len(self.admin_users)

def create_admin_manager(config: Config) -> AdminManager:
    """
    Factory function to create an AdminManager instance from configuration.
    
    Args:
        config: Application configuration object
        
    Returns:
        AdminManager: Configured admin manager instance
    """
    admin_users = []
    if hasattr(config, 'ADMIN_USERS') and config.ADMIN_USERS:
        # Parse comma-separated list of admin user IDs
        admin_users = [user_id.strip() for user_id in config.ADMIN_USERS.split(',') if user_id.strip()]
    
    return AdminManager(admin_users)
