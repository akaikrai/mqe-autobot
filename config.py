import os
from pathlib import Path
from dataclasses import dataclass

@dataclass
class Config:
    # Slack configuration
    SLACK_BOT_TOKEN: str 
    SLACK_APP_TOKEN: str
    SLACK_SIGNING_SECRET: str  # For request signature validation
    
    # AI Integration settings
    DIG_MODEL_ID: int = 42
    
    # Message handling settings
    MESSAGE_CACHE_TTL: int = 60  # Time in seconds to keep messages in deduplication cache
    THREAD_TIMEOUT: int = 300  # 5 minutes in seconds
    
    # Security settings
    ADMIN_USERS: str = ""  # Comma-separated list of admin Slack user IDs
    WHITELISTED_EMAILS: str = ""  # Comma-separated list of email addresses allowed to use the bot

def load_config():
    """Load configuration from environment variables"""
    
    # Parse boolean values
    def parse_bool(value, default=False):
        if value is None:
            return default
        return value.lower() == "true"
    
    config = Config(
        # Required settings with no defaults
        SLACK_BOT_TOKEN=os.environ["SLACK_BOT_TOKEN"],
        SLACK_APP_TOKEN=os.environ["SLACK_APP_TOKEN"],
        SLACK_SIGNING_SECRET=os.environ["SLACK_SIGNING_SECRET"],
        
        # AI Integration settings
        DIG_MODEL_ID=int(os.environ.get("DIG_MODEL_ID", 42)),
        
        # Message handling settings
        MESSAGE_CACHE_TTL=int(os.environ.get("MESSAGE_CACHE_TTL", 60)),
        THREAD_TIMEOUT=int(os.environ.get("THREAD_TIMEOUT", 300)),
        
        # Security settings
        ADMIN_USERS=os.environ.get("ADMIN_USERS", ""),
        WHITELISTED_EMAILS=os.environ.get("WHITELISTED_EMAILS", "")
    )
    
    return config
