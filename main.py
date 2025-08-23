import os
import re
import logging
import signal
import sys
import json
import hashlib
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from dotenv import load_dotenv

# Import components
from config import load_config, Config
from dig_connector import setup_dig_ai
from utils import should_process_message, send_long_message, manage_active_thread

# Import security components
from security.slack_validator import create_slack_validator
from security.content_filter import create_content_filter
from auth.admin_manager import create_admin_manager
from auth.email_whitelist import create_email_whitelist
from auth.slack_user_info import create_slack_user_info_manager

# Load variables from .env file
load_dotenv()

# Set up logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for maximum verbosity
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler("ai_assistant_bot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load configuration
logger.info("Loading application configuration...")
config = load_config()
logger.info("Configuration loaded successfully")

# Initialize security components
logger.info("Initializing security components...")
slack_validator = create_slack_validator(config.SLACK_SIGNING_SECRET)
logger.debug("Slack validator initialized")

content_filter = create_content_filter()
logger.debug("Content filter initialized")

admin_manager = create_admin_manager(config)
logger.debug("Admin manager initialized")

email_whitelist = create_email_whitelist(config)
logger.debug(f"Email whitelist initialized with {email_whitelist.get_whitelist_count()} emails")

slack_user_info = create_slack_user_info_manager()
logger.debug("Slack user info manager initialized")
logger.info("Security components initialized successfully")

# Initialize the Slack app
logger.info("Initializing Slack app...")
app = App(token=config.SLACK_BOT_TOKEN)
logger.info("Slack app initialized successfully")

# Message deduplication cache
processed_messages = {}
logger.debug("Message deduplication cache initialized")

# Mapping of Slack channel IDs to in-progress threads
active_threads = {}  # Format: {"channel_id:ts": (start_time, user_id)}
active_threads_lock = threading.Lock()
logger.debug("Thread tracking initialized")

# DIG AI integration
logger.info("Initializing DIG AI integration...")
dig_connector = setup_dig_ai(config)
if dig_connector:
    logger.info("DIG AI integration successfully initialized")
else:
    logger.error("DIG AI integration failed to initialize")

logger.info("Setting up event handlers...")

def check_user_access(client, user_id: str) -> tuple[bool, str]:
    """
    Check if user has access to the bot based on email whitelist.
    
    Args:
        client: Slack client instance
        user_id: Slack user ID
        
    Returns:
        tuple[bool, str]: (has_access, error_message)
    """
    # If no emails are whitelisted, allow all users
    if not email_whitelist.is_enabled():
        logger.debug("Email whitelist is disabled, allowing all users")
        return True, ""
    
    # Get user email from Slack
    user_email = slack_user_info.get_user_email(client, user_id)
    
    if not user_email:
        logger.warning(f"Could not retrieve email for user {user_id}")
        # Check if this is a known admin user as fallback
        if admin_manager.is_admin(user_id):
            logger.info(f"Granting access to admin user {user_id} despite email retrieval failure")
            return True, ""
        return False, "I'm sorry, but I couldn't verify your access permissions. This may be due to missing bot permissions or your email not being visible in your Slack profile. Please contact your administrator."
    
    # Check if email is whitelisted
    if email_whitelist.is_email_allowed(user_email):
        logger.info(f"Access granted to user {user_id} with email {user_email}")
        return True, ""
    else:
        logger.warning(f"Access denied to user {user_id} with email {user_email}")
        return False, "I'm sorry, but you don't have access to this information. Please contact your administrator if you believe this is an error."

def clean_url(url):
    """
    Clean and validate a URL, removing malformed parts.
    Only allows URLs from paramount.atlassian.net/wiki/spaces/PLQA.
    """
    import re
    
    if not url:
        return None
    
    # Remove trailing punctuation, brackets, backticks, quotation marks, and commas that are not part of the URL
    url = re.sub(r'[`\]\)"\',,]+$', '', url)
    
    # Remove any trailing fragments that look malformed
    url = re.sub(r'\].*$', '', url)
    
    # Basic validation - must start with http/https and have a domain
    if not re.match(r'https?://[a-zA-Z0-9.-]+', url):
        return None
    
    # Only allow URLs from paramount.atlassian.net/wiki/spaces/PLQA
    if not 'paramount.atlassian.net/wiki/spaces/PLQA' in url:
        return None
    
    return url.strip()

def extract_title_from_url(url):
    """
    Extract a meaningful title from a URL for display in the sources section.
    """
    import re
    
    # Try to extract a meaningful title from the URL
    if 'atlassian' in url and 'confluence' in url:
        # For Atlassian Confluence pages, try to extract page title from URL structure
        # Pattern: /wiki/spaces/SPACE/pages/PAGEID/PAGE-TITLE
        page_title_match = re.search(r'/pages/\d+/([^/?#]+)', url)
        if page_title_match:
            # Convert URL-encoded title to readable format
            page_title = page_title_match.group(1)
            page_title = page_title.replace('-', ' ').replace('+', ' ')
            # Decode common URL encodings
            page_title = page_title.replace('%20', ' ')
            return page_title.title()
        else:
            return "Confluence Documentation"
    elif 'atlassian' in url:
        return "Atlassian Documentation"
    elif 'github' in url:
        return "GitHub"
    elif 'stackoverflow' in url:
        return "Stack Overflow"
    else:
        # Use domain name as title
        domain_match = re.search(r'https?://([^/]+)', url)
        return domain_match.group(1) if domain_match else "Link"

def clean_response_for_slack(text):
    """
    Clean AI response text to display properly in Slack with professional formatting.
    Converts escaped characters, improves formatting, and handles source links.
    """
    if not text:
        return text
    
    import re
    
    # Convert escaped newlines to actual newlines
    text = text.replace('\\n', '\n')
    
    # Convert escaped tabs to spaces
    text = text.replace('\\t', '    ')
    
    # Convert markdown bold **text** to Slack format *text*
    text = re.sub(r'\*\*(.*?)\*\*', r'*\1*', text)
    
    # Extract and collect source links
    source_links = []
    
    # Find naked URLs in the text and extract them
    naked_urls = re.findall(r'https?://[^\s\)]+', text)
    for url_string in naked_urls:
        # Split URLs that might be comma-separated
        individual_urls = re.split(r',\s*', url_string)
        for url in individual_urls:
            # Clean malformed URLs (remove trailing brackets, etc.)
            url = clean_url(url.strip())
            if url:  # Only add if URL is valid after cleaning
                title = extract_title_from_url(url)
                source_links.append((title, url))
    
    # Find various source link patterns and collect them
    # Pattern 1: [Source: text](url)
    source_pattern1 = re.findall(r'\[Source:\s*([^\]]+)\]\((https?://[^\)]+)\)', text, re.IGNORECASE)
    for title, url in source_pattern1:
        url = clean_url(url)
        if url:
            source_links.append((title.strip(), url))
    
    # Pattern 2: Source: [text](url)
    source_pattern2 = re.findall(r'Source:\s*\[([^\]]+)\]\((https?://[^\)]+)\)', text, re.IGNORECASE)
    for title, url in source_pattern2:
        url = clean_url(url)
        if url:
            source_links.append((title.strip(), url))
    
    # Pattern 3: (Source: url) patterns
    source_pattern3 = re.findall(r'\(Source:\s*(https?://[^\)]+)\)', text, re.IGNORECASE)
    for url in source_pattern3:
        url = clean_url(url)
        if url:
            title = extract_title_from_url(url)
            source_links.append((title, url))
    
    # Remove ALL inline source citations from the text
    # Remove formal source patterns since we'll collect the URLs separately
    text = re.sub(r'\[Source:\s*[^\]]+\]\(https?://[^\)]+\)', '', text, flags=re.IGNORECASE)
    text = re.sub(r'Source:\s*\[[^\]]+\]\(https?://[^\)]+\)', '', text, flags=re.IGNORECASE)
    # Remove inline (Source: url) patterns - comprehensive removal
    text = re.sub(r'\(Source:\s*[^\)]*https?://[^\)]*\)', '', text, flags=re.IGNORECASE)
    # Remove patterns like (Source: `url`)
    text = re.sub(r'\(Source:\s*`[^`]*`\)', '', text, flags=re.IGNORECASE)
    # Remove any remaining source references with URLs
    text = re.sub(r'Source:\s*https?://[^\s\)]+', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\(Source:[^)]*\)', '', text, flags=re.IGNORECASE)
    # Remove "according to" patterns with empty spaces
    text = re.sub(r'\(according to\s*\)\s*:?', '', text, flags=re.IGNORECASE)
    text = re.sub(r'according to\s*:', '', text, flags=re.IGNORECASE)
    
    # Remove all asterisk (*) characters 
    text = re.sub(r'\*', '', text)
    
    # Format numbered sections: put numbered items on separate lines with extra spacing
    text = re.sub(r'^(\d+\.\s+[^:]+:)\s*', r'\n\1\n', text, flags=re.MULTILINE)
    
    # Remove naked URLs from the response body AFTER collecting them for sources
    text = re.sub(r'https?://[^\s\n]+', '', text)
    
    # Clean up excessive newlines and whitespace
    text = re.sub(r'\n\s*\n\s*\n+', '\n\n', text)
    
    # Remove any trailing whitespace on lines
    lines = text.split('\n')
    cleaned_lines = [line.rstrip() for line in lines]
    text = '\n'.join(cleaned_lines).strip()
    
    # Add source links section at the end if we found any
    if source_links:
        # Remove duplicates while preserving order
        unique_sources = []
        seen_urls = set()
        for title, url in source_links:
            if url not in seen_urls:
                unique_sources.append((title, url))
                seen_urls.add(url)
        
        if unique_sources:
            text += '\n\n' + '─' * 40 + '\n'
            text += '📚 Sources:\n'
            for i, (title, url) in enumerate(unique_sources, 1):
                # Use naked links for Atlassian/Confluence, otherwise use titles
                if 'atlassian' in url.lower() or 'confluence' in url.lower():
                    text += f'{i}. {url}\n'
                else:
                    text += f'{i}. <{url}|{title}>\n'
    
    return text

def format_response_for_slack(question, response):
    """
    Format the complete response with professional styling for Slack.
    """
    # Clean the response content
    cleaned_response = clean_response_for_slack(response)
    
    # Create professional formatting
    formatted_response = f"""Your Question:
> {question}

Answer:

{cleaned_response}"""
    
    return formatted_response

@app.event("app_mention")
def handle_app_mentions(body, say, client):
    """Process messages where the bot is mentioned in channels."""
    logger.info("=== APP MENTION EVENT RECEIVED ===")
    logger.debug(f"Full event body: {body}")
    
    event = body.get("event", {})
    logger.info(f"App mention event details: channel={event.get('channel')}, user={event.get('user')}, ts={event.get('ts')}")
    logger.debug(f"App mention event text: {event.get('text', '')}")
    
    # Skip if we've processed this message recently
    if not should_process_message(event, processed_messages):
        logger.info("Skipping message - already processed recently")
        return
        
    channel_id = event["channel"]
    thread_ts = event.get("thread_ts", event.get("ts"))
    user_id = event["user"]
    text = event["text"]
    
    logger.info(f"Processing mention: channel_id={channel_id}, thread_ts={thread_ts}, user_id={user_id}")
    
    # Check user access before processing
    logger.debug("Checking user access...")
    has_access, access_error = check_user_access(client, user_id)
    if not has_access:
        logger.warning(f"Access denied for user {user_id} in app mention")
        say(text=access_error)
        return
    logger.debug("User access check passed")
    
    logger.debug("Proceeding to process app mention...")
    
    # Extract the question (remove the app mention)
    question = re.sub(r'<@[A-Z0-9]+>\s*', '', text).strip()
    logger.info(f"Extracted question: '{question}'")
    
    if not question:
        logger.warning("Empty question received")
        return
    
    # Check for admin commands
    logger.debug(f"Checking if '{question.lower()}' is an admin command in app mention")
    if question.lower() == "refresh":
        if not admin_manager.require_admin(user_id):
            say(text="Sorry, only authorized administrators can perform this action.")
            return
        
        say(text="DIG AI connection is always live - no refresh needed! 🎉")
        return
    
    elif question.lower() == "status":
        if not admin_manager.require_admin(user_id):
            say(text="Sorry, only authorized administrators can view system status.")
            return
        
        status_message = f"""
*System Status*
• Bot Status: Running
• DIG AI: {'Connected' if dig_connector else 'Disconnected'}
• Admin Users: {admin_manager.get_admin_count()}
• Email Whitelist: {'Enabled' if email_whitelist.is_enabled() else 'Disabled'}
        """.strip()
        
        say(text=status_message)
        return
    
    # Check if this thread is already being processed
    logger.debug("Checking if thread is already being processed...")
    if not manage_active_thread(channel_id, thread_ts, user_id, "add", active_threads, active_threads_lock, config.THREAD_TIMEOUT):
        logger.info(f"Thread {thread_ts} is already being processed")
        say(text="I'm already processing a request in this thread. Please wait until it's complete before asking another question.")
        return
    logger.debug("Thread management check passed")
    
    try:
        # Show typing indicator
        logger.debug("Adding thinking face reaction...")
        try:
            client.reactions_add(
                channel=channel_id,
                timestamp=thread_ts,
                name="thinking_face"
            )
            logger.debug("Thinking face reaction added successfully")
        except Exception as e:
            logger.warning(f"Could not add reaction: {str(e)}. This is non-critical.")
            # Use typing indicator as alternative if reactions fail
            try:
                client.conversations_mark(channel=channel_id, ts=thread_ts)
                logger.debug("Used conversations_mark as alternative")
            except Exception as e2:
                logger.warning(f"Could not use conversations_mark alternative: {str(e2)}")
                pass
        
        # Check if DIG AI is available
        logger.debug("Checking DIG AI connector availability...")
        if not dig_connector:
            logger.error("DIG AI connector is not available")
            say(text="I'm having trouble connecting to the AI service. Please try again later.")
            return
        logger.debug("DIG AI connector is available")
        
        # Log the query
        logger.info(f"Processing question from user {user_id}: {question}")
        
        # Generate response using DIG AI
        try:
            logger.info("Sending request to DIG AI...")
            # For now, we'll use DIG AI without context since there's no knowledge base
            response = dig_connector.generate_response(question, [])
            logger.info("Received response from DIG AI")
            logger.debug(f"DIG AI response: {response}")
            
            # Format the response professionally for Slack
            formatted_response = format_response_for_slack(question, response)
            logger.debug(f"Formatted response: {formatted_response}")
        except Exception as e:
            logger.error(f"Error generating response: {str(e)}", exc_info=True)
            say(text="I encountered an error while processing your question. Please try again later.")
            return
        
        # Apply content filtering for sensitive data
        filtered_response, findings = content_filter.filter_content(formatted_response)
        
        # Check if response should be blocked due to sensitive content
        if content_filter.should_block_response(findings):
            logger.warning(f"Blocking response due to sensitive content detected for user {user_id}")
            say(text="I'm sorry, but I cannot provide this information as it may contain sensitive data. Please contact your administrator for assistance.")
            return
        
        # Log if any content was filtered
        if findings:
            logger.info(f"Content filtered for user {user_id}: {content_filter.get_filter_summary(findings)}")
            formatted_response = filtered_response
        
        # Check if response should be blocked due to sensitive content
        if content_filter.should_block_response(findings):
            logger.warning(f"Blocking response due to sensitive content detected for user {user_id}")
            say(text="I'm sorry, but I cannot provide this information as it may contain sensitive data. Please contact your administrator for assistance.")
            return
        
        # Log if any content was filtered
        if findings:
            logger.info(f"Content filtered for user {user_id}: {content_filter.get_filter_summary(findings)}")
            formatted_response = filtered_response
        
        # Remove typing indicator
        try:
            client.reactions_remove(
                channel=channel_id,
                timestamp=thread_ts,
                name="thinking_face"
            )
        except Exception as e:
            logger.warning(f"Could not remove reaction: {str(e)}. This is non-critical.")
        
        # Send the response
        send_long_message(say, formatted_response, thread_ts=thread_ts)
    
    except Exception as e:
        logger.error(f"Error processing question: {str(e)}")
        say(text="Sorry, I encountered an error while processing your question. Please try again later.")
    
    finally:
        # Remove the thread from active tracking
        manage_active_thread(channel_id, thread_ts, user_id, "remove", active_threads, active_threads_lock, config.THREAD_TIMEOUT)

@app.message("help")
def help_message(message, say):
    """Provide help information in any channel or DM."""
    help_text = """
*AI Assistant Help*

I'm your secure AI assistant powered by the DIG platform. I can help answer questions and assist with various tasks!

*Commands:*
- Send me a DM with your question.
- In channels, mention me with your question (e.g., `@AIBot How do I...?`).
- Admins can send `refresh` (though I'm always up to date!).
- `help` - Show this help message.

*Tips for Good Questions:*
- Be specific and clear in your questions
- Break complex questions into smaller parts
- If you don't get a good answer, try rephrasing your question

*My Capabilities:*
- Answer general questions
- Provide explanations and assistance
- Help with problem-solving
- Available 24/7 with real-time responses
    """
    say(text=help_text)

@app.event("message")
def handle_dm_messages(body, say, client):
    """Process direct messages (DMs) sent to the bot."""
    logger.info("=== DM MESSAGE EVENT RECEIVED ===")
    logger.debug(f"Full event body: {body}")
    
    event = body.get("event", {})
    
    # Only process DMs
    if event.get("channel_type") != "im":
        logger.debug(f"Ignoring non-DM message: channel_type={event.get('channel_type')}")
        return
    
    logger.info(f"DM Event details: channel={event.get('channel')}, user={event.get('user')}, ts={event.get('ts')}")
    logger.debug(f"DM Event text: {event.get('text', '')}")
    
    # Skip if we've processed this message recently
    if not should_process_message(event, processed_messages):
        logger.info("Skipping DM message - already processed recently")
        return
        
    channel_id = event.get("channel")
    user_id = event.get("user")
    thread_ts = event.get("thread_ts", event.get("ts"))
    question = event.get("text", "").strip()
    
    # Ignore messages from bots (including ourselves)
    logger.debug(f"Bot check: bot_id={event.get('bot_id')}, user_id={user_id}")
    if event.get("bot_id") or user_id == "USLACKBOT":
        logger.info("Ignoring message from bot")
        return
    
    logger.debug(f"Question received: '{question}'")
    if not question:
        logger.warning("Empty question in DM")
        return
    
    # Check user access before processing
    logger.debug("Checking user access for DM...")
    has_access, access_error = check_user_access(client, user_id)
    if not has_access:
        logger.warning(f"Access denied for user {user_id} in DM")
        say(text=access_error)
        return
    logger.debug("User access check passed for DM")
    
    logger.info(f"Processing DM question from user {user_id}: {question}")
    
    try:
        logger.debug("Starting DM processing...")
        
        # Check for admin commands
        logger.debug(f"Checking if '{question.lower()}' is an admin command in DM")
        if question.lower() == "refresh":
            logger.info("Refresh command detected in DM")
            if not admin_manager.require_admin(user_id):
                logger.warning(f"Non-admin user {user_id} tried to use refresh command in DM")
                say(text="Sorry, only authorized administrators can perform this action.")
                return
            
            logger.info("Responding to admin refresh command in DM")
            say(text="DIG AI connection is always live - no refresh needed! 🎉")
            return
        
        elif question.lower() == "status":
            logger.info("Status command detected in DM")
            if not admin_manager.require_admin(user_id):
                logger.warning(f"Non-admin user {user_id} tried to use status command in DM")
                say(text="Sorry, only authorized administrators can view system status.")
                return
            
            status_message = f"""
*System Status*
• Bot Status: Running
• DIG AI: {'Connected' if dig_connector else 'Disconnected'}
• Admin Users: {admin_manager.get_admin_count()}
• Email Whitelist: {'Enabled' if email_whitelist.is_enabled() else 'Disabled'}
            """.strip()
            
            say(text=status_message)
            return
        
        if question.lower() == "help":
            logger.info("Help command detected in DM")
            help_message(event, say)
            return
        
        # Check if this thread is already being processed
        logger.debug("Checking if DM thread is already being processed...")
        if not manage_active_thread(channel_id, thread_ts, user_id, "add", active_threads, active_threads_lock, config.THREAD_TIMEOUT):
            logger.info(f"DM thread {thread_ts} is already being processed")
            say(text="I'm already processing a request in this thread. Please wait until it's complete before asking another question.")
            return
        logger.debug("DM thread management check passed")
        # Show typing indicator
        try:
            client.reactions_add(
                channel=channel_id,
                timestamp=thread_ts,
                name="thinking_face"
            )
        except Exception as e:
            logger.warning(f"Could not add reaction: {str(e)}. This is non-critical.")
        
        # Check if DIG AI is available
        if not dig_connector:
            say(text="I'm having trouble connecting to the AI service. Please try again later.")
            return
        
        # Log the query
        logger.info(f"Processing DM question from <@{user_id}>: {question}")
        
        # Generate response using DIG AI
        try:
            logger.info("Sending DM request to DIG AI...")
            # For now, we'll use DIG AI without context since there's no knowledge base
            response = dig_connector.generate_response(question, [])
            logger.info("Received DM response from DIG AI")
            logger.debug(f"DIG AI DM response: {response}")
            
            # Format the response professionally for Slack
            formatted_response = format_response_for_slack(question, response)
            logger.debug(f"Formatted DM response: {formatted_response}")
        except Exception as e:
            logger.error(f"Error generating DM response: {str(e)}", exc_info=True)
            say(text="I encountered an error while processing your question. Please try again later.")
            return
        
        # Remove typing indicator
        try:
            client.reactions_remove(
                channel=channel_id,
                timestamp=thread_ts,
                name="thinking_face"
            )
        except Exception as e:
            logger.warning(f"Could not remove reaction: {str(e)}. This is non-critical.")
        
        # Send the response
        send_long_message(say, formatted_response, thread_ts=thread_ts)
    
    except Exception as e:
        logger.error(f"Error processing DM question: {str(e)}", exc_info=True)
        say(text="Sorry, I encountered an error while processing your question. Please try again later.")
    
    finally:
        # Remove the thread from active tracking
        logger.debug("Cleaning up DM thread tracking...")
        manage_active_thread(channel_id, thread_ts, user_id, "remove", active_threads, active_threads_lock, config.THREAD_TIMEOUT)

@app.event("app_home_opened")
def update_home_tab(client, event, logger):
    """Update the app home tab when a user opens it"""
    user_id = event["user"]
    
    try:
        # Publish view to Home tab
        client.views_publish(
            user_id=user_id,
            view={
                "type": "home",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "AI Assistant",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Welcome to your AI Assistant powered by the DIG platform! I'm here to help answer questions and assist with various tasks."
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*How to use me:*"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "• Send me a direct message with your question\n• Mention me in a channel with your question\n• Ask me anything - I'm powered by advanced AI"
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "🤖 Powered by DIG AI Platform - Always ready to help!"
                            }
                        ]
                    }
                ]
            }
        )
    except Exception as e:
        logger.error(f"Error publishing home tab: {str(e)}")

# Add a signal handler for graceful shutdown
def signal_handler(sig, frame):
    """Handle termination signals"""
    logger.info("Received shutdown signal, cleaning up...")
    logger.info("Cleanup complete, exiting")
    sys.exit(0)

# Initialize the app and start it using Socket Mode
if __name__ == "__main__":
    print("\n=== Starting AI Assistant Bot ===")
    print(f"Current working directory: {os.getcwd()}")
    print(f"Python version: {sys.version}")
    
    # Check for required environment variables
    required_vars = ["SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"]
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        print(f"ERROR: Missing required environment variables: {', '.join(missing_vars)}")
        sys.exit(1)
    
    api_key = os.environ.get("DIGAI_API_KEY")
    print(f"DIGAI_API_KEY: {'Set' if api_key else 'Not set'}")
    print(f"DIG AI model ID: {config.DIG_MODEL_ID}")
    
    if not api_key:
        print("WARNING: DIGAI_API_KEY is required for DIG AI integration")
    
    # Print email whitelist status
    print(f"Email whitelist enabled: {email_whitelist.is_enabled()}")
    if email_whitelist.is_enabled():
        print(f"Whitelisted emails count: {email_whitelist.get_whitelist_count()}")
        print("NOTE: Bot requires 'users:read' and 'users:read.email' scopes to access user emails")
    else:
        print("Email whitelist disabled - all workspace users allowed")
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("Starting Slack bot...")
    logger.info("Starting AI Assistant Bot...")
    logger.info("Registering event handlers...")
    logger.debug("Event handlers registered: app_mention, message, app_home_opened")
    
    print("Connecting to Slack via Socket Mode...")
    logger.info("Connecting to Slack via Socket Mode...")
    
    try:
        handler = SocketModeHandler(app, config.SLACK_APP_TOKEN)
        logger.info("Socket Mode handler created successfully")
        print("✅ Bot is now running and listening for events!")
        logger.info("✅ Bot is now running and listening for events!")
        handler.start()
    except Exception as e:
        logger.error(f"Failed to start bot: {str(e)}", exc_info=True)
        print(f"❌ Failed to start bot: {str(e)}")
        raise
