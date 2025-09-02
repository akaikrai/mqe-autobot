# AutoBot

A Slack bot that integrates with the DIG AI platform to provide intelligent, context-aware responses to user questions. The bot maintains conversation context and provides well-formatted responses with proper source attribution.

## Features

- **DIG AI Integration**: Connects to the DIG AI platform for intelligent question answering
- **Slack Interface**: Handles direct messages and channel mentions with professional formatting
- **Source Management**: Automatically extracts, deduplicates, and formats source links
- **Response Formatting**: Cleans and formats AI responses for optimal Slack readability
- **Security Features**: Comprehensive security including request validation and content filtering
- **Admin Controls**: Admin-only commands for system management
- **Thread Management**: Prevents duplicate processing and manages active conversations
- **Message Deduplication**: Prevents the bot from processing the same message multiple times

## System Architecture

The application is structured into modular components:

- **main.py**: Entry point that handles Slack interactions and orchestrates the workflow
- **config.py**: Centralizes configuration management from environment variables
- **dig_connector.py**: Manages communication with the DIG AI platform
- **utils.py**: Contains utility functions for message processing and thread management
- **auth/**: Authentication and authorization components
- **security/**: Security and content filtering components

### Core Components

- **main.py**: Main application that handles Slack events, processes messages, and formats responses
- **config.py**: Configuration management using environment variables
- **dig_connector.py**: DIG AI platform integration for generating responses
- **utils.py**: Message deduplication, thread management, and utility functions

### Security Components

- **security/slack_validator.py**: Validates Slack requests (simplified for Socket Mode)
- **security/content_filter.py**: Filters sensitive information from responses
- **auth/admin_manager.py**: Manages admin user permissions and access control
- **auth/email_whitelist.py**: Email domain whitelisting for user access
- **auth/slack_user_info.py**: Retrieves Slack user information

## Prerequisites

- Python 3.9+
- Slack bot with Socket Mode enabled
- DIG AI platform access with API key
- Slack app with appropriate scopes:
  - `app_mentions:read`
  - `chat:write`
  - `im:history`
  - `im:read`
  - `im:write`
  - `users:read`
  - `reactions:write`
  - `users:read.email`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/viacomcbs/mqe-autobot
   cd autobot
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables in a `.env` file:
   ```bash
   # Copy and edit the environment file
   cp .env.example .env
   # Edit .env with your settings
   ```

## Configuration

Configure the bot by setting environment variables. Key settings include:

### Required Environment Variables

```bash
# Slack Configuration
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_APP_TOKEN=xapp-your-app-token
SLACK_SIGNING_SECRET=your-slack-signing-secret

# DIG AI Configuration
DIGAI_API_KEY=your-dig-ai-api-key

# Admin Configuration
ADMIN_USERS=U1234567890,U0987654321
WHITELISTED_EMAILS=user@company.com
```

### Optional Configuration

```bash
# DIG AI Model ID (default: 42)
DIGAI_MODEL_ID=42

# Logging Level
LOG_LEVEL=INFO
```

## Usage

1. Start the bot:
   ```bash
   python main.py
   ```

2. Interact with the bot in your Slack workspace:
   - **Direct Messages**: Send a question directly to the bot
   - **Channel Mentions**: Mention the bot in channels with your question
   - **Admin Commands**: Administrators can use special commands for system management

## Response Processing

The bot automatically processes and formats responses:

### Source Link Management
- Extracts source URLs from AI responses
- Removes inline source citations from the main text
- Deduplicates and normalizes URLs
- Presents clean, numbered source lists at the bottom

### Text Formatting
- Converts markdown to Slack formatting
- Improves numbered list formatting
- Cleans up excessive whitespace and newlines
- Handles escaped characters properly

### Security Features
- Filters sensitive information from responses
- Validates Slack requests
- Implements admin-only access controls
- Whitelists specific email domains

## Security Features

AutoBot includes comprehensive security features:

### Request Validation
- **Slack Signature Verification**: Validates that requests originate from Slack
- **Socket Mode Security**: Leverages Slack's built-in authentication for Socket Mode

### Access Control
- **Admin Management**: Configurable list of admin users with privileged access
- **Email Whitelisting**: Restricts access to specific email domains
- **User Permissions**: Granular control over administrative actions

### Content Filtering
- **Sensitive Data Detection**: Automatic detection and filtering of sensitive information
- **Response Sanitization**: Ensures no sensitive data leaks in responses

## Project Structure

```
autobotRepoPersonalGitStake/
├── main.py                  # Main application entry point
├── config.py                # Configuration management
├── dig_connector.py         # DIG AI platform integration
├── utils.py                 # Utility functions and message processing
├── requirements.txt         # Project dependencies
├── README.md               # This documentation
├── .gitignore              # Git ignore rules
├── auth/                   # Authentication components
│   ├── __init__.py
│   ├── admin_manager.py     # Admin user management
│   ├── email_whitelist.py  # Email domain whitelisting
│   └── slack_user_info.py  # Slack user information retrieval
└── security/               # Security components
    ├── __init__.py
    ├── slack_validator.py  # Slack request validation
    └── content_filter.py   # Sensitive data filtering
```

## Dependencies

Key Python packages used:

- **slack-bolt**: Slack bot framework with Socket Mode support
- **python-dotenv**: Environment variable management
- **requests**: HTTP client for API communication
- **urllib3**: HTTP client library
- **nltk**: Natural language processing
- **slack-sdk**: Slack API client
- **cryptography**: Cryptographic utilities

## Troubleshooting

### Common Issues

1. **Bot not responding**: Check that all environment variables are set correctly
2. **Permission errors**: Verify the bot has the required Slack scopes
3. **DIG AI connection issues**: Check your API key and network connectivity
4. **Formatting problems**: The bot automatically handles most formatting issues

### Logs

Check the console output for detailed logging information. The bot provides comprehensive logging for debugging.
