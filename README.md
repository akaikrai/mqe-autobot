# AutoBot

A Slack bot that uses embeddings and natural language processing to answer questions based on your Confluence knowledge base. The bot maintains a local cache of Confluence content for quick and private answers.

## Features

- **Confluence Integration**: Securely access your Confluence knowledge base
- **Local Processing**: Processes content locally with vector embeddings for quick search
- **Smart Chunking**: Breaks documents into semantic chunks for precise retrieval
- **Slack Interface**: Ask questions directly in Slack channels or DMs
- **Automatic Updates**: Refreshes knowledge base on a configurable schedule
- **Google Vertex AI Integration**: Optional integration for advanced responses using Gemini models
- **Intelligent Formatting**: Properly formats responses for optimal readability in Slack
- **Modular Architecture**: Code is organized into separate modules for easier maintenance
- **Enterprise Security**: Comprehensive security features including request validation, rate limiting, and content filtering

## System Architecture

The application is structured into modular components:

- **main.py**: Entry point that handles Slack interactions and orchestrates the workflow
- **config.py**: Centralizes configuration management from environment variables
- **confluence_client.py**: Manages communication with the Confluence API
- **knowledge_base.py**: Handles document chunking, embedding, and search
- **cache_manager.py**: Provides caching services for the knowledge base
- **response_generator.py**: Creates well-formatted responses from retrieved chunks
- **vertex_ai_connector.py**: Handles integration with Google Vertex AI
- **utils.py**: Contains utility functions used throughout the application

### Security Components

- **security/slack_validator.py**: Validates that requests are actually from Slack using signature verification
- **security/rate_limiter.py**: Implements rate limiting and budget monitoring to prevent abuse
- **security/content_filter.py**: Filters sensitive information from responses
- **auth/admin_manager.py**: Manages admin user permissions and access control

## Prerequisites

- Python 3.9+
- Slack bot with Socket Mode enabled
- Confluence API access token
- Slack signing secret for request validation
- (Optional) Google Cloud project with Vertex AI API enabled

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/cbsi-cbscom/autobot.git
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

4. Copy the example environment file and update it with your credentials:
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

## Configuration

Configure the bot by editing the `.env` file. Key settings include:

- **Slack Credentials**: Bot and App tokens for your Slack workspace
- **Security Settings**: Signing secret for request validation, admin users, and rate limiting
- **Confluence Settings**: URL, username, API token, and space keys
- **Caching Options**: Control caching behavior and refresh intervals
- **Chunking Parameters**: Adjust how documents are split for optimal retrieval
- **Vertex AI Integration**: Configure optional AI-powered responses

### Important Configuration Options

```
# Confluence space configuration - separate multiple spaces with commas
CONFLUENCE_SPACE_KEY=SPACE1,SPACE2,SPACE3

# Maximum pages to fetch per space (handling pagination properly)
MAX_PAGES_PER_SPACE=500

# Security settings
SLACK_SIGNING_SECRET=your-slack-signing-secret
ADMIN_USERS=U1234567890,U0987654321
RATE_LIMIT_PER_USER=10
RATE_LIMIT_PER_CHANNEL=50
MAX_DAILY_REQUESTS=1000
MAX_DAILY_COST=100.0

# Vertex AI model selection
VERTEX_MODEL=gemini-1.5-pro
```

## Usage

1. Start the bot:
   ```bash
   python main.py
   ```

2. Interact with the bot in your Slack workspace:
   - **Direct Messages**: Send a question directly to the bot
   - **Channel Mentions**: Mention the bot in channels with your question
   - **Admin Commands**: Administrators can use `refresh` to update the knowledge base or `status` to view system statistics

## Advanced Usage

### Customizing Response Generation

You can modify the response generation approach in `response_generator.py` to change how answers are created from document chunks.

### Changing Embedding Models

Update the `EMBEDDING_MODEL` environment variable to use a different SentenceTransformer model for embeddings.

### Vertex AI Integration

To enable the Vertex AI integration for enhanced responses:

1. Set up a Google Cloud project and enable the Vertex AI API
2. Create a service account with appropriate permissions
3. Set the following environment variables:
   ```
   USE_VERTEX_AI=true
   GCP_PROJECT_ID=your-project-id
   GCP_LOCATION=us-central1
   VERTEX_MODEL=gemini-1.5-pro
   ```

4. Ensure the appropriate Google Cloud authentication is set up:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/your/service-account-key.json
   ```

## Security Features

AutoBot includes comprehensive security features to protect your data and prevent abuse:

### Request Validation
- **Slack Signature Verification**: All incoming requests are validated using Slack's signing secret to ensure they originate from Slack
- **Timestamp Validation**: Requests are rejected if they're older than 5 minutes to prevent replay attacks

### Rate Limiting & Budget Protection
- **User Rate Limiting**: Configurable limits per user (default: 10 requests per 15 minutes)
- **Channel Rate Limiting**: Configurable limits per channel (default: 50 requests per 15 minutes)
- **Daily Limits**: Maximum daily requests and cost limits to prevent budget overruns
- **Budget Monitoring**: Real-time tracking of usage costs with automatic shutdown when limits are reached

### Access Control
- **Admin Management**: Configurable list of admin users with privileged access
- **Admin Commands**: Special commands like `refresh` and `status` require admin privileges
- **User Permissions**: Granular control over who can perform administrative actions

### Content Filtering
- **Sensitive Data Detection**: Automatic detection of passwords, API keys, emails, and other sensitive information
- **Response Filtering**: Sensitive content is automatically redacted or blocked
- **Custom Patterns**: Support for custom sensitive data patterns specific to your organization

## Maintenance

- **Cache Management**: The bot automatically refreshes its knowledge base based on the `REFRESH_INTERVAL_HOURS` setting
- **Logging**: Check `confluence_bot.log` for detailed activity and error logs
- **Troubleshooting**: For issues with the knowledge base, administrators can use the `refresh` command
- **Security Monitoring**: Monitor logs for security events and rate limiting violations

## Project Structure

```
confluence-knowledge-bot/
├── main.py                  # Main application entry point
├── config.py                # Configuration management
├── confluence_client.py     # Handles API communication with Confluence
├── knowledge_base.py        # Manages document processing and search
├── cache_manager.py         # Handles caching of knowledge base data
├── response_generator.py    # Formats responses for Slack
├── vertex_ai_connector.py   # Handles AI integration
├── utils.py                 # Utility functions
├── security/                # Security components
│   ├── __init__.py
│   ├── slack_validator.py   # Slack request signature validation
│   ├── rate_limiter.py      # Rate limiting and budget monitoring
│   └── content_filter.py    # Sensitive data filtering
├── auth/                    # Authentication components
│   ├── __init__.py
│   └── admin_manager.py     # Admin user management
├── tests/                   # Test suite
│   ├── __init__.py
│   └── test_security.py     # Security feature tests
├── requirements.txt         # Project dependencies
└── .env                     # Environment variables (from .env.example)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgements

This project uses several open-source libraries, including:
- Slack Bolt for Slack API interactions
- Sentence Transformers for document embeddings
- NLTK for text processing
- Atlassian Python API for Confluence integration
- LangChain for Vertex AI integration
