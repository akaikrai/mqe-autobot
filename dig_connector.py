import logging
import os
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from datetime import datetime, UTC
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

BASE = "https://ai.digdev.cbsicloud.com"

class DIGConnector:
    """Connector for DIG AI platform integration"""
    
    def __init__(self, api_key, model_id=42):
        """Initialize the DIG connector"""
        self.api_key = api_key
        self.model_id = model_id
        self.session = self._make_session()
        self.chat_id = None
        
        # Initialize a session chat
        self._initialize_session_chat()
    
    def _make_session(self):
        """Create a robust HTTP session with retry policy"""
        s = requests.Session()
        retry = Retry(
            total=5,
            connect=5,
            read=5,
            backoff_factor=0.6,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        return s
    
    def _headers(self):
        """Return headers with API key"""
        return {"Content-Type": "application/json", "X-API-Key": self.api_key}
    
    def _initialize_session_chat(self):
        """Initialize a session chat for this connector instance"""
        logger.info("Starting DIG chat session initialization...")
        try:
            chat_name = f"Slack Bot Session {datetime.now(UTC).isoformat()}"
            logger.debug(f"Creating chat with name: {chat_name}")
            self.chat_id = self._create_chat(chat_name, self.model_id)
            logger.info(f"Successfully initialized DIG chat session with ID: {self.chat_id}")
        except Exception as e:
            logger.error(f"Failed to initialize DIG chat session: {str(e)}", exc_info=True)
            self.chat_id = None
    
    def _create_chat(self, chat_name, model_id):
        """Create a new chat and return its ID"""
        url = f"{BASE}/fastapi/chats"
        payload = {"chat_nm": chat_name, "model_id": model_id}
        logger.debug(f"Creating chat - URL: {url}, Payload: {payload}")
        
        r = self.session.post(url, headers=self._headers(), json=payload, timeout=30)
        logger.debug(f"Create chat response: status={r.status_code}")
        
        if not (200 <= r.status_code < 300):
            error_msg = f"Create chat failed: HTTP {r.status_code} {r.text[:400]}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        # Try common response shapes
        try:
            data = r.json()
        except Exception:
            data = {}

        if isinstance(data, dict):
            if isinstance(data.get("id"), int):
                return data["id"]
            if isinstance(data.get("chat_id"), int):
                return data["chat_id"]
            chat = data.get("chat")
            if isinstance(chat, dict) and isinstance(chat.get("id"), int):
                return chat["id"]

        # Location header fallback
        loc = r.headers.get("Location") or r.headers.get("location")
        if loc:
            parts = loc.rstrip("/").split("/")
            if parts and parts[-1].isdigit():
                return int(parts[-1])

        # As a last resort, try listing and matching by name
        rl = self.session.get(f"{BASE}/fastapi/chats", headers=self._headers(), timeout=30)
        if 200 <= rl.status_code < 300:
            try:
                lst = rl.json()
                if isinstance(lst, list):
                    for item in reversed(lst):
                        if isinstance(item, dict) and item.get("chat_nm") == chat_name and isinstance(item.get("id"), int):
                            return item["id"]
            except Exception:
                pass

        raise RuntimeError("Could not determine new chat id from create response.")
    
    def _send_message(self, text):
        """Send a message to the current chat session"""
        if not self.chat_id:
            logger.error("No active chat session available")
            raise RuntimeError("No active chat session. Cannot send message.")
        
        url = f"{BASE}/fastapi/chats/{self.chat_id}/generate"
        payload = {
            "model_id": self.model_id,
            "message_text": text,
            "history": [{"role": "user", "content": text}],
        }
        logger.info(f"Sending message to DIG API - URL: {url}")
        logger.debug(f"Message payload: {payload}")
        
        r = self.session.post(url, headers=self._headers(), json=payload, timeout=60)
        logger.debug(f"DIG API response: status={r.status_code}")
        r.raise_for_status()
        
        response_data = r.json()
        logger.debug(f"DIG API response data: {response_data}")
        return response_data
    
    def generate_response(self, query, relevant_chunks):
        """Generate a response using DIG AI platform"""
        logger.info(f"Generating response for query: '{query}' with {len(relevant_chunks)} chunks")
        
        # Format the context
        context = self._format_context(relevant_chunks)
        logger.debug(f"Formatted context length: {len(context) if context else 0}")
        
        if not context:
            logger.info("No context available, using direct query")
            # If no context, send the query directly
            prompt = query
        else:
            logger.debug("Creating prompt with context")
            # Create the prompt with context
            prompt = self._create_prompt(query, context)
        
        try:
            logger.info("Sending prompt to DIG platform...")
            # Send message to DIG platform
            response = self._send_message(prompt)
            
            logger.info("Extracting response content...")
            # Extract the response content
            result = self._extract_response_content(response)
            logger.info(f"Successfully generated response (length: {len(result)})")
            return result
            
        except Exception as e:
            logger.error(f"Error generating DIG AI response: {str(e)}", exc_info=True)
            return self._generate_fallback_response(query, relevant_chunks)
    
    def _format_context(self, relevant_chunks):
        """Format chunks into a context string for the prompt"""
        if not relevant_chunks:
            return ""
        
        # Sort chunks by score
        sorted_chunks = sorted(relevant_chunks, key=lambda x: x.get('score', 0), reverse=True)
        
        # Format chunks
        formatted_chunks = []
        for i, chunk in enumerate(sorted_chunks):
            metadata = chunk.get('metadata', {})
            title = metadata.get('title', 'Unknown document')
            content = chunk.get('chunk', '').strip()
            
            formatted_chunk = f"Document {i+1}: {title}\n{content}\n"
            formatted_chunks.append(formatted_chunk)
        
        return "\n\n".join(formatted_chunks)
    
    def _create_prompt(self, question, context):
        """Create a prompt with context for the DIG platform"""
        prompt = f"""You are a precise information assistant that delivers well-formatted, structured answers based on Confluence documentation.

Context information:
--------------------------
{context}
--------------------------

Question: {question}

Instructions:
1. Answer the specific question asked using ONLY information from the context
2. Present a SINGLE, coherent response that flows naturally
3. Maintain proper formatting for all lists, steps, and instructions:
   - Ensure numbered lists have proper spacing and indentation
   - Preserve paragraph breaks and section headings
   - Format code snippets, commands, and technical details properly
4. If a procedure has steps, ensure they are clearly numbered and complete
5. If multiple procedures exist (e.g., for different platforms), separate them with clear headings
6. Use consistent terminology throughout your response
7. Prefer information from a single document when possible for coherence
8. If the answer isn't in the context, say "I don't have specific information on this topic."
9. Never reference document names or sources within your answer text

Your response should be a polished, properly formatted answer that could appear in an official guide."""
        
        return prompt
    
    def _extract_response_content(self, response):
        """Extract the response content from DIG API response, focusing on message_text"""
        try:
            # The response format may vary, so we need to handle different structures
            if isinstance(response, dict):
                # First, try to find message_text specifically (user's requirement)
                message_text = response.get('message_text')
                if message_text:
                    logger.debug("Found message_text in response")
                    return message_text.strip()
                
                # Check if response is a list of messages, extract message_text from the last one
                if isinstance(response, list) and response:
                    for item in reversed(response):  # Start from the last item
                        if isinstance(item, dict) and 'message_text' in item:
                            logger.debug("Found message_text in list item")
                            return item['message_text'].strip()
                
                # Check nested structures for message_text
                if 'data' in response and isinstance(response['data'], dict):
                    data_message_text = response['data'].get('message_text')
                    if data_message_text:
                        logger.debug("Found message_text in nested data")
                        return data_message_text.strip()
                
                # Fallback to other common response fields if message_text not found
                content = response.get('content') or response.get('message') or response.get('text') or response.get('response')
                
                if content:
                    logger.debug("Using fallback content field")
                    return content.strip()
                
                # If still not found, convert the whole response to string
                logger.warning(f"No message_text found in DIG response structure: {response}")
                return str(response)
            
            elif isinstance(response, str):
                return response.strip()
            
            else:
                logger.warning(f"Unexpected DIG response type: {type(response)}")
                return str(response)
                
        except Exception as e:
            logger.error(f"Error extracting DIG response content: {str(e)}")
            return "I encountered an error processing the response from the AI service."
    
    def _generate_fallback_response(self, query, relevant_chunks):
        """Generate a fallback response when the API call fails"""
        if not relevant_chunks:
            return "I couldn't find relevant information to answer your question."
        
        # Use highest scoring chunk
        top_chunk = max(relevant_chunks, key=lambda x: x.get('score', 0))
        content = top_chunk.get('chunk', '')
        
        return f"Based on the available information:\n\n{content}\n\n(Note: This is a fallback response due to an issue with the AI processing.)"

def setup_dig_ai(config):
    """Set up DIG AI integration"""
    
    # Get API key from environment
    api_key = os.environ.get("DIGAI_API_KEY")
    if not api_key:
        logger.error("DIGAI_API_KEY is required for DIG AI integration")
        return None
        
    try:
        # Get model ID from config
        model_id = config.DIG_MODEL_ID
        
        logger.info(f"Initializing DIG AI with model ID: {model_id}")
        connector = DIGConnector(api_key=api_key, model_id=model_id)
        return connector
    except Exception as e:
        logger.error(f"Error initializing DIG AI: {str(e)}")
        return None