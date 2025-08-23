import hashlib
import time
import logging
from datetime import datetime, timedelta
from nltk.tokenize import sent_tokenize

logger = logging.getLogger(__name__)

def count_tokens(text, tokenizer=None):
    """Count the number of tokens in a text using tiktoken"""
    if tokenizer:
        return len(tokenizer.encode(text))
    else:
        # Rough estimation if tokenizer not provided (approx 1 token per 4 chars)
        return len(text) // 4

def should_process_message(event, processed_messages, cache_ttl=60):
    """
    Check if a message should be processed by creating a unique hash and
    checking if we've seen it recently.
    """
    # Create a unique message signature
    message_text = event.get("text", "")
    channel = event.get("channel", "")
    ts = event.get("ts", "")
    
    logger.debug(f"Checking message processing: channel={channel}, ts={ts}, text='{message_text[:50]}...'")
    
    # Create a unique hash for this message
    message_hash = hashlib.md5(f"{channel}:{ts}:{message_text}".encode()).hexdigest()
    logger.debug(f"Message hash: {message_hash}")
    
    current_time = datetime.now()
    
    # Clean up old entries from cache
    expired_keys = []
    for key, (timestamp, _) in processed_messages.items():
        if current_time - timestamp > timedelta(seconds=cache_ttl):
            expired_keys.append(key)
    
    if expired_keys:
        logger.debug(f"Cleaning up {len(expired_keys)} expired message entries")
    for key in expired_keys:
        del processed_messages[key]
    
    # Check if we've processed this message recently
    if message_hash in processed_messages:
        logger.info(f"Skipping duplicate message (hash: {message_hash}): {message_text[:30]}...")
        return False
    
    # Add to cache
    processed_messages[message_hash] = (current_time, message_text)
    logger.debug(f"Added message to processing cache (total entries: {len(processed_messages)})")
    return True

def manage_active_thread(channel_id, thread_ts, user_id, action="add", active_threads=None, 
                         active_threads_lock=None, thread_timeout=300):
    """
    Add, check, or remove a thread from the active threads tracking.
    Returns True if the thread can be processed, False if it's already being processed.
    """
    if active_threads is None or active_threads_lock is None:
        logger.debug("No thread tracking configured, allowing all threads")
        return True  # If no tracking, always allow
        
    thread_key = f"{channel_id}:{thread_ts}"
    logger.debug(f"Managing thread: {thread_key}, action: {action}, user: {user_id}")
    
    with active_threads_lock:
        current_time = time.time()
        
        # Clean up any expired threads
        expired_keys = []
        for key, (start_time, _) in active_threads.items():
            if current_time - start_time > thread_timeout:
                expired_keys.append(key)
        
        if expired_keys:
            logger.info(f"Cleaning up {len(expired_keys)} expired threads")        
        for key in expired_keys:
            logger.debug(f"Removing expired thread: {key}")
            del active_threads[key]
        
        if action == "check":
            result = thread_key in active_threads
            logger.debug(f"Thread check result for {thread_key}: {result}")
            return result
            
        elif action == "add":
            if thread_key in active_threads:
                logger.info(f"Thread {thread_key} is already being processed")
                return False
            active_threads[thread_key] = (current_time, user_id)
            logger.info(f"Added thread {thread_key} to active tracking (total: {len(active_threads)})")
            return True
            
        elif action == "remove":
            if thread_key in active_threads:
                del active_threads[thread_key]
                logger.info(f"Removed thread {thread_key} from active tracking (remaining: {len(active_threads)})")
            return True
    
    return False

def send_long_message(say, text, thread_ts=None, blocks=None):
    """
    Send messages that may exceed Slack's character limit by splitting intelligently.
    Uses blocks when available for better formatting.
    """
    max_chars = 3000  # Setting a bit lower than the 4000 limit to be safe
    
    # If message is short enough, send it directly
    if len(text) <= max_chars:
        say(text=text, thread_ts=thread_ts, blocks=blocks)
        return
    
    # If we have blocks, we need a different approach
    if blocks:
        # First send just the text portion in chunks
        send_long_message(say, text, thread_ts)
        
        # Then send blocks in separate messages if needed
        for i in range(0, len(blocks), 50):  # Slack has a limit of 50 blocks per message
            block_subset = blocks[i:i+50]
            say(text="", thread_ts=thread_ts, blocks=block_subset)
        return
        
    # Split on sentence boundaries for more natural breaks
    sentences = sent_tokenize(text)
    
    chunks = []
    current_chunk = ""
    
    for sentence in sentences:
        if len(current_chunk) + len(sentence) + 1 > max_chars:
            # Current chunk would be too large, store it and start a new one
            chunks.append(current_chunk)
            current_chunk = sentence
        else:
            # Add to current chunk with a space if not empty
            if current_chunk:
                current_chunk += " " + sentence
            else:
                current_chunk = sentence
    
    # Don't forget the last chunk
    if current_chunk:
        chunks.append(current_chunk)
    
    # Send each chunk in order
    for i, chunk in enumerate(chunks):
        # Add continuation indicator for multi-part messages
        if len(chunks) > 1:
            if i == 0:
                chunk += "\n\n_(message continued in thread...)_"
            else:
                chunk = f"_(part {i+1}/{len(chunks)})_\n\n" + chunk
        
        say(text=chunk, thread_ts=thread_ts)
