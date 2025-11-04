from dotenv import load_dotenv
import logging
import tiktoken
from gen_ai_hub.proxy.native.amazon.clients import Session

# Load environment variables (if needed)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def count_tokens(text: str) -> int:
    """
    Count the number of tokens in a text string using tiktoken.
    """
    try:
        encoder = tiktoken.get_encoding("cl100k_base")
        tokens = encoder.encode(text)
        return len(tokens)
    except Exception as e:
        logger.info(f"Token counting failed: {str(e)}")
        return 0

def print_token_summary(result: dict) -> None:
    """
    Print a formatted summary of token usage.
    """
    print("\n" + "="*50)
    print("TOKEN USAGE SUMMARY")
    print("="*50)
    print(f"Input Tokens:  {result.get('input_tokens', 0):,}")
    print(f"Output Tokens: {result.get('output_tokens', 0):,}")
    print(f"Total Tokens:  {result.get('total_tokens', 0):,}")
    print("="*50 + "\n")