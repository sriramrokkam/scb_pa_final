from dotenv import load_dotenv
from gen_ai_hub.proxy.native.amazon.clients import Session
from botocore.exceptions import ClientError
from pathlib import Path
import logging
from logger_setup import get_logger
from env_config import MODEL_ID, IMAGE_EXTENSIONS
import tenacity
from typing import List, Dict
import re
import os
from destination_srv import get_destination_service_credentials, generate_token, fetch_destination_details, \
    extract_aicore_credentials
import requests
import json
import time
from api_client import fetch_bank_details_from_odata

# Configure logging
# logging.basicConfig(level=logging.INFO,
#                    format='%(asctime)s - %(levelname)s - %(message)s')
# logger = logging.getLogger(__name__)
logger=get_logger()

# Initialize AIC Credentials
logger.info("====>image_processor.py -> AIC CREDENTIALS <====")

load_dotenv()

vcap_services=os.environ.get("VCAP_SERVICES")
destination_service_credentials=get_destination_service_credentials(vcap_services)

try:
    oauth_token=generate_token(
        uri = destination_service_credentials['dest_auth_url'] + "/oauth/token",
        client_id = destination_service_credentials['clientid'],
        client_secret = destination_service_credentials['clientsecret']
    )
except requests.exceptions.HTTPError as e:
    if e.response is not None and e.response.status_code == 500:
        raise Exception("HTTP 500: Check if the client secret is correct.") from e
    else:
        raise

AIC_CREDENTIALS=None
dest_AIC="EARNINGS_AIC"
aicore_details=fetch_destination_details(
    destination_service_credentials['dest_base_url'],
    dest_AIC,
    oauth_token
)
AIC_CREDENTIALS=extract_aicore_credentials(aicore_details)

from gen_ai_hub.proxy import GenAIHubProxyClient
logger.info(f"AIC Credentials: {json.dumps(AIC_CREDENTIALS)}")

proxy_client=GenAIHubProxyClient(
            base_url = AIC_CREDENTIALS['aic_base_url'],
            auth_url = AIC_CREDENTIALS['aic_auth_url'],
            client_id = AIC_CREDENTIALS['clientid'],
            client_secret = AIC_CREDENTIALS['clientsecret'],
            resource_group = AIC_CREDENTIALS['resource_group']
)


def get_bedrock_client_with_proxy(model_id: str, creds: dict):
    proxy_client = GenAIHubProxyClient(
        base_url = creds['aic_base_url'],
        auth_url = creds['aic_auth_url'],
        client_id = creds['clientid'],
        client_secret = creds['clientsecret'],
        resource_group = creds['resource_group']
    )

    session = Session()
    return session.client(model_name=model_id, proxy_client=proxy_client)

@tenacity.retry(
    stop=tenacity.stop_after_attempt(3),
    wait=tenacity.wait_exponential(multiplier=1, min=4, max=10),
    retry=tenacity.retry_if_exception_type(ClientError),
    before_sleep=lambda retry_state: logger.info(
        f"Retrying Bedrock API call (attempt {retry_state.attempt_number})..."
    )
)
def generate_image_conversation(bedrock_client, model_id: str, input_text: str, input_image: Path) -> str:
    """
    Sends a message with text and image to a Bedrock model and returns the text response.
    
    Args:
        bedrock_client: The Boto3 Bedrock runtime client.
        model_id: The model ID to use.
        input_text: The text prompt accompanying the image.
        input_image: The path to the input image.
    
    Returns:
        str: The text response from the model.
    
    Raises:
        ValueError: If the image format is unsupported.
        FileNotFoundError: If the image file cannot be read.
        Exception: For other unexpected errors during API call.
    """
    try:
        # Validate image extension
        image_ext = input_image.suffix.lstrip(".").lower()
        
        if image_ext not in IMAGE_EXTENSIONS:
            logger.error(f"Unsupported image format: {image_ext}")
            raise ValueError(f"Unsupported image format: {image_ext}. Supported formats: {IMAGE_EXTENSIONS}")

        # Read image as bytes
        with input_image.open("rb") as f:
            image = f.read()

        message = {
            "role": "user",
            "content": [
                {"text": input_text},
                {
                    "image": {
                        "format": image_ext,
                        "source": {"bytes": image}
                    }
                }
            ]
        }

        # Send the message to Bedrock
        response = bedrock_client.converse(
            modelId=model_id,
            messages=[message]
        )
        
        # Extract text from response
        output_message = response['output']['message']
        result_text = ""
        for content in output_message['content']:
            if 'text' in content:
                result_text += content['text'] + "\n"
        
        logger.info(f"Successfully processed image: {input_image}")
        return result_text.strip()

    except FileNotFoundError:
        logger.error(f"Image file not found: {input_image}")
        raise
    except ValueError as ve:
        logger.error(f"Invalid image: {str(ve)}")
        raise
    except Exception as e:
        logger.error(f"Error processing image {input_image}: {str(e)}")
        raise

def process_images(folder_path: str, user_prompt: str = "") -> List[Dict[str, str]]:
    """
    Loads images from a folder, filters them based on bank code and quarter from user prompt,
    processes each with the LLM using combined default and user prompts,
    prints the response, and returns the responses.
    
    Args:
        folder_path: Path to the folder containing images.
        user_prompt: User-provided prompt containing bank name and quarter details, combined with the default prompt.
    
    Returns:
        List[Dict[str, str]]: A list of dictionaries, each containing the image path and its analysis.
    """
    # Define default prompt
    default_prompt = """
    Summarize the details with meaningful insights in a concise paragraph format:
    Include Stock Price movement in Percentage with closing stock price and timestamp.
    Stock Insights by identifying meaningful Key phases along with timestamp.
    Concisely explain these key phases with all indicators (price, volume, On Balance Volume, Money Flow Index) and numbers
    """
    
    
    # Combine prompts
    combined_prompt = default_prompt
    if user_prompt.strip():
        combined_prompt += "\n" + user_prompt.strip()

    # Validate folder
    folder = Path(folder_path)
    if not folder.exists():
        logger.error(f"Folder does not exist: {folder_path}")
        return []
    if not folder.is_dir():
        logger.error(f"Path is not a directory: {folder_path}")
        return []

    logger.info(f"Scanning for images in: {folder_path}")
    logger.info(f"Absolute path: {folder_path}")

    # Get all image files in the directory
    # image_files_in_dir = []
    # for ext in IMAGE_EXTENSIONS:
    #     files = list(folder.glob(f"*.{ext.lower()}"))
    #     files += list(folder.glob(f"*.{ext.upper()}"))
    #     image_files_in_dir.extend(files)
    
    # if not image_files_in_dir:
    #     logger.warning(f"No image files found in the directory with supported extensions: {IMAGE_EXTENSIONS}")
    #     return []
    # Try 3 times to get image files in case of async write delays
    image_files_in_dir = []
    for attempt in range(3):
        image_files_in_dir = []
        for ext in IMAGE_EXTENSIONS:
            files = list(folder.glob(f"*.{ext}"))
            files += list(folder.glob(f"*.{ext.upper()}"))  # Match uppercase too
            image_files_in_dir.extend(files)
        
        if image_files_in_dir:
            logger.info(f"Found {len(image_files_in_dir)} images on attempt {attempt+1}")
            break

        logger.info(f"No images found yet on attempt {attempt+1}, retrying...")
        time.sleep(1)  # Wait a second before retry

    if not image_files_in_dir:
        logger.warning(f"No image files found in the directory with supported extensions: {IMAGE_EXTENSIONS}")
        return []

    # Extract bank name and quarter from user_prompt
    bank_code = None
    quarter = None
    # known_banks = get_known_banks()  # Load bank code-name dictionary
    known_banks = fetch_bank_details_from_odata()
    # logger.info(f"Bank List: {known_banks}")


    # Try structured prompt format with fix for both "Ban:" and "Bank:"
    bank_match = re.search(r'[Bb]an[k]?:\s*([^\n,]+)', user_prompt)
    
    # Look for both "Period:" and "Quarter:" in the prompt
    period_match = re.search(r'(?:[Pp]eriod|[Qq]uarter):\s*([^\n,]+)', user_prompt)

    if bank_match:
        bank_name = bank_match.group(1).strip()
        
        # Try exact match first
        for code, name in known_banks.items():
            if bank_name.lower() == name.lower():
                bank_code = code
                break
                
        # If no exact match, try code match
        if not bank_code:
            for code, name in known_banks.items():
                if bank_name.lower() == code.lower():
                    bank_code = code
                    break
                    
        # If still no match, try contains match
        if not bank_code:
            for code, name in known_banks.items():
                if bank_name.lower() in name.lower() or name.lower() in bank_name.lower():
                    bank_code = code
                    break

    if period_match:
        period = period_match.group(1).strip()
        
        # More flexible quarter format handling
        quarter_match = re.search(r'(?:q)?([1-4])[- ]?q[- ]?(?:20)?([0-9]{2})|([1-4])q(?:\')?([0-9]{2})', 
                                 period, re.IGNORECASE)
        
        if quarter_match:
            if quarter_match.group(1) and quarter_match.group(2):  # e.g., "Q1 2025" or "Q1-25"
                quarter = f"{quarter_match.group(1)}Q{quarter_match.group(2)}"
            elif quarter_match.group(3) and quarter_match.group(4):  # e.g., "1Q25" or "1Q'25"
                quarter = f"{quarter_match.group(3)}Q{quarter_match.group(4)}"
        else:
            # Try to directly extract numbers
            numbers = re.findall(r'\d+', period)
            if len(numbers) >= 2:
                # Assume first number is quarter, second is year
                quarter_num = numbers[0][-1]  # Get last digit if multiple digits
                year = numbers[1][-2:] if len(numbers[1]) > 2 else numbers[1]  # Get last 2 digits if longer
                quarter = f"{quarter_num}Q{year}"
            elif len(numbers) == 1 and 'q' in period.lower():
                # Try to handle formats like 'Q1'
                q_match = re.search(r'q([1-4])', period.lower())
                if q_match:
                    quarter_num = q_match.group(1)
                    # Default to current year if only quarter is specified
                    import datetime
                    current_year = str(datetime.datetime.now().year)[-2:]
                    quarter = f"{quarter_num}Q{current_year}"

    # Fallback to free-form prompt if structured format not found
    if not bank_code or not quarter:
        prompt_lower = user_prompt.lower()
        
        # # Find bank name
        # if not bank_code:
        #     for code, name in known_banks.items():
        #         if name.lower() in prompt_lower:
        #             bank_code = code
        #             break
        #         elif code.lower() in prompt_lower:
        #             bank_code = code
        #             break
        if not bank_code:
            for code, name in known_banks.items():
                # Check full word match for bank name
                if re.search(rf'\b{re.escape(name.lower())}\b', prompt_lower):
                    bank_code = code
                    break
                # Check full word match for bank code
                elif re.search(rf'\b{re.escape(code.lower())}\b', prompt_lower):
                    bank_code = code
                    break
        
        # Find quarter
        if not quarter:
            # More comprehensive pattern for various quarter formats
            quarter_patterns = [
                r'(?:q)?([1-4])[- ]?q[- ]?(?:20)?([0-9]{2})',  # Q1 2025, Q1-25, 1Q 25
                r'([1-4])q(?:\')?([0-9]{2})',                  # 1Q25, 1Q'25
                r'q([1-4])[\s\-\/](?:20)?([0-9]{2})',          # Q1/25, Q1-2025
                r'(?:20)?([0-9]{2})[\s\-\/]q([1-4])'           # 25-Q1, 2025/Q1
            ]
            
            for pattern in quarter_patterns:
                quarter_match = re.search(pattern, prompt_lower)
                if quarter_match:
                    if quarter_match.group(1) and quarter_match.group(2):
                        # Check if first group is year or quarter
                        if len(quarter_match.group(1)) >= 2:  # Likely a year
                            quarter = f"{quarter_match.group(2)}Q{quarter_match.group(1)[-2:]}"
                        else:  # Likely a quarter
                            quarter = f"{quarter_match.group(1)}Q{quarter_match.group(2)}"
                        break
            
            # If still not found, try to find any numbers and 'q' in the prompt
            if not quarter:
                q_positions = [m.start() for m in re.finditer(r'q', prompt_lower)]
                
                for pos in q_positions:
                    # Look for digits before and after 'q'
                    before = prompt_lower[max(0, pos-5):pos]
                    after = prompt_lower[pos+1:min(len(prompt_lower), pos+6)]
                    
                    # Try to extract quarter number and year
                    before_digits = re.findall(r'\d+', before)
                    after_digits = re.findall(r'\d+', after)
                    
                    if after_digits and len(after_digits[0]) <= 2 and int(after_digits[0]) <= 4:
                        # Format like "Q1"
                        quarter_num = after_digits[0]
                        # Default to current year
                        import datetime
                        current_year = str(datetime.datetime.now().year)[-2:]
                        quarter = f"{quarter_num}Q{current_year}"
                        break
                    elif before_digits and len(before_digits[-1]) <= 2 and int(before_digits[-1]) <= 4:
                        # Format like "1Q"
                        quarter_num = before_digits[-1]
                        # Look for year after
                        year = after_digits[0][-2:] if after_digits else str(datetime.datetime.now().year)[-2:]
                        quarter = f"{quarter_num}Q{year}"
                        break

    # Try to extract quarter directly from the prompt as a last resort
    if not quarter:
        # Look for "1Q25" or similar patterns directly in the prompt
        direct_quarter_match = re.search(r'([1-4])Q[\'"]?(\d{2})', user_prompt, re.IGNORECASE)
        if direct_quarter_match:
            quarter = f"{direct_quarter_match.group(1)}Q{direct_quarter_match.group(2)}"
        else:
            # Look for Q1 followed by 2025 or 25
            q_year_match = re.search(r'Q([1-4])[^0-9]*(?:20)?(\d{2})', user_prompt, re.IGNORECASE)
            if q_year_match:
                quarter = f"{q_year_match.group(1)}Q{q_year_match.group(2)}"
            else:
                # Check for a number 1-4 followed by digit(s) that could be a year
                num_year_match = re.search(r'[^0-9]([1-4])[^0-9]*(\d{2,4})', user_prompt)
                if num_year_match:
                    year = num_year_match.group(2)[-2:]  # Get last 2 digits of year
                    quarter = f"{num_year_match.group(1)}Q{year}"
                else:
                    # If user prompt contains both "Q1" and "2025" separately
                    q_match = re.search(r'Q([1-4])', user_prompt, re.IGNORECASE)
                    year_match = re.search(r'(?:20)?(\d{2})', user_prompt)
                    if q_match and year_match:
                        quarter = f"{q_match.group(1)}Q{year_match.group(1)[-2:]}"
                    else:
                        # Absolute fallback: if we have a bank but no quarter, use simple heuristics
                        for i in range(1, 5):
                            if f"q{i}" in user_prompt.lower() or f"q {i}" in user_prompt.lower():
                                import datetime
                                current_year = str(datetime.datetime.now().year)[-2:]
                                quarter = f"{i}Q{current_year}"
                                break
    logger.info(
        f"[Bank Extraction] Identified bank_code: '{bank_code}', quarter: '{quarter}' from user prompt: '{user_prompt}'")

    if not bank_code:
        logger.warning(f"Could not identify bank in prompt: {user_prompt}")
        return []
        
    if not quarter:
        logger.warning(f"Could not identify quarter in prompt: {user_prompt}")
        return []

    # Use a set to store unique image paths and avoid duplicates
    image_files_set = set()
    
    # Approach 1: Try different quarter variants
    quarter_variants = [
        quarter,                             # 1Q25
        quarter.replace('Q', 'Q\''),         # 1Q'25
        quarter[0] + 'Q' + quarter[2:],      # 1Q25 (if input was Q125)
        'Q' + quarter                        # Q1Q25 (unlikely but checking)
    ]

    for q_variant in quarter_variants:
        patterns = [f"{bank_code}_{q_variant}_*", f"{bank_code}_{q_variant}*"]
        for pattern in patterns:
            for ext in IMAGE_EXTENSIONS:
                glob_pattern = f"{pattern}.{ext}"
                matched_files = list(folder.glob(glob_pattern))
                # Add to set instead of list to avoid duplicates
                image_files_set.update(matched_files)

    # Approach 2: If no matches, try with just the bank code
    if not image_files_set:
        patterns = [f"{bank_code}_*"]
        for pattern in patterns:
            for ext in IMAGE_EXTENSIONS:
                glob_pattern = f"{pattern}.{ext}"
                matched_files = list(folder.glob(glob_pattern))
                image_files_set.update(matched_files)
                    
    # Approach 3: Try a more flexible approach for quarter matching
    if not image_files_set:
        # Extract just the quarter number and year
        quarter_num = quarter[0]  # Get first character (the quarter number)
        year = quarter[-2:]       # Get last two characters (the year)
        
        patterns = [
            f"{bank_code}_{quarter_num}*{year}_*",  # Match any format with quarter number and year
            f"{bank_code}*{quarter_num}*{year}*"    # Even more flexible pattern
        ]
        
        for pattern in patterns:
            for ext in IMAGE_EXTENSIONS:
                glob_pattern = f"{pattern}.{ext}"
                matched_files = list(folder.glob(glob_pattern))
                image_files_set.update(matched_files)
                
    # Approach 4: As a last resort, try manual comparison
    if not image_files_set and image_files_in_dir:
        for img_file in image_files_in_dir:
            file_name = img_file.name.lower()
            
            # Check if filename contains both bank code and quarter details
            if bank_code.lower() in file_name:
                # Check for quarter number and year
                quarter_num = quarter[0]
                year = quarter[-2:]
                if quarter_num in file_name and year in file_name:
                    image_files_set.add(img_file)

    # # Final fallback - if we have bank code and no matches, just use any image with that bank code
    # if not image_files_set and bank_code:
    #     for img_file in image_files_in_dir:
    #         file_name = img_file.name.lower()
    #         if bank_code.lower() in file_name.lower():
    #             image_files_set.add(img_file)

    # # Convert set back to list for processing
    # image_files = list(image_files_set)

    # if not image_files:
    #     logger.warning(f"No images found matching bank code {bank_code} and quarter {quarter} in {folder_path}")
    #     return []
    if not image_files_set and bank_code:
        logger.warning(
            f"[Fallback Triggered] No exact image match found for bank '{bank_code}' and quarter '{quarter}'. Attempting fallback match...")

        bank_code_lower=bank_code.lower()
        quarter_num=quarter[0]
        year=quarter[-2:]

        for img_file in image_files_in_dir:
            file_name=img_file.name.lower()

            # Match the bank code as a whole word (e.g., 'SCB', not 'INGSCB')
            bank_code_match=re.search(rf'\b{re.escape(bank_code_lower)}\b', file_name)
            has_quarter = re.search(rf'\b{re.escape(quarter.lower())}\b', file_name)

            # Also check if both quarter number and year are present
            # has_quarter=quarter_num in file_name and year in file_name

            if bank_code_match and has_quarter:
                logger.info(
                    f"[Fallback Match] Using fallback image: '{img_file.name}' for bank: '{bank_code}', quarter: '{quarter}'")
                image_files_set.add(img_file)

        if not image_files_set:
            logger.error(f"[Fallback Failed] No fallback images found for bank '{bank_code}' and quarter '{quarter}'")
            return []

    # Process each filtered image and collect responses
    try:
        # bedrock_client = Session().client(model_name=MODEL_ID)
        bedrock_client = get_bedrock_client_with_proxy(MODEL_ID, AIC_CREDENTIALS)
    except Exception as e:
        logger.error(f"Failed to create Bedrock client: {str(e)}")
        return []
        
    results = []
    image_files = list(image_files_set)

    for image_path in image_files:
        try:
            response = generate_image_conversation(bedrock_client, MODEL_ID, combined_prompt, image_path)
            logger.info(f"Successfully analyzed image: {image_path.name}")
            results.append({
                "image_path": str(image_path),
                "analysis": response
            })
        except Exception as e:
            logger.error(f"Failed to process {image_path}: {str(e)}")

    return results