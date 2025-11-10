import os
from pickle import NONE
import time
import logging
from logging.handlers import RotatingFileHandler
import uuid
import json
import requests
import traceback
from flask import Flask, request, jsonify, Response, url_for, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
load_dotenv()

from hdbcli import dbapi  # SAP HANA client library
from env_config import DEF_SCHEMA
from db_connection import get_db_connection, load_vector_stores
from query_processor import process_query
from embedding_storer import process_and_store_embeddings
from api_client import download_embedding_files, update_completed_files, get_file_mappings, update_file_status, extract_period, extract_bank_code
from destination_srv import get_destination_service_credentials, generate_token, fetch_destination_details,extract_hana_credentials,extract_aicore_credentials
from xsuaa_srv import get_xsuaa_credentials, verify_jwt_token, require_auth
from fastapi import HTTPException  # Ensure HTTPException is imported for error handling
import shutil
import atexit
import threading
from math import ceil
import pandas as pd
from urllib.parse import urljoin, quote
from datetime import datetime, timezone
from llm_client import enable_excel_prompt_mode, reset_excel_prompt_mode

from content_scanner_orchestrator import SimpleDocumentProcessor, cleanup_processing_files
from Dublin_Core.metadata_fetch import get_metadata_by_filename


# Initialize Flask app
app = Flask(__name__)


# Define improved error handling system
class ErrorCategory:
    """Enum-like class to categorize errors for frontend interpretation"""
    INPUT_VALIDATION = "input_validation"
    SECURITY = "security"
    FILE_NOT_FOUND = "file_not_found"
    FILE_ACCESS = "file_access"
    FILE_FORMAT = "file_format"
    RATE_LIMIT = "rate_limit"
    DATABASE = "database"
    PROCESSING = "processing"
    INTERNAL = "internal"
    METHOD_NOT_ALLOWED = "method_not_allowed"

class AppError(Exception):
    """Enhanced application error with standardized structure"""
    def __init__(self, error_type, message, user_friendly=True, status_code=400, details=None):
        super().__init__(message)
        self.error_type = error_type
        self.user_friendly = user_friendly
        self.status_code = status_code
        self.details = details or {}
    
    def to_dict(self):
        """Convert error to standardized dictionary format"""
        error_dict = {
            "error": True,
            "error_type": self.error_type,
            "message": str(self) if self.user_friendly else "An unexpected error occurred. Please try again later.",
            "status_code": self.status_code
        }
        if self.details and self.user_friendly:
            error_dict["details"] = self.details
        return error_dict

# Set up logger
logger = logging.getLogger('EarningsAnalysis')
logger.setLevel(logging.INFO)

#CORS(app)
logger.info('CORS Disabled')


# Set directories
LOCALPATH = os.getenv('LOCALPATH', os.getcwd())
documents_dir = os.path.join(LOCALPATH, "Documents")
logger.info(f"Document Directory: {documents_dir}")
images_dir = os.path.join(LOCALPATH, "Images")
logger.info(f"Image Library: {images_dir}")
logs_dir = os.path.join(LOCALPATH, "logs")
logger.info(f"Log Directory: {logs_dir}")
chat_document_dir = os.path.join(LOCALPATH, "ChatDocuments")
logger.info(f"Chat Documents Dir: {chat_document_dir}")
# output_dir = os.path.join(LOCALPATH, "outputs")
# logger.info(f"Output folder: {output_dir}")

os.makedirs(documents_dir, exist_ok=True)
os.makedirs(images_dir, exist_ok=True)
os.makedirs(logs_dir, exist_ok=True)
os.makedirs(chat_document_dir, exist_ok=True)
# os.makedirs(output_dir, exist_ok=True)


# Cleanup function to remove file after program exits
def cleanup_directories():
    for dir_path in [documents_dir, logs_dir]:
        if os.path.exists(dir_path):
            try:
                for filename in os.listdir(dir_path):
                    file_path = os.path.join(dir_path, filename)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        logger.info(f"Deleted file: {file_path}")
            except Exception as e:
                logger.error(f"No File to clean up files in {dir_path}: {e}")


# Configure logging with rotation
log_file_path = os.path.join(logs_dir, "earnings_analysis.log")
handler = RotatingFileHandler(log_file_path, maxBytes=50 * 1024 * 1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# ---------------------------- XSUAA Authentication Setup ----------------------------
"""
XSUAA authentication is enforced on protected endpoints using the @require_auth decorator.
- The XSUAA credentials are loaded from VCAP_SERVICES and stored in the Flask app context as 'uaa_xsuaa_credentials'.
- The decorator (from xsuaa_srv.py) checks for a Bearer token in the Authorization header and validates it using the credentials.
- If the token is missing, invalid, or lacks the required scope, a 401/403 error is returned.
- Example usage:
    @app.route('/api/chat', methods=['POST'])
    @require_auth
    def chat():
        ...
"""

vcap_services = os.environ.get("VCAP_SERVICES")

uaa_xsuaa_credentials = get_xsuaa_credentials(vcap_services)
logger.info(f"XSUAA Credentials: {uaa_xsuaa_credentials}")
# Store credentials in Flask app context for decorator access
app.uaa_xsuaa_credentials = uaa_xsuaa_credentials

#----------------------------LOAD CF VCAP_SERVICES Variables -----------------------------
# Log start of credential retrieval
logger.info ("***server.py -> GET HANA AND AIC CREDENTIALS FROM DESTINATION SERVICES***")
# # Load VCAP_SERVICES from environment
# vcap_services = os.environ.get("VCAP_SERVICES")
# Extract destination service credentials
destination_service_credentials = get_destination_service_credentials(vcap_services)
logger.info(f"Destination Service Credentials: {destination_service_credentials}")
# Generate OAuth token for destination service
try:
    oauth_token = generate_token(
        uri=destination_service_credentials['dest_auth_url'] + "/oauth/token",
        client_id=destination_service_credentials['clientid'],
        client_secret=destination_service_credentials['clientsecret']
    )
except requests.exceptions.HTTPError as e:
    # Handle HTTP 500 error for invalid client secret
    if e.response is not None and e.response.status_code == 500:
        raise Exception("HTTP 500: Check if the client secret is correct.") from e
    else:
        raise
#-------------------------------- READ HANA DB Configuration -------------------------------------
# Step 2: Get the destination details by passing name and token
dest_HDB = 'EARNINGS_HDB' # make sure this is the correct destination name at btp account.
hana_dest_details = fetch_destination_details(
    destination_service_credentials['dest_base_url'],
    name=dest_HDB,
    token=oauth_token
)
logger.info(f"HANA Destination Details: {hana_dest_details}")
# Step 2.2: Extract HANA connection details
HANA_CONN = GV_HANA_CREDENTIALS = NONE

def initialize_hana_connection():
    """Initialize HANA DB connection using extracted credentials"""
    global HANA_CONN, GV_HANA_CREDENTIALS

    # set the hana connection details
    GV_HANA_CREDENTIALS = extract_hana_credentials(hana_dest_details)
    logger.info(f" HANA Credentials: {GV_HANA_CREDENTIALS}")

    try:
        HANA_CONN = dbapi.connect(
            address=GV_HANA_CREDENTIALS['address'],
            port=GV_HANA_CREDENTIALS['port'],
            user=GV_HANA_CREDENTIALS['user'],
            password=GV_HANA_CREDENTIALS['password'],
            encrypt=True,
            sslValidateCertificate=False
        )
        
        logger.info("Successfully connected to HANA database")
        return True
    except Exception as e:
        logger.info(f"Error initializing HANA connection: {str(e)}")
        return False

# Initialize the HANA Crdentials to Global Variables
initialize_hana_connection()


def store_metadata_in_hana(filename, file_path, file_type, upload_time):
    """Store file metadata in HANA database"""
    try:
        if not HANA_CONN:
            logger.warning("HANA connection not initialized, skipping metadata storage")
            return False

        cursor = HANA_CONN.cursor()
        cursor.execute(f"SET SCHEMA {DEF_SCHEMA}")
        logger.info("Schema set to {DEF_SCHEMA}")

        query = """
            INSERT INTO "FILE_METADATA" (filename, file_path, file_type, upload_time)
            VALUES (?, ?, ?, ?)
        """
        cursor.execute(query, (filename, file_path, file_type, upload_time))
        HANA_CONN.commit()
        logger.info(f"Stored metadata for {filename} in HANA database")
        cursor.close()
        return True
    except Exception as e:
        logger.info(f"Error storing metadata in HANA: {str(e)}")
        return False

#-------------------------------- READ AIC Configuration -------------------------------------

# # Global variables for AIC credentials
AIC_CREDENTIALS = None

def initialize_aic_credentials():
    """Initialize AIC credentials from VCAP_SERVICES"""
    global GV_AIC_CREDENTIALS#, AIC_BASE_URL, AIC_CLIENTID, AIC_CLIENTSECRET, AIC_AUTH_URL, AIC_RESOURCE_GROUP
    
    try:
        dest_AIC = "EARNINGS_AIC"
        aicore_details = fetch_destination_details(
            destination_service_credentials['dest_base_url'],
            dest_AIC,
            oauth_token
        )
        
        logger.info("AIC Destination Details fetched successfully")
        GV_AIC_CREDENTIALS = extract_aicore_credentials(aicore_details)
        logger.info(f"Global AIC Credentials: {GV_AIC_CREDENTIALS}")
        
        return True
        
    except Exception as e:
        logger.info(f"Error initializing AIC credentials: {str(e)}")
        return False

# Initialize the AIC Credentials
initialize_aic_credentials()

# ### EOC: SRIRAM ROKKAM 23.05.2025###

# Load vector stores
logger.info("Loading vector stores")
transcript_store, non_transcript_store, excel_non_transcript_store = load_vector_stores(AIC_CREDENTIALS=GV_AIC_CREDENTIALS)
if transcript_store is None or non_transcript_store is None:
    logger.info("Failed to load required vector stores (transcript or non-transcript)")
    transcript_store = non_transcript_store = None
if excel_non_transcript_store is None:
    logger.warning("Failed to load excel_non_transcript_store; proceeding without Excel support")
else:
    logger.info("All vector stores loaded successfully")

# Configuration
ALLOWED_EXTENSIONS = {'.pdf', '.txt', '.docx', '.doc', '.xlsx', '.jpg', '.png', '.jpeg'}
IMAGE_EXTENSIONS = {'.jpg', '.png', '.jpeg'}
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
UPLOAD_LIMIT = 30
upload_counts = {}

def allowed_file(filename):
    """Check if a file has an allowed extension"""
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

# Log all incoming requests
@app.before_request
def log_request_info():
    logger.info(f"Incoming request: {request.method} {request.url} from {request.remote_addr}")

# Enhanced error handlers
@app.errorhandler(AppError)
def handle_app_error(error):
    """Global error handler for AppError exceptions"""
    logger.info(f"Handling AppError: [{error.error_type}] {str(error)}")
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response

@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"Route not found: {request.path}")
    return jsonify({
        "error": True,
        "error_type": ErrorCategory.FILE_NOT_FOUND,
        "message": "The requested resource was not found.",
        "status_code": 404
    }), 404

@app.errorhandler(500)
def internal_server_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        "error": True,
        "error_type": ErrorCategory.INTERNAL,
        "message": "An internal server error occurred. Please try again later.",
        "status_code": 500
    }), 500

@app.errorhandler(429)
def rate_limit_error(error):
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return jsonify({
        "error": True,
        "error_type": ErrorCategory.RATE_LIMIT,
        "message": "Rate limit exceeded. Please slow down your requests.",
        "status_code": 429
    }), 429

@app.errorhandler(405)
def method_not_allowed_error(error):
    logger.warning(f"Method not allowed: {request.method} on {request.path}")
    endpoint = app.url_map._rules_by_endpoint.get(request.endpoint, [{}])[0]
    allowed_methods = endpoint.get('methods', [])
    return jsonify({
        "error": True,
        "error_type": ErrorCategory.METHOD_NOT_ALLOWED,
        "message": f"Method {request.method} not allowed for {request.path}.",
        "status_code": 405,
        "details": {"allowed_methods": allowed_methods}
    }), 405

@app.route('/api/health_check', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    logger.info("Health check accessed")
    status_info = {
        "status": "Server is running",
        "aic_credentials_loaded": GV_AIC_CREDENTIALS is not None,
        "hana_connected": HANA_CONN is not None
    }
    return jsonify(status_info), 200

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get detailed status information"""
    status = {
        "server_status": "running",
        "vector_stores": {
            "transcript_store": transcript_store is not None,
            "non_transcript_store": non_transcript_store is not None,
            "excel_non_transcript_store": excel_non_transcript_store is not None
        },
        "aic_configuration": {
            "credentials_loaded": GV_AIC_CREDENTIALS is not None,
            "base_url_configured": GV_AIC_CREDENTIALS['aic_base_url'] is not None,
            "auth_url_configured": GV_AIC_CREDENTIALS['aic_auth_url'] is not None
        },
        "hana_configuration": {
            "connected": HANA_CONN is not None,
            "credentials_loaded": GV_HANA_CREDENTIALS is not None,
           # "schema_configured": GV_HANA_CREDENTIALS['schema'] is not None
        }
    }
    return jsonify(status), 200



@app.route('/api/chat', methods=['POST', 'GET', 'HEAD'])
@require_auth
def chat():
    """Process chat queries and return responses"""
    logger.info("Chat endpoint accessed")
    try:
        data = request.get_json()
        logger.info(f"Received data: {data}")
        if not data or 'message' not in data:
            logger.warning("Missing 'message' in request")
            return jsonify({"error": "Missing 'message' in request body"}), 400

        user_input = data.get('message', '')
        result = process_query(
            user_input,
            transcript_store=transcript_store,
            non_transcript_store=non_transcript_store,
            excel_non_transcript_store=excel_non_transcript_store if excel_non_transcript_store is not None else None
        )
        return jsonify({"result": result}), 200
    except Exception as e:
        logger.info(f"Error in chat endpoint: {str(e)}")
        return jsonify({"error": f"Error processing query: {str(e)}"}), 500

@app.route('/api/metadata-retreival', methods=['POST'])
@require_auth
def get_metadata():
    """API endpoint to retrieve metadata for a given filename."""
    try:
        filename = request.args.get('filename')
        
        if not filename:
            return jsonify({'error': 'Missing required parameter: filename'}), 400
        
        # Use the same function as in upload API
        metadata = get_metadata_by_filename(filename)
        
        if metadata:
            return jsonify({
                'status': 'success',
                'filename': filename,
                'metadata': metadata
            }), 200
        else:
            return jsonify({
                'status': 'success',
                'filename': filename,
                'metadata': None,
                'message': f'No metadata found for {filename}'
            }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving metadata for {filename}: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500
            
@app.route('/api/upload', methods=['POST'])
@require_auth
def upload_file():
    client_ip = request.remote_addr
    logger.info(f"Received upload request from {client_ip}")
    current_time = int(time.time())
    hour_ago = current_time - 3600

    try:
        # Clean up old upload counts
        upload_counts[client_ip] = [t for t in upload_counts.get(client_ip, []) if t > hour_ago]

        # Check upload limit
        if len(upload_counts.get(client_ip, [])) >= UPLOAD_LIMIT:
            logger.warning(f"Upload limit reached for {client_ip}")
            raise AppError(
                ErrorCategory.RATE_LIMIT,
                "Upload limit reached (500 files per hour). Please try again later.",
                status_code=429
            )

        if 'file' not in request.files:
            logger.error("No file part in request")
            raise AppError(
                ErrorCategory.INPUT_VALIDATION,
                "No file provided in the request",
                status_code=400
            )

        file = request.files['file']
        if file.filename == '':
            logger.error("No selected file")
            raise AppError(
                ErrorCategory.INPUT_VALIDATION,
                "No file selected",
                status_code=400
            )

        if not allowed_file(file.filename):
            logger.error(f"Unsupported file type: {file.filename}")
            file_ext = os.path.splitext(file.filename)[1].lower() or "unknown"
            raise AppError(
                ErrorCategory.FILE_FORMAT,
                "Unsupported file type. Only PDF, XLSX, .DOC,  .DOCX, TXT, JPG, PNG, and JPEG are allowed.",
                status_code=400,
                details={"filename": file.filename, "extension": file_ext, "allowed": list(ALLOWED_EXTENSIONS)}
            )

        filename = file.filename
        file_ext = os.path.splitext(filename)[1].lower()
        # Determine the appropriate directory based on file extension
        target_dir = images_dir if file_ext in IMAGE_EXTENSIONS else documents_dir
        file_path = os.path.join(target_dir, filename)

        if os.path.exists(file_path):
            overwrite = request.form.get('overwrite', 'false').lower() == 'true'
            logger.info(f"File {filename} exists in {target_dir}, overwrite={overwrite}")
            if not overwrite:
                return jsonify({
                    "exists": True, 
                    "message": f"File '{filename}' already exists. Overwrite?",
                    "filename": filename
                }), 200
            # If overwrite is true, continue with saving

        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)

        if file_size > MAX_FILE_SIZE:
            logger.error(f"File {filename} too large: {file_size} bytes")
            raise AppError(
                ErrorCategory.INPUT_VALIDATION,
                f"File too large. Maximum size is {MAX_FILE_SIZE//1024//1024}MB.",
                status_code=400,
                details={"filename": filename, "size": file_size, "max_size": MAX_FILE_SIZE}
            )

        file.save(file_path)
        logger.info(f"File {filename} saved to {file_path}")

        # Record upload
        if client_ip not in upload_counts:
            upload_counts[client_ip] = []
        upload_counts[client_ip].append(current_time)

        target_folder_name = 'Images' if file_ext in IMAGE_EXTENSIONS else 'Documents'
        
        # Initialize base message
        base_message = f"File '{filename}' uploaded and scanning through the Document."
        
        # Process document only if it's not an image
        if file_ext not in IMAGE_EXTENSIONS:
            try:
                logger.info(f"Starting document processing for: {filename}")
                
                # Initialize processor
                processor = SimpleDocumentProcessor()
                
                # Process document
                result = processor.process_document(filename, store_in_database=True)
                
                # Cleanup processing files
                cleanup_processing_files(filename)
                
                if result["status"] == "SUCCESS":
                    logger.info(f"✅ Successfully processed: {filename}")
                    logger.info(f"🎯 Decision: {result['final_decision']}")
                    logger.info(f"📁 Output files: {len(result['output_files'])} files")
                    logger.info(f"💾 Database: {'✅ STORED' if result['database_stored'] else '❌ NOT STORED'}")
                    
                    # Enhanced success message with decision
                    decision = result.get('final_decision', 'Unknown')
                    final_message = f"{base_message} and processed. Decision: {decision}.Reasoning: {result['reasoning']}"
                else:
                    logger.error(f"❌ Processing failed: {filename}")
                    for error in result["errors"]:
                        logger.error(f"   • {error}")
                    
                    # File uploaded but processing failed
                    final_message = f"{base_message}, but processing failed"
                
            except ImportError as e:
                logger.error(f"Failed to import document processor: {str(e)}")
                final_message = f"{base_message}, but document processor is not available"
                
            except Exception as e:
                logger.error(f"Error during document processing for {filename}: {str(e)}")
                final_message = f"{base_message}, but processing encountered an error"
        else:
            # Image file - no processing needed
            logger.info(f"Image file detected, returning early for {filename} with ext {file_ext}")
            final_message = base_message
            
            response_data = {
                "success": True,
                "message": final_message,
                "filename": filename,
                "folder": target_folder_name
            }
            # logger.info(f"Image file detected, returning early for {filename} with ext {file_ext}")
            return jsonify(response_data), 200
        
        # For non image files, continue with metadata retrieval as before
        metadata = None
        try:
            logger.info(f"Retrieving metadata for file: {filename}")
            metadata = get_metadata_by_filename(filename)
            if metadata:
                logger.info(f"Successfully retrieved metadata for {filename}")
            else:
                logger.warning(f"No metadata found for {filename}")
        except Exception as e:
            logger.error(f"Error retrieving metadata for {filename}: {str(e)}")
            # Don't fail the upload if metadata retrieval fails
        
        # Prepare response
        response_data = {
            "success": True,
            "message": final_message,
            "filename": filename,
            "folder": target_folder_name
        }
        
        # Add metadata to response if available
        if metadata:
            response_data["metadata"] = metadata
        
        return jsonify(response_data), 200
    
    except AppError:
        # Re-raise AppError to be caught by the global handler
        raise
    except Exception as e:
        logger.error(f"Upload error: {str(e)}\n{traceback.format_exc()}")
        raise AppError(
            ErrorCategory.INTERNAL,
            "An unexpected error occurred during file upload",
            status_code=500
        )

@app.route('/api/approved-file-upload', methods=['POST'])
@require_auth
def approved_upload_file():
    client_ip = request.remote_addr
    logger.info(f"Received upload request from {client_ip}")

    try:
        # Basic file existence check
        if 'file' not in request.files:
            return jsonify({"error": "No file provided in the request"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        filename = file.filename
        file_ext = os.path.splitext(filename)[1].lower()
        
        # Determine the appropriate directory based on file extension
        target_dir = images_dir if file_ext in IMAGE_EXTENSIONS else documents_dir
        file_path = os.path.join(target_dir, filename)

        # Handle file overwrite
        if os.path.exists(file_path):
            overwrite = request.form.get('overwrite', 'false').lower() == 'true'
            logger.info(f"File {filename} exists in {target_dir}, overwrite={overwrite}")
            if not overwrite:
                return jsonify({
                    "exists": True, 
                    "message": f"File '{filename}' already exists. Overwrite?",
                    "filename": filename
                }), 200

        # Save the file
        file.save(file_path)
        logger.info(f"File {filename} saved to {file_path}")

        target_folder_name = 'Images' if file_ext in IMAGE_EXTENSIONS else 'Documents'
        
        # Prepare response
        response_data = {
            "success": True,
            "message": f"File '{filename}' uploaded successfully.",
            "filename": filename,
            "folder": target_folder_name
        }
        
        return jsonify(response_data), 200
    
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({"error": "An unexpected error occurred during file upload"}), 500
    

@app.route('/api/generate-embeddings', methods=['POST'])
@require_auth
def generate_embeddings():
    """Endpoint to generate embeddings for uploaded files."""
    logger.info("Step 1: Starting embedding generation process")
    cleanup_directories() # Cleanup the Directories at the Start and the End

    # Step 1: Download files
    logger.info("Step 2: Downloading files for embedding generation")
    downloaded_files = download_embedding_files(
        documents_dir=documents_dir,
        images_dir=images_dir,
        image_extensions=IMAGE_EXTENSIONS
    )


    logger.info(f"Step 3: Downloaded files: {downloaded_files}")

    # Explicitly check if the list is empty
    if not downloaded_files:
        logger.info("Step 4: No files were downloaded. Exiting process.")
        return jsonify({"error": "No files were downloaded. Please check the source or file status."}), 500

    if not isinstance(downloaded_files, list):
        logger.info("Step 5: Invalid data type for downloaded files. Exiting process.")
        return jsonify({"error": "Failed to download files or invalid data type returned."}), 500

    logger.info(f"Step 6: Downloaded {len(downloaded_files)} files: {downloaded_files}")

    all_successful_files = True  # Track overall success
    successful_files=[]
    failed_files = []  # Track failed files

    # Step 2: Categorize files
    logger.info("Step 7: Categorizing files")
    transcripts = [f for f in downloaded_files if f.endswith(('.txt', '.docx', '.doc'))]
    non_transcripts = [f for f in downloaded_files if f.endswith(('.pdf', '.xlsx'))]
    images = [f for f in downloaded_files if f.endswith(tuple(IMAGE_EXTENSIONS))]

    logger.info(f"Step 8: Categorized files - Transcripts: {len(transcripts)}, Non-Transcripts: {len(non_transcripts)}, Images: {len(images)}")

    # Step 8.1: Skip embedding generation for image files only
    if images:
        logger.info(f"Step 8.1: {len(images)} image file(s) detected. Skipping embedding generation for them.")

        # Get file mappings
        file_mappings = get_file_mappings()

        # Update image files' status to 'Completed'
        for image_path in images:
            short_name = os.path.basename(image_path)
            if short_name in file_mappings:
                file_id = file_mappings[short_name]
                if update_file_status(file_id, "Completed"):
                    logger.info(f"Marked image {short_name} as Completed")
                else:
                    logger.warning(f"Failed to update status for image {short_name}")
            else:
                logger.warning(f"No mapping found for image file: {short_name}")

    # Filter out image files before embedding loop
    files_to_process = [f for f in downloaded_files if f not in images]

    # Step 3: Process and store embeddings for each category
    for file_path in files_to_process:
        try:
            logger.info(f"Step 9: Processing file: {file_path}")
            process_and_store_embeddings(directory_path=os.path.dirname(file_path))
            logger.info(f"Step 10: Successfully processed and stored embeddings for file: {file_path}")
            successful_files.append(file_path)
        except Exception as e:
            logger.info(f"Step 11: Error processing file {file_path}: {e}", exc_info=True)
            # all_successful_files = False  # Mark as failed if any file processing fails
            failed_files.append(file_path)
            continue  # Continue with the next file
    
    # for file_path in downloaded_files:
    #     try:
    #         logger.info(f"Step 9: Processing file: {file_path}")
    #         process_and_store_embeddings(directory_path=os.path.dirname(file_path))
    #         logger.info(f"Step 10: Successfully processed and stored embeddings for file: {file_path}")
    #     except Exception as e:
    #         logger.info(f"Step 11: Error processing file {file_path}: {e}", exc_info=True)
    #         all_successful_files = False  # Mark as failed if any file processing fails
    #         failed_files.append(file_path)
    #         continue  # Continue with the next file

    # Get file mappings (filename -> file_id)
    file_mappings=get_file_mappings()

    # Update successful files to Completed
    for filename in successful_files:
        short_name = os.path.basename(filename)
        if short_name in file_mappings:
            file_id = file_mappings[short_name]
            if update_file_status(file_id, "Completed"):
                logger.info(f"Updated status to Completed for {short_name}")
            else:
                logger.warning(f"Failed to update status to Completed for {short_name}")
        else:
            logger.warning(f"No mapping found for successful file: {short_name}")

    # Update failed files to Failed
    for filename in failed_files:
        short_name=os.path.basename(filename)
        if short_name in file_mappings:
            file_id=file_mappings[short_name]
            if update_file_status(file_id, "Failed"):
                logger.info(f"Updated status to Failed for {short_name}")
            else:
                logger.warning(f"Failed to update status to Failed for {short_name}")
        else:
            logger.warning(f"No mapping found for failed file: {short_name}")

    cleanup_directories()

    if failed_files:
        logger.warning("Some files failed during embedding generation.")
        return jsonify({
            "status": "partial",
            "successful_files": [os.path.basename(f) for f in successful_files],
            "failed_files": [os.path.basename(f) for f in failed_files]
        }), 206

    logger.info("All embeddings generated and statuses updated successfully.")
    return jsonify({"status": "success", "message": "All embeddings generated successfully"}), 200


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    logger.info(f"Starting Flask app on port {port}")
    for rule in app.url_map.iter_rules():
        logger.info(f"Registered rule: {rule}")
    app.run(host='0.0.0.0', port=port, debug=False)