import json
import os
import datetime
import typing
from db_connection import get_db_connection, release_db_connection
from logger_setup import get_logger
from destination_srv import get_destination_service_credentials, generate_token, fetch_destination_details,extract_hana_credentials
from env_config import DUBLIN_CORE_METADATA, SCHEMA_NAME


# Configure logger
logger = get_logger()


# Initialize HANA Credentials
logger.info("====> DANS_Upload.py -> GET HANA CREDENTIALS <====")
vcap_services = os.environ.get("VCAP_SERVICES")
destination_service_credentials = get_destination_service_credentials(vcap_services)
logger.info(f"Destination Service Credentials: {destination_service_credentials}")

try:
    oauth_token = generate_token(
        uri=destination_service_credentials['dest_auth_url'] + "/oauth/token",
        client_id=destination_service_credentials['clientid'],
        client_secret=destination_service_credentials['clientsecret']
    )
    logger.info("OAuth token generated successfully for destination service.")
except Exception as e:
    logger.error(f"Error generating OAuth token: {str(e)}")
    raise

HANA_CREDENTIALS = None
dest_HDB = "EARNINGS_HDB"
hana_dest_details = fetch_destination_details(
    destination_service_credentials['dest_base_url'],
    dest_HDB,
    oauth_token
)
HANA_CREDENTIALS = extract_hana_credentials(hana_dest_details)
logger.info(f"HANA Credentials: {HANA_CREDENTIALS}")

class DublinCoreMetadataStorage:
    """
    Handles storage of Dublin Core JSON metadata in HANA database.
    """
    SCHEMA_NAME = SCHEMA_NAME
    TABLE_NAME = DUBLIN_CORE_METADATA

    @classmethod
    def store_dublin_core_metadata(cls, json_data: dict, original_filename: str, 
                                 processing_decision: str = None, reasoning: str = None, 
                                 is_scb_document: bool = None, classification_keywords: str = None,
                                 primary_classification: str = None) -> None:
        """
        Store Dublin Core JSON metadata in HANA table with fields matching the provided JSON structure.
        
        Args:
            json_data (dict): The JSON metadata from Dublin Core extractor
            original_filename (str): The original filename associated with the metadata
            processing_decision (str, optional): Final processing decision (APPROVED/NEEDS_APPROVAL/REJECTED)
            reasoning (str, optional): Reasoning for the processing decision
            is_scb_document (bool, optional): Specifying if the file belongs to SCB or not
            classification_keywords (str, optional): Classification keywords (DC_CLASSIFICATION)
            primary_classification (str, optional): Primary classification (DC_PRIMARY_CLASSIFICATION)
            
        Raises:
            ValueError: If required fields are missing or invalid
            Exception: For database-related errors
        """
        conn = None
        cursor = None
        
        try:
            # Validate input
            if not json_data:
                logger.error("No JSON data provided for storage")
                raise ValueError("JSON data cannot be empty")
                
            if not original_filename:
                logger.error("Original filename not provided")
                raise ValueError("Original filename cannot be empty")

            # Extract key fields from JSON
            document_id = json_data.get('document_id', '')
            if not document_id:
                logger.error("Document ID not found in JSON data")
                raise ValueError("Document ID is required")

            dublin_core = json_data.get('dublin_core', {})
            title = dublin_core.get('title', 'Untitled')
            creator = ', '.join(dublin_core.get('creator', ['Unknown'])) if dublin_core.get('creator') else 'Unknown'
            subject = ', '.join(dublin_core.get('subject', [])) if dublin_core.get('subject') else ''
            description = dublin_core.get('description', '')
            publisher = dublin_core.get('publisher', '')
            contributor = ', '.join(dublin_core.get('contributor', [])) if dublin_core.get('contributor') else ''
            date = dublin_core.get('date', datetime.datetime.now().isoformat() + 'Z')
            dc_type = dublin_core.get('type', 'Unknown')
            file_format = dublin_core.get('format', 'Unknown')
            language = dublin_core.get('language', 'en-US')
            rights = dublin_core.get('rights', '')
            
            file_info = json_data.get('file_info', {})
            file_size = file_info.get('file_size', 0)
            file_path = file_info.get('file_path', '')
            mime_type = file_info.get('mime_type', '')
            file_hash = file_info.get('file_hash', {})
            md5_hash = file_hash.get('md5', '')
            sha256_hash = file_hash.get('sha256', '')
            
            copyright_info = json_data.get('copyright_info', {})
            copyright_status = copyright_info.get('copyright_status', 'Unknown')
            copyright_year = copyright_info.get('copyright_year', None)
            copyright_holder = copyright_info.get('copyright_holder', None)
            
            license_info = json_data.get('license_info', {})
            license_type = license_info.get('license_type', 'All Rights Reserved')
            
            # Access control information
            access_control = json_data.get('access_control', {})
            access_level = access_control.get('access_level', 'Public')
            
            # Extraction metadata
            extraction_metadata = json_data.get('extraction_metadata', {})
            extraction_method = extraction_metadata.get('extraction_method', '')
            extraction_date = extraction_metadata.get('extraction_date', '')
            extraction_tool = extraction_metadata.get('extraction_tool', '')
            confidence_scores = json.dumps(extraction_metadata.get('confidence_scores', {}), ensure_ascii=False)
            
            # Audit trail
            audit_trail = json.dumps(json_data.get('audit_trail', []), ensure_ascii=False)
            
            # Extract classification fields from JSON if not provided as parameters
            if classification_keywords is None:
                classification_keywords = json_data.get('classification_keywords', '')
            if primary_classification is None:
                primary_classification = json_data.get('primary_classification', '')
            
            # Convert JSON to string for storage
            json_content = json.dumps(json_data, ensure_ascii=False)
            
            # Get file extension
            file_extension = os.path.splitext(original_filename)[1].lower()
            
            # Get database connection
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check if record already exists
            check_query = f"""
            SELECT "DOCUMENT_ID" FROM "{cls.SCHEMA_NAME}"."{cls.TABLE_NAME}"
            WHERE UPPER("ORIGINAL_FILENAME") = UPPER(?)
            """
            cursor.execute(check_query, (original_filename,))
            result = cursor.fetchone()
            
            conn.setautocommit(False)
            
            if result:
                existing_document_id = result[0]
                logger.info(f"Found existing record for {original_filename} with document_id {existing_document_id}, updating")
                update_query = f"""
                UPDATE "{cls.SCHEMA_NAME}"."{cls.TABLE_NAME}"
                SET "FILE_EXTENSION" = ?, "UPLOAD_TIMESTAMP" = ?, "METADATA_JSON" = ?,
                    "TITLE" = ?, "CREATOR" = ?, "SUBJECT" = ?, "DESCRIPTION" = ?,
                    "PUBLISHER" = ?, "CONTRIBUTOR" = ?, "DOCUMENT_DATE" = ?,
                    "DC_TYPE" = ?, "FILE_FORMAT" = ?, "LANGUAGE" = ?, "RIGHTS" = ?,
                    "FILE_SIZE" = ?, "FILE_PATH" = ?, "MIME_TYPE" = ?,
                    "MD5_HASH" = ?, "SHA256_HASH" = ?, "COPYRIGHT_STATUS" = ?,
                    "COPYRIGHT_YEAR" = ?, "COPYRIGHT_HOLDER" = ?, "LICENSE_TYPE" = ?,
                    "ACCESS_LEVEL" = ?, "EXTRACTION_METHOD" = ?, "EXTRACTION_DATE" = ?,
                    "EXTRACTION_TOOL" = ?, "CONFIDENCE_SCORES" = ?, "AUDIT_TRAIL" = ?,
                    "PROCESSING_DECISION" = ?, "REASONING" = ?, "SCB_DOCUMENT" = ?,
                    "DC_CLASSIFICATION" = ?, "DC_PRIMARY_CLASSIFICATION" = ?
                WHERE "DOCUMENT_ID" = ? AND UPPER("ORIGINAL_FILENAME") = UPPER(?)
                """
                update_record = (
                    file_extension,
                    datetime.datetime.now(),
                    json_content,
                    title,
                    creator,
                    subject,
                    description,
                    publisher,
                    contributor,
                    date,
                    dc_type,
                    file_format,
                    language,
                    rights,
                    file_size,
                    file_path,
                    mime_type,
                    md5_hash,
                    sha256_hash,
                    copyright_status,
                    copyright_year,
                    copyright_holder,
                    license_type,
                    access_level,
                    extraction_method,
                    extraction_date,
                    extraction_tool,
                    confidence_scores,
                    audit_trail,
                    processing_decision,
                    reasoning,
                    is_scb_document,
                    classification_keywords,
                    primary_classification,
                    existing_document_id,
                    original_filename
                )
                cursor.execute(update_query, update_record)
                logger.info(f"Successfully updated Dublin Core metadata for {original_filename} with document_id {existing_document_id}")
                print(f"✔ Updated Dublin Core metadata for {original_filename} with document_id {existing_document_id}")
            else:
                logger.info(f"No existing record for {original_filename}, inserting with document_id {document_id}")
                insert_query = f"""
                INSERT INTO "{cls.SCHEMA_NAME}"."{cls.TABLE_NAME}" (
                    "DOCUMENT_ID", "ORIGINAL_FILENAME", "FILE_EXTENSION", 
                    "UPLOAD_TIMESTAMP", "METADATA_JSON", "TITLE", "CREATOR",
                    "SUBJECT", "DESCRIPTION", "PUBLISHER", "CONTRIBUTOR",
                    "DOCUMENT_DATE", "DC_TYPE", "FILE_FORMAT", "LANGUAGE", "RIGHTS",
                    "FILE_SIZE", "FILE_PATH", "MIME_TYPE", "MD5_HASH", "SHA256_HASH", 
                    "COPYRIGHT_STATUS", "COPYRIGHT_YEAR", "COPYRIGHT_HOLDER", "LICENSE_TYPE",
                    "ACCESS_LEVEL", "EXTRACTION_METHOD", "EXTRACTION_DATE", "EXTRACTION_TOOL",
                    "CONFIDENCE_SCORES", "AUDIT_TRAIL", "PROCESSING_DECISION", "REASONING", 
                    "SCB_DOCUMENT", "DC_CLASSIFICATION", "DC_PRIMARY_CLASSIFICATION"
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                insert_record = (
                    document_id,
                    original_filename,
                    file_extension,
                    datetime.datetime.now(),
                    json_content,
                    title,
                    creator,
                    subject,
                    description,
                    publisher,
                    contributor,
                    date,
                    dc_type,
                    file_format,
                    language,
                    rights,
                    file_size,
                    file_path,
                    mime_type,
                    md5_hash,
                    sha256_hash,
                    copyright_status,
                    copyright_year,
                    copyright_holder,
                    license_type,
                    access_level,
                    extraction_method,
                    extraction_date,
                    extraction_tool,
                    confidence_scores,
                    audit_trail,
                    processing_decision,
                    reasoning,
                    is_scb_document,
                    classification_keywords,
                    primary_classification
                )
                cursor.execute(insert_query, insert_record)
                logger.info(f"Successfully inserted Dublin Core metadata for {original_filename} with document_id {document_id}")
                print(f"✔ Inserted Dublin Core metadata for {original_filename} with document_id {document_id}")
            
            conn.commit()
            logger.info(f"Dublin Core metadata stored successfully for {original_filename}")
            print(f"✔ Dublin Core metadata stored successfully for {original_filename}")
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to store Dublin Core metadata for {original_filename}: {str(e)}")
            print(f"✖ Failed to store Dublin Core metadata for {original_filename}: {str(e)}")
            raise
            
        finally:
            if conn:
                conn.setautocommit(True)
            if cursor:
                cursor.close()
            if conn:
                release_db_connection(conn)

    @classmethod
    def update_processing_decision(cls, original_filename: str, processing_decision: str, reasoning: str, 
                                 is_scb_document: bool, classification_keywords: str = None,
                                 primary_classification: str = None) -> None:
        """
        Update only the processing decision, reasoning, and classification fields for an existing record.
        
        Args:
            original_filename (str): The original filename to update
            processing_decision (str): Final processing decision (APPROVED/NEEDS_APPROVAL/REJECTED)
            reasoning (str): Reasoning for the processing decision
            is_scb_document (bool): SCB Document flag
            classification_keywords (str, optional): Classification keywords (DC_CLASSIFICATION)
            primary_classification (str, optional): Primary classification (DC_PRIMARY_CLASSIFICATION)
            
        Raises:
            ValueError: If required fields are missing or invalid
            Exception: For database-related errors
        """
        conn = None
        cursor = None
        
        try:
            # Validate input
            if not original_filename:
                logger.error("Original filename not provided")
                raise ValueError("Original filename cannot be empty")
                
            if not processing_decision:
                logger.error("Processing decision not provided")
                raise ValueError("Processing decision cannot be empty")

            # Get database connection
            conn = get_db_connection()
            cursor = conn.cursor()
            
            conn.setautocommit(False)
            
            # Update processing decision, reasoning, and classification fields
            update_query = f"""
            UPDATE "{cls.SCHEMA_NAME}"."{cls.TABLE_NAME}"
            SET "PROCESSING_DECISION" = ?, "REASONING" = ?, "UPLOAD_TIMESTAMP" = ?, "SCB_DOCUMENT" = ?,
                "DC_CLASSIFICATION" = ?, "DC_PRIMARY_CLASSIFICATION" = ?
            WHERE UPPER("ORIGINAL_FILENAME") = UPPER(?)
            """
            
            cursor.execute(update_query, (processing_decision, reasoning, datetime.datetime.now(), 
                                        is_scb_document, classification_keywords, primary_classification, 
                                         original_filename))
            
            if cursor.rowcount == 0:
                logger.warning(f"No record found for filename: {original_filename}")
                print(f"⚠ No record found for filename: {original_filename}")
            else:
                logger.info(f"Successfully updated processing decision and classification for {original_filename}")
                print(f"✔ Updated processing decision and classification for {original_filename}: {processing_decision}")
            
            conn.commit()
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to update processing decision for {original_filename}: {str(e)}")
            print(f"✖ Failed to update processing decision for {original_filename}: {str(e)}")
            raise
            
        finally:
            if conn:
                conn.setautocommit(True)
            if cursor:
                cursor.close()
            if conn:
                release_db_connection(conn)

def store_dublin_core_metadata(json_data: dict, original_filename: str, 
                             processing_decision: str = None, reasoning: str = None, 
                             is_scb_document: bool = None, classification_keywords: str = None,
                             primary_classification: str = None) -> None:
    """
    Public function to store Dublin Core JSON metadata in HANA table.
    
    Args:
        json_data (dict): The JSON metadata from Dublin Core extractor
        original_filename (str): The original filename associated with the metadata
        processing_decision (str, optional): Final processing decision (APPROVED/NEEDS_APPROVAL/REJECTED)
        reasoning (str, optional): Reasoning for the processing decision
        is_scb_document (bool, optional): SCB Document flag
        classification_keywords (str, optional): Classification keywords (DC_CLASSIFICATION)
        primary_classification (str, optional): Primary classification (DC_PRIMARY_CLASSIFICATION)
    
    Raises:
        ValueError: If required fields are missing or invalid
        Exception: For database-related errors
    """
    DublinCoreMetadataStorage.store_dublin_core_metadata(json_data, original_filename, processing_decision, 
                                                        reasoning, is_scb_document, classification_keywords,
                                                        primary_classification)

def update_processing_decision(original_filename: str, processing_decision: str, reasoning: str, 
                             is_scb_document: bool, classification_keywords: str = None,
                             primary_classification: str = None) -> None:
    """
    Public function to update only the processing decision, reasoning, and classification fields for an existing record.
    
    Args:
        original_filename (str): The original filename to update
        processing_decision (str): Final processing decision (APPROVED/NEEDS_APPROVAL/REJECTED)
        reasoning (str): Reasoning for the processing decision
        is_scb_document (bool): SCB Document flag
        classification_keywords (str, optional): Classification keywords (DC_CLASSIFICATION)
        primary_classification (str, optional): Primary classification (DC_PRIMARY_CLASSIFICATION)
    
    Raises:
        ValueError: If required fields are missing or invalid
        Exception: For database-related errors
    """
    DublinCoreMetadataStorage.update_processing_decision(original_filename, processing_decision, reasoning, 
                                                        is_scb_document, classification_keywords, 
                                                        primary_classification)