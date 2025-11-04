import json
import datetime
import typing
from db_connection import get_db_connection, release_db_connection
from logger_setup import get_logger
from destination_srv import get_destination_service_credentials, generate_token, fetch_destination_details,extract_hana_credentials
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

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

class DublinCoreMetadataReader:
    """
    Handles reading of Dublin Core metadata from HANA database. EARNINGS_HDB
    """
    SCHEMA_NAME = "EARNINGS_AI"
    TABLE_NAME = "EARNINGS_DUBLIN_CORE_METADATA_UI5"

    @classmethod
    def get_metadata_by_filename(cls, original_filename: str) -> typing.Dict[str, typing.Any]:
        """
        Retrieve Dublin Core metadata for a specific filename from HANA table.
        
        Args:
            original_filename (str): The original filename to search for
            
        Returns:
            Dict[str, Any]: Dictionary containing the metadata record, or None if not found
            
        Raises:
            ValueError: If filename is not provided
            Exception: For database-related errors
        """
        conn = None
        cursor = None
        
        try:
            # Validate input
            if not original_filename:
                logger.error("Original filename not provided")
                raise ValueError("Original filename cannot be empty")

            # Get database connection
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Query to get all metadata for the filename
            query = f"""
            SELECT 
                "DOCUMENT_ID",
                "ORIGINAL_FILENAME",
                "FILE_EXTENSION",
                "UPLOAD_TIMESTAMP",
                "METADATA_JSON",
                "TITLE",
                "CREATOR",
                "SUBJECT",
                "DESCRIPTION",
                "PUBLISHER",
                "CONTRIBUTOR",
                "DOCUMENT_DATE",
                "DC_TYPE",
                "FILE_FORMAT",
                "LANGUAGE",
                "RIGHTS",
                "FILE_SIZE",
                "FILE_PATH",
                "MIME_TYPE",
                "MD5_HASH",
                "SHA256_HASH",
                "COPYRIGHT_STATUS",
                "COPYRIGHT_YEAR",
                "COPYRIGHT_HOLDER",
                "LICENSE_TYPE",
                "ACCESS_LEVEL",
                "EXTRACTION_METHOD",
                "EXTRACTION_DATE",
                "EXTRACTION_TOOL",
                "CONFIDENCE_SCORES",
                "AUDIT_TRAIL",
                "PROCESSING_DECISION",
                "REASONING",
                "DC_PRIMARY_CLASSIFICATION"
            FROM "{cls.SCHEMA_NAME}"."{cls.TABLE_NAME}"
            WHERE UPPER("ORIGINAL_FILENAME") = UPPER(?)
            """
            
            cursor.execute(query, (original_filename,))
            result = cursor.fetchone()
            
            if not result:
                logger.info(f"No metadata found for filename: {original_filename}")
                return None
            
            # Convert result to dictionary
            columns = [
                "document_id", "original_filename", "file_extension", "upload_timestamp",
                "metadata_json", "title", "creator", "subject", "description",
                "publisher", "contributor", "document_date", "dc_type", "file_format",
                "language", "rights", "file_size", "file_path", "mime_type",
                "md5_hash", "sha256_hash", "copyright_status", "copyright_year",
                "copyright_holder", "license_type", "access_level", "extraction_method",
                "extraction_date", "extraction_tool", "confidence_scores", "audit_trail",
                "processing_decision", "reasoning", "dc_primary_classification"
            ]
            
            metadata_dict = dict(zip(columns, result))
            
            # Parse JSON fields
            try:
                if metadata_dict.get("metadata_json"):
                    metadata_dict["metadata_json"] = json.loads(metadata_dict["metadata_json"])
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse metadata_json for {original_filename}")
                metadata_dict["metadata_json"] = {}
            
            try:
                if metadata_dict.get("confidence_scores"):
                    metadata_dict["confidence_scores"] = json.loads(metadata_dict["confidence_scores"])
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse confidence_scores for {original_filename}")
                metadata_dict["confidence_scores"] = {}
            
            try:
                if metadata_dict.get("audit_trail"):
                    metadata_dict["audit_trail"] = json.loads(metadata_dict["audit_trail"])
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse audit_trail for {original_filename}")
                metadata_dict["audit_trail"] = []
            
            # Convert datetime objects to ISO format strings for JSON serialization
            if isinstance(metadata_dict.get("upload_timestamp"), datetime.datetime):
                metadata_dict["upload_timestamp"] = metadata_dict["upload_timestamp"].isoformat()
            
            logger.info(f"Successfully retrieved metadata for {original_filename}")
            return metadata_dict
            
        except Exception as e:
            logger.error(f"Failed to retrieve metadata for {original_filename}: {str(e)}")
            raise
            
        finally:
            if cursor:
                cursor.close()
            if conn:
                release_db_connection(conn)

    @classmethod
    def get_all_metadata(cls, limit: int = 100, offset: int = 0) -> typing.List[typing.Dict[str, typing.Any]]:
        """
        Retrieve all Dublin Core metadata records with pagination.
        
        Args:
            limit (int): Maximum number of records to return (default: 100)
            offset (int): Number of records to skip (default: 0)
            
        Returns:
            List[Dict[str, Any]]: List of metadata records
            
        Raises:
            Exception: For database-related errors
        """
        conn = None
        cursor = None
        
        try:
            # Get database connection
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Query to get all metadata with pagination
            query = f"""
            SELECT 
                "DOCUMENT_ID",
                "ORIGINAL_FILENAME",
                "FILE_EXTENSION",
                "UPLOAD_TIMESTAMP",
                "TITLE",
                "CREATOR",
                "SUBJECT",
                "DESCRIPTION",
                "PUBLISHER",
                "DC_TYPE",
                "FILE_FORMAT",
                "LANGUAGE",
                "FILE_SIZE",
                "COPYRIGHT_STATUS",
                "LICENSE_TYPE",
                "ACCESS_LEVEL",
                "PROCESSING_DECISION",
                "REASONING",
                "DC_PRIMARY_CLASSIFICATION"
            FROM "{cls.SCHEMA_NAME}"."{cls.TABLE_NAME}"
            ORDER BY "UPLOAD_TIMESTAMP" DESC
            LIMIT ? OFFSET ?
            """
            
            cursor.execute(query, (limit, offset))
            results = cursor.fetchall()
            
            if not results:
                logger.info("No metadata records found")
                return []
            
            # Convert results to list of dictionaries
            columns = [
                "document_id", "original_filename", "file_extension", "upload_timestamp",
                "title", "creator", "subject", "description", "publisher", "dc_type",
                "file_format", "language", "file_size", "copyright_status",
                "license_type", "access_level", "processing_decision", "reasoning","dc_primary_classification"
            ]
            
            metadata_list = []
            for result in results:
                metadata_dict = dict(zip(columns, result))
                
                # Convert datetime objects to ISO format strings for JSON serialization
                if isinstance(metadata_dict.get("upload_timestamp"), datetime.datetime):
                    metadata_dict["upload_timestamp"] = metadata_dict["upload_timestamp"].isoformat()
                
                metadata_list.append(metadata_dict)
            
            logger.info(f"Successfully retrieved {len(metadata_list)} metadata records")
            return metadata_list
            
        except Exception as e:
            logger.error(f"Failed to retrieve metadata records: {str(e)}")
            raise
            
        finally:
            if cursor:
                cursor.close()
            if conn:
                release_db_connection(conn)

    @classmethod
    def search_metadata(cls, search_term: str, search_fields: typing.List[str] = None) -> typing.List[typing.Dict[str, typing.Any]]:
        """
        Search for metadata records based on a search term in specified fields.
        
        Args:
            search_term (str): The term to search for
            search_fields (List[str]): List of fields to search in. If None, searches in common fields.
            
        Returns:
            List[Dict[str, Any]]: List of matching metadata records
            
        Raises:
            ValueError: If search_term is empty
            Exception: For database-related errors
        """
        conn = None
        cursor = None
        
        try:
            # Validate input
            if not search_term:
                logger.error("Search term not provided")
                raise ValueError("Search term cannot be empty")

            # Default search fields if none provided
            if search_fields is None:
                search_fields = ["ORIGINAL_FILENAME", "TITLE", "CREATOR", "SUBJECT", "DESCRIPTION", "PUBLISHER","DC_PRIMARY_CLASSIFICATION"]
            
            # Get database connection
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Build search query
            search_conditions = []
            search_params = []
            
            for field in search_fields:
                search_conditions.append(f'UPPER("{field}") LIKE UPPER(?)')
                search_params.append(f'%{search_term}%')
            
            where_clause = " OR ".join(search_conditions)
            
            query = f"""
            SELECT 
                "DOCUMENT_ID",
                "ORIGINAL_FILENAME",
                "FILE_EXTENSION",
                "UPLOAD_TIMESTAMP",
                "TITLE",
                "CREATOR",
                "SUBJECT",
                "DESCRIPTION",
                "PUBLISHER",
                "DC_TYPE",
                "FILE_FORMAT",
                "LANGUAGE",
                "FILE_SIZE",
                "COPYRIGHT_STATUS",
                "LICENSE_TYPE",
                "ACCESS_LEVEL",
                "PROCESSING_DECISION",
                "REASONING","DC_PRIMARY_CLASSIFICATION"
            FROM "{cls.SCHEMA_NAME}"."{cls.TABLE_NAME}"
            WHERE {where_clause}
            ORDER BY "UPLOAD_TIMESTAMP" DESC
            """
            
            cursor.execute(query, search_params)
            results = cursor.fetchall()
            
            if not results:
                logger.info(f"No metadata records found for search term: {search_term}")
                return []
            
            # Convert results to list of dictionaries
            columns = [
                "document_id", "original_filename", "file_extension", "upload_timestamp",
                "title", "creator", "subject", "description", "publisher", "dc_type",
                "file_format", "language", "file_size", "copyright_status",
                "license_type", "access_level", "processing_decision", "reasoning",
                "dc_primary_classification"
            ]
            
            metadata_list = []
            for result in results:
                metadata_dict = dict(zip(columns, result))
                
                # Convert datetime objects to ISO format strings for JSON serialization
                if isinstance(metadata_dict.get("upload_timestamp"), datetime.datetime):
                    metadata_dict["upload_timestamp"] = metadata_dict["upload_timestamp"].isoformat()
                
                metadata_list.append(metadata_dict)
            
            logger.info(f"Successfully found {len(metadata_list)} metadata records for search term: {search_term}")
            return metadata_list
            
        except Exception as e:
            logger.error(f"Failed to search metadata records: {str(e)}")
            raise
            
        finally:
            if cursor:
                cursor.close()
            if conn:
                release_db_connection(conn)


# Public functions for easy import
def get_metadata_by_filename(original_filename: str) -> typing.Dict[str, typing.Any]:
    """
    Public function to retrieve Dublin Core metadata for a specific filename.
    
    Args:
        original_filename (str): The original filename to search for
        
    Returns:
        Dict[str, Any]: Dictionary containing the metadata record, or None if not found
        
    Raises:
        ValueError: If filename is not provided
        Exception: For database-related errors
    """
    return DublinCoreMetadataReader.get_metadata_by_filename(original_filename)


def get_all_metadata(limit: int = 100, offset: int = 0) -> typing.List[typing.Dict[str, typing.Any]]:
    """
    Public function to retrieve all Dublin Core metadata records with pagination.
    
    Args:
        limit (int): Maximum number of records to return (default: 100)
        offset (int): Number of records to skip (default: 0)
        
    Returns:
        List[Dict[str, Any]]: List of metadata records
        
    Raises:
        Exception: For database-related errors
    """
    return DublinCoreMetadataReader.get_all_metadata(limit, offset)


def search_metadata(search_term: str, search_fields: typing.List[str] = None) -> typing.List[typing.Dict[str, typing.Any]]:
    """
    Public function to search for metadata records based on a search term.
    
    Args:
        search_term (str): The term to search for
        search_fields (List[str]): List of fields to search in. If None, searches in common fields.
        
    Returns:
        List[Dict[str, Any]]: List of matching metadata records
        
    Raises:
        ValueError: If search_term is empty
        Exception: For database-related errors
    """
    return DublinCoreMetadataReader.search_metadata(search_term, search_fields)