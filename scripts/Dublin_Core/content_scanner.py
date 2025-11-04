import os
import json
import typing
import re
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import logging
from pathlib import Path

# Configure logger
logger = logging.getLogger(__name__)

class ProcessingDecision(Enum):
    """Processing decision levels"""
    APPROVED = "APPROVED"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    REJECTED = "REJECTED"

class RiskLevel(Enum):
    """Risk assessment levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AllowedPIICategory(Enum):
    """Allowed PII categories based on new requirements"""
    # Employee Data (Allowed)
    EMPLOYEE_ID = "Employee ID"
    EMPLOYEE_NAME = "Employee Name"
    EMPLOYEE_LOCATION = "Employee Location"
    EMPLOYEE_JOB_TITLE = "Employee Job Title"
    
    # External Customer Data (Corporate Only - Publicly Available)
    CLIENT_NAME = "Client Name (Corporate)"
    COUNTRY_OF_INCORPORATION = "Country of Incorporation"
    DOMICILE = "Domicile"
    INDUSTRY_CLASSIFICATION = "Industry Classification"
    
    # Financial Information (Allowed)
    FINANCIAL_STATEMENTS = "Financial Statements"
    FINANCIAL_INFORMATION = "Financial Information"
    
    # Prohibited PII
    PERSONAL_FINANCIAL = "Personal Financial Data (PROHIBITED)"
    PERSONAL_IDENTIFIERS = "Personal Identifiers (PROHIBITED)"
    NONE = "No PII Detected"

class DocumentClassification(Enum):
    """Enhanced document classification"""
    # Standard classifications
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    
    # Personal document types (to be rejected)
    HEALTH_BILL = "Health Bill (REJECTED)"
    RESTAURANT_BILL = "Restaurant Bill (REJECTED)"
    MEDICAL_DOCUMENT = "Medical Document (REJECTED)"
    PAYSLIP = "Employee Payslip (REJECTED)"
    TAX_SLIP = "Tax Slip (REJECTED)"
    PERSONAL_RECEIPT = "Personal Receipt (REJECTED)"


class CopyrightStatus(Enum):
    """Copyright status classification"""
    PUBLIC_DOMAIN = "PUBLIC_DOMAIN"
    COPYRIGHTED = "COPYRIGHTED"
    FAIR_USE = "FAIR_USE"
    COPYRIGHT_INFRINGEMENT = "COPYRIGHT_INFRINGEMENT"
    UNKNOWN = "UNKNOWN"

@dataclass
class ClassificationKeywordResult:
    """Result of classification keyword detection"""
    keywords_found: typing.List[str]
    keywords_string: str  # Comma-separated string for database storage
    classification_confidence: float
    keyword_positions: typing.Dict[str, typing.List[int]]  # Optional: positions where keywords were found

@dataclass
class SCBDetectionResult:
    """Result of SCB detection"""
    is_scb_document: bool
    confidence_score: float  # 0-100
    reasoning: str
    scb_indicators_found: typing.List[str]
    document_origin: str  # "INTERNAL_SCB", "EXTERNAL_ABOUT_SCB", "EXTERNAL_OTHER"
    detection_method: str  # "RULE_BASED"

@dataclass
class CopyrightDetectionResult:
    """Result of copyright detection from document content"""
    copyright_found_in_content: bool
    copyright_holders_from_content: typing.List[str]
    copyright_statements: typing.List[str]
    content_copyright_confidence: float  # 0-100
    detection_method: str  # "CONTENT_ANALYSIS"
    
@dataclass
class DublinCoreMetadata:
    """Enhanced Dublin Core metadata structure matching actual JSON output"""
    # Document identification
    document_id: str = ""
    
    # Standard Dublin Core fields
    title: str = ""
    creator: typing.List[str] = None
    subject: typing.List[str] = None
    description: str = ""
    publisher: str = ""
    contributor: typing.List[str] = None
    date: str = ""
    type: str = ""
    format: str = ""
    language: str = ""
    rights: str = ""
    
    # Copyright information
    copyright_year: typing.Optional[int] = None
    copyright_holder: typing.List[str] = None
    copyright_status: str = "Unknown"
    
    # License information
    license_type: str = "All Rights Reserved"
    
    # Access control (Critical for business rules)
    access_level: str = ""  # PUBLIC, INTERNAL, CONFIDENTIAL, etc.
    
    # File information
    file_name: str = ""
    file_path: str = ""
    file_size: int = 0
    mime_type: str = ""
    
    # Extraction metadata
    extraction_confidence: float = 0.0
    extraction_date: str = ""
    
    # Custom fields for Earnings processing
    earnings_relevance: str = ""
    scb_confidence: float = 0.0
    
    def __post_init__(self):
        """Initialize list fields if None"""
        if self.creator is None:
            self.creator = []
        if self.subject is None:
            self.subject = []
        if self.contributor is None:
            self.contributor = []
        if self.copyright_holder is None:
            self.copyright_holder = []

@dataclass
class EnhancedScanResult:
    """Enhanced scan result with new requirements including classification keywords"""
    # Core decision
    processing_decision: ProcessingDecision
    risk_level: RiskLevel
    risk_score: float  # 0-100
    
    # Document classification
    document_classification: DocumentClassification
    is_scb_document: bool
    is_earnings_relevant: bool
    is_personal_document: bool  # New field for personal document detection
    
    # Enhanced SCB detection fields
    scb_detection_result: SCBDetectionResult = None
    
    # Enhanced Copyright detection fields
    copyright_detection_result: CopyrightDetectionResult = None
    
    # Classification keyword fields
    classification_keywords: str = ""  # Comma-separated keywords found (e.g., "CONFIDENTIAL, INTERNAL")
    primary_classification: str = ""   # Primary classification keyword (e.g., "CONFIDENTIAL")
    classification_keyword_confidence: float = 0.0  # Confidence score 0-100
    
    # PII and content analysis
    allowed_pii_categories: typing.List[AllowedPIICategory] = None
    prohibited_pii_found: typing.List[str] = None
    sensitive_content_found: bool = False
    
    # Copyright and compliance
    copyright_status: CopyrightStatus = None
    copyright_holder: str = ""
    copyright_concerns: typing.List[str] = None
    
    # Earnings-specific analysis
    earnings_risks: typing.List[str] = None
    compliance_concerns: typing.List[str] = None
    
    # Metadata and enrichment
    dublin_core_metadata: DublinCoreMetadata = None
    
    # Actions and recommendations
    recommendations: typing.List[str] = None
    required_approvals: typing.List[str] = None
    redaction_required: bool = False
    
    # Audit information
    scan_timestamp: str = ""
    confidence_score: float = 0.0
    reasoning: str = ""
    filename: str = ""
    
    def __post_init__(self):
        """Initialize list fields if None"""
        if self.allowed_pii_categories is None:
            self.allowed_pii_categories = []
        if self.prohibited_pii_found is None:
            self.prohibited_pii_found = []
        if self.copyright_concerns is None:
            self.copyright_concerns = []
        if self.earnings_risks is None:
            self.earnings_risks = []
        if self.compliance_concerns is None:
            self.compliance_concerns = []
        if self.recommendations is None:
            self.recommendations = []
        if self.required_approvals is None:
            self.required_approvals = []

class ContentCopyrightDetector:
    """Enhanced copyright detection from document content"""
    

    @staticmethod
    def detect_copyright_in_content(content: str, filename: str = "") -> CopyrightDetectionResult:
        """
        FIXED: Enhanced copyright detection specifically for Standard Chartered Bank patterns
        """
        if not content:
            return CopyrightDetectionResult(
                copyright_found_in_content=False,
                copyright_holders_from_content=[],
                copyright_statements=[],
                content_copyright_confidence=0.0,
                detection_method="CONTENT_ANALYSIS"
            )
        
        content_lower = content.lower()
        copyright_holders = []
        copyright_statements = []
        confidence_score = 0.0
        
        # ENHANCED: Specific Standard Chartered Bank copyright patterns (HIGHEST PRIORITY)
        scb_specific_patterns = [
            # "All rights reserved. Standard Chartered Bank" variations
            r'all\s+rights\s+reserved\.\s*standard\s+chartered\s+bank',
            r'all\s+rights\s+reserved\.\s*standard\s+chartered',
            
            # "Standard Chartered Bank. All rights reserved" variations  
            r'standard\s+chartered\s+bank\.\s*all\s+rights\s+reserved',
            r'standard\s+chartered\.\s*all\s+rights\s+reserved',
            
            # Year + Standard Chartered + All rights reserved
            r'(\d{4})?\s*standard\s+chartered\s+bank\.\s*all\s+rights\s+reserved',
            r'(\d{4})?\s*standard\s+chartered\.\s*all\s+rights\s+reserved',
            
            # Copyright symbol + Year + Standard Chartered
            r'©\s*(\d{4})?\s*standard\s+chartered\s+bank',
            r'copyright\s*©?\s*(\d{4})?\s*standard\s+chartered\s+bank',
            r'©\s*(\d{4})?\s*standard\s+chartered(?:\s+bank)?',
            
            # Standard Chartered with "All rights reserved" in any order
            r'standard\s+chartered[^\n\r.]{0,50}all\s+rights\s+reserved',
            r'all\s+rights\s+reserved[^\n\r.]{0,50}standard\s+chartered',
        ]
        
        # Check SCB-specific patterns first (highest confidence)
        for pattern in scb_specific_patterns:
            matches = re.finditer(pattern, content_lower, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                full_match = match.group(0).strip()
                copyright_statements.append(full_match)
                confidence_score += 50.0  # High confidence for SCB patterns
                
                # Extract Standard Chartered as copyright holder
                if 'standard chartered bank' in full_match:
                    copyright_holders.append('Standard Chartered Bank')
                elif 'standard chartered' in full_match:
                    copyright_holders.append('Standard Chartered')
        
        # ENHANCED: General copyright patterns with better Standard Chartered detection
        general_copyright_patterns = [
            # Copyright symbol with year and holder
            r'copyright\s*©\s*(\d{4}(?:[-\s]*\d{4})?)\s+(?:by\s+)?([^\n\r.;,]{10,80})',
            r'©\s*(\d{4}(?:[-\s]*\d{4})?)\s+(?:by\s+)?([^\n\r.;,]{10,80})',
            r'copyright\s*\(c\)\s*(\d{4}(?:[-\s]*\d{4})?)\s+(?:by\s+)?([^\n\r.;,]{10,80})',
            
            # Copyright ownership statements
            r'copyright\s+(?:is\s+)?(?:owned\s+by|belongs\s+to)\s+([^\n\r.;,]{10,80})',
            r'copyrighted\s+(?:material\s+)?(?:by|to)\s+([^\n\r.;,]{10,80})',
            
            # All rights reserved with context (only if not already found by SCB patterns)
            r'copyright[^\n\r]{0,30}all\s+rights\s+reserved\s*(?:by\s+)?([^\n\r.;,]{10,80})',
            r'all\s+rights\s+reserved[^\n\r]{0,30}copyright\s*(?:by\s+)?([^\n\r.;,]{10,80})',
            
            # ADDED: Direct "All rights reserved" patterns for Standard Chartered
            r'all\s+rights\s+reserved\s*\.?\s*([^\n\r.;,]{0,50}standard\s+chartered[^\n\r.;,]{0,50})',
            r'([^\n\r.;,]{0,50}standard\s+chartered[^\n\r.;,]{0,50})\s*\.?\s*all\s+rights\s+reserved',
        ]
        
        # ENHANCED: False positive patterns - EXCLUDE Standard Chartered from false positives
        false_positive_patterns = [
            r'co\.\s*reg\.\s*no\.',  # Company registration
            r'company\s+registration\s+number',
            r'incorporated\s+in',
            r'tel:\s*\+?\d+',  # Phone numbers
            r'fax:\s*\+?\d+',
            r'www\.',  # Websites
            r'\.com\b',
            r'singapore\s+\d{6}',  # Postal codes
            r'marina\s+bay\s+financial',
            r'tower\s+\d+',
            r'level\s+\d+',
            r'floor\s+\d+',
            r'group\s+holdings\s+ltd',
            r'plc\b', r'ltd\b', r'inc\b', r'corp\b',
            r'board\s+of\s+directors',
            r'group\s+secretary',
            r'chief\s+executive\s+officer',
            r'more\s+information.*available\s+at',
        ]
        
        # Process general patterns only if no SCB-specific patterns found
        if not copyright_statements:  # Only if no SCB patterns already found
            for pattern in general_copyright_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    full_match = match.group(0).strip()
                    
                    # ENHANCED: Check if this matches false positive patterns
                    # BUT EXCLUDE Standard Chartered from false positive filtering
                    is_standard_chartered = any(scb_term in full_match.lower() 
                                            for scb_term in ['standard chartered', 'standardchartered'])
                    
                    if not is_standard_chartered:  # Only apply false positive filtering to non-SCB content
                        is_false_positive = any(
                            re.search(fp_pattern, full_match, re.IGNORECASE) 
                            for fp_pattern in false_positive_patterns
                        )
                        if is_false_positive:
                            continue  # Skip this match - it's corporate info, not copyright
                    
                    copyright_statements.append(full_match)
                    confidence_score += 30.0
                    
                    # Extract copyright holder if pattern captures it
                    if len(match.groups()) >= 2:
                        holder = match.group(2).strip()
                    elif len(match.groups()) >= 1 and len(match.groups()[0]) > 4:
                        holder = match.group(1).strip()
                    else:
                        continue
                    
                    # Clean and validate the holder
                    holder = ContentCopyrightDetector._clean_copyright_holder(holder)
                    if holder and len(holder) > 3:  # Must be substantial
                        # ENHANCED: Always include Standard Chartered holders
                        is_scb_holder = any(scb_term in holder.lower() 
                                        for scb_term in ['standard chartered', 'standardchartered'])
                        
                        if is_scb_holder or not ContentCopyrightDetector._is_corporate_info(holder):
                            copyright_holders.append(holder)
        
        # Remove duplicates and clean up
        copyright_holders = list(set([h for h in copyright_holders if h]))
        copyright_statements = list(set(copyright_statements))
        
        # Cap confidence score
        confidence_score = min(100.0, confidence_score)
        
        return CopyrightDetectionResult(
            copyright_found_in_content=len(copyright_statements) > 0,
            copyright_holders_from_content=copyright_holders,
            copyright_statements=copyright_statements,
            content_copyright_confidence=confidence_score,
            detection_method="CONTENT_ANALYSIS"
        )

    @staticmethod
    def _is_corporate_info(text: str) -> bool:
        """
        ENHANCED: Check if text is corporate info rather than copyright holder
        EXCLUDES Standard Chartered from corporate info filtering
        """
        text_lower = text.lower().strip()
        
        # ENHANCED: Never treat Standard Chartered as corporate info
        scb_indicators = [
            'standard chartered',
            'standardchartered', 
            'scb bank',
            'standard chartered bank',
            'standard chartered plc'
        ]
        
        is_scb = any(scb_term in text_lower for scb_term in scb_indicators)
        if is_scb:
            return False  # Standard Chartered is never corporate info - always a valid copyright holder
        
        # Apply corporate info filtering only to non-SCB content
        corporate_patterns = [
            r'co\.\s*reg\.\s*no\.',
            r'company\s+registration',
            r'singapore\s+\d{6}',
            r'tower\s+\d+',
            r'level\s+\d+',
            r'marina\s+bay',
            r'financial\s+centre',
            r'tel:\s*\+?\d+',
            r'www\.',
            r'\.com',
            r'group\s+secretary',
            r'chief\s+executive',
            r'board\s+of\s+directors',
            r'^\d+\s+\w+\s+(?:street|road|avenue|boulevard)',  # Addresses
        ]
        
        return any(re.search(pattern, text_lower, re.IGNORECASE) for pattern in corporate_patterns)


    @staticmethod
    def _clean_copyright_holder(holder_text: str) -> str:
        """
        ENHANCED: Better cleaning while preserving Standard Chartered copyright holders
        """
        if not holder_text:
            return ""
        
        original_text = holder_text.strip()
        
        # ENHANCED: Preserve Standard Chartered copyright statements
        scb_indicators = ['standard chartered', 'standardchartered']
        is_scb_holder = any(scb_term in original_text.lower() for scb_term in scb_indicators)
        
        if is_scb_holder:
            # For Standard Chartered, do minimal cleaning to preserve important context
            cleaned = original_text
            
            # Only remove trailing punctuation and common suffixes
            cleanup_patterns = [
                r'\s*\.\s*$',    # Trailing period
                r'\s*,\s*$',     # Trailing comma
                r'\s*;\s*$',     # Trailing semicolon
                r'\s*-\s*$',     # Trailing dash
            ]
            
            for pattern in cleanup_patterns:
                cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE).strip()
            
            # Remove extra whitespace
            cleaned = re.sub(r'\s+', ' ', cleaned)
            
            return cleaned
        
        # For non-SCB holders, apply more aggressive cleaning
        cleanup_patterns = [
            r'\s*all\s*rights\s*reserved.*$',
            r'\s*\.\s*$',
            r'\s*,\s*$',
            r'\s*;\s*$',
            r'\s*-\s*$',
            r'^\s*by\s*',
            r'^\s*to\s*',
            r'^\s*of\s*',
        ]
        
        cleaned = original_text
        for pattern in cleanup_patterns:
            cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE).strip()
        
        # Remove extra whitespace
        cleaned = re.sub(r'\s+', ' ', cleaned)
        
        return cleaned



# FIX 2: Update _check_copyright_holder_text to include DBS as acceptable
# In EnhancedEarningsContentScanner class:

    def _check_copyright_holder_text(self, copyright_holder_text: str) -> bool:
        """
        ENHANCED: Comprehensive Standard Chartered Bank copyright holder validation
        """
        if not copyright_holder_text:
            return True  # Empty = Unknown = acceptable
        
        holder_lower = copyright_holder_text.lower().strip()
        
        # ENHANCED: Comprehensive Standard Chartered patterns (case-insensitive)
        acceptable_holders = [
            # Core Standard Chartered patterns
            'standard chartered',
            'standard chartered bank', 
            'standardchartered',
            'standard chartered plc',
            'standard chartered group',
            
            # Regional variations
            'standard chartered (singapore)',
            'standard chartered singapore',
            'standard chartered malaysia',
            'standard chartered india',
            'standard chartered hong kong',
            'standard chartered thailand',
            'standard chartered korea',
            'standard chartered china',
            'standard chartered pakistan',
            'standard chartered bangladesh',
            'standard chartered sri lanka',
            'standard chartered uae',
            'standard chartered kenya',
            'standard chartered tanzania',
            'standard chartered ghana',
            'standard chartered nigeria',
            'standard chartered botswana',
            'standard chartered zambia',
            'standard chartered zimbabwe',
            'standard chartered south africa',
            
            # Abbreviations
            'scb',
            'sc bank',
            'sc group',
            
            # Legal entities
            'standard chartered bank (singapore) limited',
            'standard chartered bank malaysia berhad',
            'standard chartered bank (thai) public company limited',
            'standard chartered bank korea limited',
            'standard chartered bank (china) limited',
            'standard chartered bank pakistan limited',
            'standard chartered bank bangladesh limited',
            'standard chartered plc',
            
            # With copyright context patterns
            'standard chartered bank. all rights reserved',
            'all rights reserved. standard chartered bank',
            'standard chartered. all rights reserved',
            'all rights reserved. standard chartered',
            
            # DBS patterns (existing)
            'dbs',
            'dbs group',
            'dbs group holdings',
            'dbs group holdings ltd',
            'dbs bank',
            'development bank of singapore',
            
            # Generic acceptable patterns
            'unknown',
            'not specified',
            'n/a',
            'na',
            'none',
            ''
        ]
        
        # ENHANCED: Check for any acceptable holder pattern
        for acceptable in acceptable_holders:
            if acceptable in holder_lower:
                logger.info(f"Acceptable copyright holder found: '{acceptable}' in '{copyright_holder_text}'")
                return True
        
        # ENHANCED: Additional fuzzy matching for Standard Chartered variations
        scb_fuzzy_patterns = [
            r'standard\s+chartered',
            r'standardchartered',
            r'\bscb\b',
            r'standard\s+chartered\s+bank',
            r'standard\s+chartered\s+plc',
            r'standard\s+chartered\s+group'
        ]
        
        for pattern in scb_fuzzy_patterns:
            if re.search(pattern, holder_lower, re.IGNORECASE):
                logger.info(f"Standard Chartered pattern matched: '{pattern}' in '{copyright_holder_text}'")
                return True
        
        # If we reach here, copyright holder is not acceptable
        logger.warning(f"Non-acceptable copyright holder detected: '{copyright_holder_text}'")
        return False

# FIX 3: Update _is_likely_public_financial_document method
# In EnhancedEarningsContentScanner class:

def _is_likely_public_financial_document(self, metadata: DublinCoreMetadata, filename: str) -> bool:
    """
    ENHANCED: Better detection of legitimate public financial documents
    """
    if not metadata:
        return False
    
    # ENHANCED: More comprehensive public financial document indicators
    public_financial_indicators = [
        # Document types
        'financial results', 'interim results', 'annual report', 'quarterly report',
        'earnings report', 'financial statements', 'investor presentation',
        'performance summary', 'unaudited', 'audited results', 'half year',
        'first half', 'second quarter', 'third quarter', 'fourth quarter',
        
        # Corporate governance
        'board of directors', 'shareholders', 'dividend', 'profit before tax',
        'net profit', 'total income', 'balance sheet', 'cash flow',
        'return on equity', 'earnings per share', 'net interest income',
        
        # Regulatory filings
        'singapore financial reporting standards', 'sfrs', 'listing rule',
        'capital adequacy', 'basel iii', 'regulatory requirements',
        'common equity tier', 'risk weighted assets', 'tier 1 capital',
        
        # Public disclosure indicators
        'investor relations', 'public announcement', 'stock exchange',
        'to shareholders', 'announcement', 'interim dividend'
    ]
    
    # Check document content - include more metadata fields
    content_text = f"{metadata.title} {metadata.description} {filename} {metadata.publisher}".lower()
    if metadata.creator:
        content_text += " " + " ".join(metadata.creator).lower()
    
    public_indicators_found = sum(1 for indicator in public_financial_indicators 
                                 if indicator in content_text)
    
    # ENHANCED: Check for legitimate financial institutions
    legitimate_institutions = [
        # Major Singapore banks
        'dbs group holdings', 'dbs bank', 'development bank of singapore',
        'ocbc', 'oversea-chinese banking corporation', 'uob', 'united overseas bank',
        
        # Standard Chartered (original)
        'standard chartered', 'standard chartered bank',
        
        # Major global banks
        'hsbc', 'citibank', 'jpmorgan', 'goldman sachs', 'morgan stanley',
        'bank of america', 'wells fargo', 'deutsche bank', 'ubs', 'credit suisse',
        'barclays', 'lloyds', 'royal bank'
    ]
    
    institution_found = any(inst in content_text for inst in legitimate_institutions)
    
    # ENHANCED: Consider it public financial document if:
    # 1. Multiple public financial indicators found (lowered threshold), AND
    # 2. From a legitimate financial institution
    is_public_financial = public_indicators_found >= 2 and institution_found
    
    if is_public_financial:
        logger.info(f"Public financial document detected: {public_indicators_found} indicators, institution: {institution_found}")
    
    return is_public_financial

# FIX 4: Update _apply_remaining_business_rules with enhanced public document handling
# In EnhancedEarningsContentScanner class:

def _apply_remaining_business_rules(self, primary_classification: str, allowed_pii: typing.List[AllowedPIICategory],
                                  prohibited_pii: typing.List[str], is_scb_document: bool, 
                                  metadata: DublinCoreMetadata, filename: str) -> typing.Tuple[ProcessingDecision, str, str]:
    """
    ENHANCED: Business rules with better public financial document support
    """
    
    updated_primary_classification = primary_classification
    
    # Rule 2a: If RESTRICTED classification - REJECT
    if primary_classification == "RESTRICTED":
        return ProcessingDecision.REJECTED, "Document classified as RESTRICTED", updated_primary_classification
    
    # ENHANCED Rule 2b: Better context-aware handling of documents without explicit classification
    if primary_classification == "":
        # Check if this appears to be a legitimate public financial document
        if self._is_likely_public_financial_document(metadata, filename):
            # ENHANCED: Additional validation - check content for financial institution
            content_text = f"{metadata.title} {metadata.description} {filename}".lower()
            
            # List of acceptable financial institutions for public documents
            acceptable_institutions = [
                'dbs group holdings', 'dbs bank', 'development bank of singapore',
                'standard chartered', 'ocbc', 'uob', 'hsbc', 'citibank'
            ]
            
            institution_match = any(inst in content_text for inst in acceptable_institutions)
            
            if institution_match:
                updated_primary_classification = "PUBLIC"
                logger.info(f"Treating {filename} as PUBLIC based on financial document context")
                # ENHANCED: Return APPROVED for legitimate public financial documents
                return ProcessingDecision.APPROVED, "Public financial document from recognized institution", updated_primary_classification
        
        return ProcessingDecision.REJECTED, "No document classification found and context unclear", updated_primary_classification
    
    # Use the updated classification for remaining rules
    current_classification = updated_primary_classification
    
    # Rule 3: PII/Sensitive information - REJECT
    if prohibited_pii:
        return ProcessingDecision.REJECTED, f"Prohibited PII detected: {', '.join(prohibited_pii)}", updated_primary_classification
    
    # Rule 3: Any ALLOWED PII Category - NEED_APPROVAL
    if allowed_pii and AllowedPIICategory.NONE not in allowed_pii:
        return ProcessingDecision.NEEDS_APPROVAL, f"Allowed PII categories detected: {', '.join([pii.value for pii in allowed_pii])}", updated_primary_classification
    
    # ENHANCED Rule 4: If PUBLIC document - handle better
    if current_classification == "PUBLIC":
        # Check if this is a legitimate public financial document
        if self._is_likely_public_financial_document(metadata, filename):
            return ProcessingDecision.APPROVED, "Public financial document", updated_primary_classification
        elif self._is_scb_copyright_holder_simple(metadata):
            return ProcessingDecision.APPROVED, "PUBLIC document with acceptable copyright", updated_primary_classification
        else:
            return ProcessingDecision.NEEDS_APPROVAL, "PUBLIC document requires review", updated_primary_classification
    
    # Rule 5: If INTERNAL/CONFIDENTIAL and SCB document - NEED_APPROVAL
    if current_classification in ["INTERNAL", "CONFIDENTIAL"]:
        if is_scb_document:
            return ProcessingDecision.NEEDS_APPROVAL, f"SCB document with {current_classification} classification", updated_primary_classification
        else:
            return ProcessingDecision.REJECTED, f"Non-SCB document cannot have {current_classification} classification", updated_primary_classification
    
    # Rule 6: Default - NEED_APPROVAL
    return ProcessingDecision.NEEDS_APPROVAL, "Document requires approval per default policy", updated_primary_classification

# FIX 5: Update _is_scb_copyright_holder to handle no-copyright cases properly
# In EnhancedEarningsContentScanner class:

    def _is_scb_copyright_holder(self, metadata: DublinCoreMetadata, 
                                content_copyright_result: CopyrightDetectionResult = None) -> bool:
        """
        ENHANCED: Comprehensive Standard Chartered copyright holder validation
        """
        # Check metadata copyright holders
        metadata_acceptable = self._is_scb_copyright_holder_simple(metadata)
        
        # If no content copyright result provided, rely on metadata only
        if not content_copyright_result:
            return metadata_acceptable
        
        # ENHANCED: Better handling of content copyright results for Standard Chartered
        if content_copyright_result.copyright_found_in_content:
            # Check if any valid Standard Chartered copyright holders were found
            valid_copyright_holders = [
                holder for holder in content_copyright_result.copyright_holders_from_content
                if holder and len(holder.strip()) > 2
            ]
            
            if not valid_copyright_holders:
                # No valid copyright holders found after filtering - treat as acceptable if no explicit non-SCB copyright
                logger.info("Content copyright detected but no valid holders found - checking if acceptable")
                return True  # No explicit copyright holder = acceptable
            
            # Check each holder using our enhanced validation
            content_acceptable = True
            for holder in valid_copyright_holders:
                if not self._check_copyright_holder_text(holder):
                    content_acceptable = False
                    logger.warning(f"Non-acceptable content copyright holder: {holder}")
                    break
            
            # If both metadata and content have copyright info, both must be acceptable
            if metadata and metadata.copyright_holder and any(h.strip() for h in metadata.copyright_holder):
                result = metadata_acceptable and content_acceptable
                logger.info(f"Both metadata and content copyright present. Metadata OK: {metadata_acceptable}, Content OK: {content_acceptable}, Final: {result}")
                return result
            else:
                # If no metadata copyright but content copyright found, check content only
                logger.info(f"Only content copyright found. Content acceptable: {content_acceptable}")
                return content_acceptable
        
        # If no content copyright found, rely on metadata check
        logger.info(f"No content copyright found, using metadata result: {metadata_acceptable}")
        return metadata_acceptable

# USAGE: The integration function remains the same name and signature
def integrate_enhanced_content_scanning(document_text: str, filename: str, 
                                      metadata_file_path: str = None, 
                                      metadata_dict: dict = None) -> typing.Tuple[bool, EnhancedScanResult]:
    """
    Integration function - SAME SIGNATURE, enhanced logic
    """
    try:
        # Initialize scanner - SAME CLASS NAME
        scanner = EnhancedEarningsContentScanner()
        
        # Load metadata - SAME LOGIC STRUCTURE
        if metadata_dict:
            if 'file_info' not in metadata_dict:
                metadata_dict['file_info'] = {}
            if 'file_name' not in metadata_dict['file_info']:
                metadata_dict['file_info']['file_name'] = filename
                
            metadata = DublinCoreMetadataLoader.load_metadata_from_dict(metadata_dict)
        else:
            metadata = DublinCoreMetadataLoader.load_metadata(metadata_file_path) if metadata_file_path else DublinCoreMetadata()
            if not metadata.file_name:
                metadata.file_name = filename
        
        # Perform scan - SAME METHOD NAME
        scan_result = scanner.scan_document(document_text, filename, metadata)
        
        # Print results - SAME FUNCTION NAME
        print_enhanced_scan_results(scan_result)
        
        # Determine if processing should proceed
        should_proceed = scan_result.processing_decision == ProcessingDecision.APPROVED
        
        # Enhanced logging
        logger.info(f"Scan completed for {filename}:")
        logger.info(f"  - Decision: {scan_result.processing_decision.value}")
        logger.info(f"  - Copyright Holder: {scan_result.copyright_holder}")
        logger.info(f"  - Content Copyright Found: {scan_result.copyright_detection_result.copyright_found_in_content if scan_result.copyright_detection_result else 'N/A'}")
        logger.info(f"  - Classification: {scan_result.primary_classification}")
        logger.info(f"  - Reasoning: {scan_result.reasoning}")
        
        return should_proceed, scan_result
    
    except Exception as e:
        logger.error(f"Content scanning failed for {filename}: {str(e)}")
        raise Exception(f"Content scanning failed: {str(e)}")

class SCBDetectionHelper:
    """Helper class for rule-based SCB detection"""
    
    @staticmethod
    def check_scb_text(text: str) -> bool:
        """Check if text contains Standard Chartered patterns"""
        if not text:
            return False
        
        text_lower = text.lower()
        scb_patterns = [
            'standard chartered',
            'standard chartered bank',
            'standardchartered',
            'sc.com',
            'standardchartered.com',
            'scb bank',
            'scb',
            'standard chartered plc',
            'standard chartered (singapore)',
            'standard chartered malaysia',
            'standard chartered india',
            'standard chartered hong kong'
        ]
        
        return any(pattern in text_lower for pattern in scb_patterns)

    @staticmethod
    def detect_scb_in_filename(file_path: str) -> bool:
        """Check if filename itself contains SCB patterns"""
        filename = Path(file_path).name
        return SCBDetectionHelper.check_scb_text(filename)

    @staticmethod
    def detect_scb_comprehensive(content: str, filename: str, metadata: 'DublinCoreMetadata' = None) -> bool:
        """
        Comprehensive rule-based SCB detection
        
        Args:
            content (str): Document content
            filename (str): Document filename
            metadata (DublinCoreMetadata): Optional metadata
            
        Returns:
            bool: True if document is from SCB, False otherwise
        """
        try:
            # Step 1: Check filename
            if SCBDetectionHelper.detect_scb_in_filename(filename):
                return True
            
            # Step 2: Check file content
            if SCBDetectionHelper.check_scb_text(content):
                return True
            
            # Step 3: Check metadata if available
            if metadata:
                # Check creators
                if metadata.creator:
                    creators_text = ' '.join(metadata.creator)
                    if SCBDetectionHelper.check_scb_text(creators_text):
                        return True
                
                # Check publisher
                if metadata.publisher and SCBDetectionHelper.check_scb_text(metadata.publisher):
                    return True
                
                # Check contributors
                if metadata.contributor:
                    contributors_text = ' '.join(metadata.contributor)
                    if SCBDetectionHelper.check_scb_text(contributors_text):
                        return True
                
                # Check copyright holder
                if metadata.copyright_holder:
                    copyright_text = ' '.join(metadata.copyright_holder)
                    if SCBDetectionHelper.check_scb_text(copyright_text):
                        return True
            
            return False
                
        except Exception as e:
            logger.error(f"Error in SCB detection for {filename}: {str(e)}")
            return False

class DocumentClassificationKeywordDetector:
    """FIXED: Document classification keyword detector with better precision"""
    
    # Keep original class structure and variables
    BASE_CLASSIFICATION_KEYWORDS = [
        "PUBLIC",
        "CONFIDENTIAL", 
        "RESTRICTED",
        "CROSS BORDER"
    ]
    
    SCB_ONLY_KEYWORDS = ["INTERNAL"]
    
    @staticmethod
    def get_applicable_keywords(is_scb_document: bool) -> typing.List[str]:
        """Same function - no changes needed"""
        keywords = DocumentClassificationKeywordDetector.BASE_CLASSIFICATION_KEYWORDS.copy()
        if is_scb_document:
            keywords.extend(DocumentClassificationKeywordDetector.SCB_ONLY_KEYWORDS)
        return keywords
    
    @staticmethod
    def detect_classification_keywords(content: str, filename: str = "", 
                                     is_scb_document: bool = False) -> ClassificationKeywordResult:
        """
        FIXED: More precise classification keyword detection avoiding false positives
        """
        if not content:
            return ClassificationKeywordResult(
                keywords_found=[],
                keywords_string="",
                classification_confidence=0.0,
                keyword_positions={}
            )
        
        applicable_keywords = DocumentClassificationKeywordDetector.get_applicable_keywords(is_scb_document)
        
        keywords_found = []
        keyword_positions = {}
        total_confidence = 0.0
        
        lines = content.split('\n')
        content_lower = content.lower()
        filename_lower = filename.lower() if filename else ""
        
        # FIXED: More precise patterns for each classification keyword
        for main_keyword in applicable_keywords:
            keyword_lower = main_keyword.lower()
            keyword_found = False
            positions = []
            confidence_boost = 0.0
            
            # FIXED: Precise high confidence patterns - require word boundaries
            high_confidence_patterns = [
                # Classification headers/banners - must be standalone
                rf'^\s*{re.escape(keyword_lower)}\s*$',
                rf'^\s*classification\s*:?\s*{re.escape(keyword_lower)}\s*$',
                rf'^\s*document\s+classification\s*:?\s*{re.escape(keyword_lower)}\s*$',
                rf'^\s*marking\s*:?\s*{re.escape(keyword_lower)}\s*$',
                rf'^\s*security\s+classification\s*:?\s*{re.escape(keyword_lower)}\s*$',
                rf'^\s*access\s+level\s*:?\s*{re.escape(keyword_lower)}\s*$',
                rf'^\s*sensitivity\s*:?\s*{re.escape(keyword_lower)}\s*$',
                
                # Header/footer patterns with clear boundaries
                rf'^\s*-+\s*{re.escape(keyword_lower)}\s*-+\s*$',
                rf'^\s*\*+\s*{re.escape(keyword_lower)}\s*\*+\s*$',
                rf'^\s*=+\s*{re.escape(keyword_lower)}\s*=+\s*$',
                
                # Structured patterns with word boundaries
                rf'\bclassification\s*[:\-=]\s*{re.escape(keyword_lower)}\b',
                rf'\bsecurity\s*[:\-=]\s*{re.escape(keyword_lower)}\b',
                rf'\bmarking\s*[:\-=]\s*{re.escape(keyword_lower)}\b',
            ]
            
            # FIXED: Word boundary patterns for medium confidence  
            medium_confidence_patterns = [
                # Document marked as classification - with word boundaries
                rf'\bthis\s+document\s+is\s+{re.escape(keyword_lower)}\b',
                rf'\bdocument\s+marked\s+as\s+{re.escape(keyword_lower)}\b',
                rf'\bmarked\s+{re.escape(keyword_lower)}\b',
                rf'\b{re.escape(keyword_lower)}\s+document\b',
                rf'\b{re.escape(keyword_lower)}\s+information\b',
                rf'\b{re.escape(keyword_lower)}\s+material\b',
                
                # In filename with word boundaries
                rf'\b{re.escape(keyword_lower)}\b' if keyword_lower in filename_lower else None
            ]
            
            # FIXED: Exclude false positive patterns BEFORE checking for keywords
            false_positive_patterns = {
                'restricted': [
                    r'\bco\.\s*reg\.\s*no\.',  # Company registration number
                    r'\bcompany\s+registration\b',
                    r'\bregistered\s+office\b',
                    r'\bregistration\s+number\b',
                    r'\btransfer\s+books.*register\b',  # Transfer books and register
                    r'\bregister\s+of\s+members\b',
                    r'\bregional\s+\w+\b',  # Regional offices, etc.
                ],
                'public': [
                    r'\brepublic\s+of\b',  # Republic of Singapore
                    r'\bpublic\s+limited\s+company\b',
                ],
                'internal': [
                    r'\binternational\s+\w+\b',  # International standards, etc.
                ],
                'confidential': [
                    r'\bconfidentiality\s+\w+\b',  # Confidentiality agreements, etc.
                ]
            }
            
            # Check if this keyword has false positive exclusions
            if keyword_lower in false_positive_patterns:
                has_false_positive = any(
                    re.search(fp_pattern, content_lower, re.IGNORECASE)
                    for fp_pattern in false_positive_patterns[keyword_lower]
                )
                if has_false_positive:
                    logger.info(f"Skipping {main_keyword} due to false positive pattern match")
                    continue  # Skip this keyword entirely
            
            # Check high confidence patterns first (line by line for headers)
            for i, line in enumerate(lines[:10]):  # Check first 10 lines for headers
                line_lower = line.lower().strip()
                for pattern in high_confidence_patterns:
                    if re.search(pattern, line_lower, re.IGNORECASE):
                        keyword_found = True
                        confidence_boost += 40.0
                        positions.append(i)
                        break
            
            # Check last 10 lines for footers
            for i, line in enumerate(lines[-10:], start=max(0, len(lines)-10)):
                line_lower = line.lower().strip()
                for pattern in high_confidence_patterns:
                    if re.search(pattern, line_lower, re.IGNORECASE):
                        keyword_found = True
                        confidence_boost += 30.0
                        positions.append(i)
                        break
            
            # Check medium confidence patterns in full content
            for pattern in medium_confidence_patterns:
                if pattern and re.search(pattern, content_lower, re.IGNORECASE):
                    keyword_found = True
                    confidence_boost += 20.0
                    
                    for match in re.finditer(pattern, content_lower, re.IGNORECASE):
                        positions.append(match.start())
            
            # REMOVED: Low confidence substring matching that caused false positives
            # The original code had: if keyword_lower in content_lower:
            # This is what was causing "REG" to match "RESTRICTED"
            
            if keyword_found:
                keywords_found.append(main_keyword)
                total_confidence += confidence_boost
                if positions:
                    keyword_positions[main_keyword] = positions
        
        # Remove duplicates and sort
        keywords_found = sorted(list(set(keywords_found)))
        
        # Create comma-separated string for database storage
        keywords_string = ", ".join(keywords_found) if keywords_found else ""
        
        # Cap total confidence
        final_confidence = min(100.0, total_confidence)
        
        return ClassificationKeywordResult(
            keywords_found=keywords_found,
            keywords_string=keywords_string,
            classification_confidence=final_confidence,
            keyword_positions=keyword_positions
        )
    
    @staticmethod
    def get_primary_classification(keywords_found: typing.List[str]) -> str:
        """Same function - no changes needed"""
        if not keywords_found:
            return ""
        
        hierarchy = ["RESTRICTED", "CONFIDENTIAL", "CROSS BORDER", "INTERNAL", "PUBLIC"]
        
        for classification in hierarchy:
            if classification in keywords_found:
                return classification
        
        return keywords_found[0]
    
    @staticmethod  
    def enhance_classification_detection(content: str, filename: str = "", 
                                       metadata_access_level: str = "",
                                       is_scb_document: bool = False) -> ClassificationKeywordResult:
        """Same function - no changes needed"""
        result = DocumentClassificationKeywordDetector.detect_classification_keywords(
            content, filename, is_scb_document
        )
        
        if metadata_access_level:
            metadata_lower = metadata_access_level.lower()
            
            metadata_mappings = {
                "public": "PUBLIC",
                "confidential": "CONFIDENTIAL", 
                "restricted": "RESTRICTED"
            }
            
            if is_scb_document:
                metadata_mappings["internal"] = "INTERNAL"
            
            for meta_key, our_keyword in metadata_mappings.items():
                if meta_key in metadata_lower and our_keyword not in result.keywords_found:
                    result.keywords_found.append(our_keyword)
                    result.classification_confidence += 25.0
        
        result.keywords_found = sorted(list(set(result.keywords_found)))
        result.keywords_string = ", ".join(result.keywords_found)
        result.classification_confidence = min(100.0, result.classification_confidence)
        
        return result

# ADDITIONAL FIX: Update the main scan_document method to use the fixed detector
# In EnhancedEarningsContentScanner class:

def scan_document(self, document_text: str, filename: str = "document", 
                 metadata: DublinCoreMetadata = None) -> EnhancedScanResult:
    """
    FIXED: Use the corrected classification detection 
    """
    logger.info(f"Starting enhanced content scan for {filename}")
    
    try:
        if metadata is None:
            metadata = DublinCoreMetadata()
            metadata.file_name = filename
        
        # Step 0: Enhanced content-based copyright detection
        content_copyright_result = ContentCopyrightDetector.detect_copyright_in_content(
            document_text, filename
        )
        
        # PRIORITY RULE 1: Enhanced copyright check
        if not self._is_scb_copyright_holder(metadata, content_copyright_result):
            logger.info(f"Non-SCB copyright holder detected: {filename} - REJECTED")
            return self._create_copyright_rejection(filename, metadata, content_copyright_result)
        
        # Step 1: Determine if document belongs to SCB
        is_scb_document = SCBDetectionHelper.detect_scb_comprehensive(
            document_text, filename, metadata
        )
        
        # Step 2: FIXED - Use corrected classification detection
        keyword_result = DocumentClassificationKeywordDetector.enhance_classification_detection(
            document_text, filename, metadata.access_level if metadata else "", is_scb_document
        )
        primary_classification = DocumentClassificationKeywordDetector.get_primary_classification(
            keyword_result.keywords_found
        )
        
        # DEBUG: Log classification detection results
        logger.info(f"Classification detection for {filename}:")
        logger.info(f"  Keywords found: {keyword_result.keywords_found}")
        logger.info(f"  Primary classification: {primary_classification}")
        logger.info(f"  Confidence: {keyword_result.classification_confidence}")
        
        # Step 3: Check for personal documents
        document_classification = DocumentTypeDetector.detect_personal_document_type(
            document_text, filename
        )
        is_personal = DocumentTypeDetector.is_personal_document(document_classification)
        
        if is_personal:
            logger.info(f"Personal document detected: {filename} - {document_classification.value}")
            return self._create_personal_document_rejection(
                filename, document_classification, metadata, keyword_result, 
                primary_classification, is_scb_document, content_copyright_result
            )
        
        # Step 4: Detect PII
        allowed_pii = PIIDetector.detect_allowed_pii(document_text, filename)
        prohibited_pii = PIIDetector.detect_prohibited_pii(document_text, filename)
        
        # Step 5: Apply business rules
        processing_decision, reasoning, updated_primary_classification = self._apply_remaining_business_rules(
            primary_classification, allowed_pii, prohibited_pii, 
            is_scb_document, metadata, filename
        )
        
        final_primary_classification = updated_primary_classification if updated_primary_classification else primary_classification
        
        # Step 6: Create final result
        final_result = self._create_scan_result(
            processing_decision, reasoning, document_classification, 
            is_scb_document, allowed_pii, prohibited_pii, metadata, 
            keyword_result, final_primary_classification, filename, content_copyright_result
        )
        
        return final_result
        
    except Exception as e:
        logger.error(f"Error during scanning of {filename}: {str(e)}")
        return self._create_fallback_result(filename, str(e))
        
class DocumentTypeDetector:
    """Utility class to detect document types, especially personal documents"""
    
    @staticmethod
    def _is_legitimate_financial_document(content: str, filename: str) -> bool:
        """Check if document is from legitimate financial institution"""
        content_lower = content.lower()
        filename_lower = filename.lower()
        
        # Major financial institutions
        financial_institutions = [
            'barclays', 'jpmorgan', 'goldman sachs', 'morgan stanley', 'citigroup',
            'bank of america', 'wells fargo', 'hsbc', 'deutsche bank', 'ubs',
            'credit suisse', 'standard chartered', 'bnp paribas', 'societe generale',
            'ing bank', 'santander', 'unicredit', 'royal bank', 'td bank',
            'commonwealth bank', 'westpac', 'anz bank', 'mizuho', 'sumitomo',
            'nomura', 'china construction bank', 'icbc', 'bank of china',
            'hdfc bank', 'icici bank', 'axis bank', 'state bank of india',
            'lloyds banking group', 'natwest', 'blackrock', 'vanguard',
            'fidelity', 'state street', 'invesco', 'allianz'
        ]
        
        # Check for financial institution names
        for institution in financial_institutions:
            if institution in content_lower or institution in filename_lower:
                return True
        
        # Corporate/institutional document indicators
        institutional_indicators = [
            'plc', 'ltd', 'inc', 'corp', 'corporation', 'limited',
            'public limited company', 'securities', 'asset management',
            'investment management', 'institutional investor', 'pension fund',
            'mutual fund', 'hedge fund', 'private equity'
        ]
        
        # Count institutional indicators
        institutional_score = sum(1 for indicator in institutional_indicators if indicator in content_lower)
        
        return institutional_score >= 1

    @staticmethod
    def detect_personal_document_type(content: str, filename: str) -> DocumentClassification:
        """Detect if document is a personal document that should be rejected"""
        content_lower = content.lower()
        filename_lower = filename.lower()
        
        # Check if this is a legitimate financial document first
        is_legitimate_financial = DocumentTypeDetector._is_legitimate_financial_document(content, filename)
        
        # Personal Tax Documents (HIGHEST PRIORITY - Always reject)
        tax_indicators = [
            'form 1040', '1040ez', '1040a', 'individual income tax return',
            'personal tax return', 'filing status:', 'married filing jointly',
            'married filing separately', 'single filer', 'head of household',
            'social security number:', 'spouse ssn:', 'dependent ssn:',
            'adjusted gross income', 'taxable income', 'tax refund',
            'amount you owe', 'federal income tax', 'state income tax',
            'itemized deductions', 'standard deduction', 'personal exemption',
            'child tax credit', 'earned income credit', 'w-2 wages', '1099 income',
            'acknowledgement pdf itr1', 'itr1'
        ]
        
        tax_filename_patterns = ['tax return', '1040', 'income tax', 'personal tax']
        
        tax_score = sum(1 for indicator in tax_indicators if indicator in content_lower)
        tax_filename_score = sum(1 for pattern in tax_filename_patterns if pattern in filename_lower)
        
        if (tax_score >= 1 or tax_filename_score >= 1) and not is_legitimate_financial:
            return DocumentClassification.TAX_SLIP
        
        # Personal Medical Documents
        medical_indicators = [
            'patient name:', 'patient id:', 'date of birth:', 'medical record number:',
            'insurance id:', 'policy number:', 'diagnosis:', 'prescription:',
            'hospital bill', 'medical bill', 'doctor bill', 'pharmacy receipt',
            'patient responsibility:', 'copay:', 'deductible:', 'out-of-pocket:',
            'dear patient', 'appointment with dr.', 'individual health plan'
        ]
        
        medical_score = sum(1 for indicator in medical_indicators if indicator in content_lower)
        if medical_score >= 2 and not is_legitimate_financial:
            return DocumentClassification.HEALTH_BILL
        
        # Personal Banking/Financial Documents
        personal_banking_indicators = [
            'account holder:', 'personal bank statement', 'checking account statement',
            'savings account statement', 'credit card statement', 'personal loan statement',
            'individual brokerage account', 'personal investment account',
            'dear account holder', 'your account summary', 'personal banking'
        ]
        
        personal_banking_score = sum(1 for indicator in personal_banking_indicators if indicator in content_lower)
        if personal_banking_score >= 1 and not is_legitimate_financial:
            return DocumentClassification.PERSONAL_RECEIPT
        
        # Payslips (Personal Employment Documents)
        payslip_indicators = [
            'employee id:', 'pay period:', 'gross pay:', 'net pay:',
            'deductions:', 'tax withholding:', 'year-to-date earnings:',
            'salary slip', 'pay slip', 'payslip', 'wage slip', 'pay stub'
        ]
        
        payslip_score = sum(1 for indicator in payslip_indicators if indicator in content_lower)
        if payslip_score >= 2 and not is_legitimate_financial:
            return DocumentClassification.PAYSLIP
        
        # Restaurant Bills (Personal Expenses)
        restaurant_indicators = [
            'restaurant', 'cafe', 'bistro', 'diner', 'food delivery',
            'meal receipt', 'tip amount:', 'server:', 'table number:',
            'thank you for dining'
        ]
        
        restaurant_score = sum(1 for indicator in restaurant_indicators if indicator in content_lower)
        if restaurant_score >= 2 and not is_legitimate_financial:
            return DocumentClassification.RESTAURANT_BILL
        
        # Personal Receipts
        personal_receipt_indicators = [
            'customer copy', 'receipt number:', 'transaction id:',
            'credit card ending in', 'personal purchase', 'individual customer',
            'thank you for shopping'
        ]
        
        receipt_score = sum(1 for indicator in personal_receipt_indicators if indicator in content_lower)
        if receipt_score >= 2 and not is_legitimate_financial:
            return DocumentClassification.PERSONAL_RECEIPT
        
        
        # Default: Not a personal document
        return DocumentClassification.PUBLIC

    @staticmethod
    def is_personal_document(classification: DocumentClassification) -> bool:
        """Check if document classification indicates a personal document"""
        personal_types = [
            DocumentClassification.HEALTH_BILL,
            DocumentClassification.RESTAURANT_BILL,
            DocumentClassification.MEDICAL_DOCUMENT,
            DocumentClassification.PAYSLIP,
            DocumentClassification.TAX_SLIP,
            DocumentClassification.PERSONAL_RECEIPT
        ]
        return classification in personal_types

class PIIDetector:
    """Rule-based PII detection utility"""
    
    @staticmethod
    def detect_allowed_pii(content: str, filename: str) -> typing.List[AllowedPIICategory]:
        """Detect allowed PII categories in content"""
        content_lower = content.lower()
        filename_lower = filename.lower()
        
        found_categories = []
        
        # Employee Data patterns
        employee_patterns = {
            AllowedPIICategory.EMPLOYEE_ID: [
                'employee id:', 'emp id:', 'staff id:', 'personnel id:'
            ],
            AllowedPIICategory.EMPLOYEE_NAME: [
                'employee name:', 'staff name:', 'employee:', 'personnel:'
            ],
            AllowedPIICategory.EMPLOYEE_LOCATION: [
                'office location:', 'work location:', 'employee location:'
            ],
            AllowedPIICategory.EMPLOYEE_JOB_TITLE: [
                'job title:', 'position:', 'designation:', 'role:'
            ]
        }
        
        # Check employee data
        for category, patterns in employee_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                found_categories.append(category)
        
        # Client/Corporate data patterns
        corporate_patterns = {
            AllowedPIICategory.CLIENT_NAME: [
                'client name:', 'company name:', 'corporation:', 'ltd', 'plc', 'inc'
            ],
            AllowedPIICategory.COUNTRY_OF_INCORPORATION: [
                'incorporated in:', 'country of incorporation:', 'domiciled in:'
            ],
            AllowedPIICategory.INDUSTRY_CLASSIFICATION: [
                'industry:', 'sector:', 'business type:', 'industry classification:'
            ]
        }
        
        # Check corporate data
        for category, patterns in corporate_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                found_categories.append(category)
        
        # Financial information patterns
        financial_patterns = [
            'financial statements', 'balance sheet', 'income statement',
            'cash flow', 'profit and loss', 'financial results', 'earnings'
        ]
        
        if any(pattern in content_lower for pattern in financial_patterns):
            found_categories.append(AllowedPIICategory.FINANCIAL_INFORMATION)
        
        return found_categories if found_categories else [AllowedPIICategory.NONE]
    
    @staticmethod
    def detect_prohibited_pii(content: str, filename: str) -> typing.List[str]:
        """Detect prohibited PII/sensitive information"""
        content_lower = content.lower()
        filename_lower = filename.lower()
        
        prohibited_items = []
        
        # Personal financial data patterns
        personal_financial_patterns = [
            'social security number:', 'ssn:', 'personal account number:',
            'credit card number:', 'personal loan:', 'personal mortgage:',
            'personal savings:', 'checking account:', 'routing number:'
        ]
        
        # Personal identifiers
        personal_id_patterns = [
            'passport number:', 'driver license:', 'national id:',
            'personal tax id:', 'individual tax:', 'pan number:',
            'aadhaar number:', 'personal identification:'
        ]
        
        # Medical/health information
        medical_patterns = [
            'medical record:', 'health information:', 'diagnosis:',
            'prescription:', 'patient id:', 'medical insurance:'
        ]
        
        # Check for prohibited PII
        pattern_categories = {
            'Personal Financial Data': personal_financial_patterns,
            'Personal Identifiers': personal_id_patterns,
            'Medical Information': medical_patterns
        }
        
        for category, patterns in pattern_categories.items():
            if any(pattern in content_lower for pattern in patterns):
                prohibited_items.append(category)
        
        return prohibited_items

class DublinCoreMetadataLoader:
    """Utility class to load and parse Dublin Core metadata"""
    
    @staticmethod
    def load_metadata(metadata_file_path: str) -> DublinCoreMetadata:
        """Load Dublin Core metadata from JSON file"""
        try:
            if os.path.exists(metadata_file_path):
                with open(metadata_file_path, 'r', encoding='utf-8') as f:
                    metadata_dict = json.load(f)
                
                return DublinCoreMetadataLoader.load_metadata_from_dict(metadata_dict)
            else:
                logger.warning(f"Metadata file not found: {metadata_file_path}")
                return DublinCoreMetadata()
                
        except Exception as e:
            logger.error(f"Error loading metadata: {str(e)}")
            return DublinCoreMetadata()
    
    @staticmethod
    def load_metadata_from_dict(metadata_dict: dict) -> DublinCoreMetadata:
        """Load Dublin Core metadata from dictionary"""
        try:
            # Extract nested structures
            dublin_core = metadata_dict.get('dublin_core', {})
            copyright_info = metadata_dict.get('copyright_info', {})
            license_info = metadata_dict.get('license_info', {})
            access_control = metadata_dict.get('access_control', {})
            file_info = metadata_dict.get('file_info', {})
            extraction_metadata = metadata_dict.get('extraction_metadata', {})
            confidence_scores = extraction_metadata.get('confidence_scores', {})
            
            return DublinCoreMetadata(
                # Document identification
                document_id=metadata_dict.get('document_id', ''),
                
                # Standard Dublin Core fields
                title=dublin_core.get('title', ''),
                creator=dublin_core.get('creator', []),
                subject=dublin_core.get('subject', []),
                description=dublin_core.get('description', ''),
                publisher=dublin_core.get('publisher', ''),
                contributor=dublin_core.get('contributor', []),
                date=dublin_core.get('date', ''),
                type=dublin_core.get('type', ''),
                format=dublin_core.get('format', ''),
                language=dublin_core.get('language', ''),
                rights=dublin_core.get('rights', ''),
                
                # Copyright information
                copyright_year=copyright_info.get('copyright_year'),
                copyright_holder=copyright_info.get('copyright_holder', []),
                copyright_status=copyright_info.get('copyright_status', 'Unknown'),
                
                # License information
                license_type=license_info.get('license_type', 'All Rights Reserved'),
                
                # Access control
                access_level=access_control.get('access_level', ''),
                
                # File information
                file_name=file_info.get('file_name', ''),
                file_path=file_info.get('file_path', ''),
                file_size=file_info.get('file_size', 0),
                mime_type=file_info.get('mime_type', ''),
                
                # Extraction metadata
                extraction_confidence=confidence_scores.get('overall', 0.0),
                extraction_date=extraction_metadata.get('extraction_date', ''),
                
                # Custom fields
                earnings_relevance='',
                scb_confidence=0.0
            )
            
        except Exception as e:
            logger.error(f"Error loading metadata from dict: {str(e)}")
            return DublinCoreMetadata()

class EnhancedEarningsContentScanner:
    """Rule-based content scanner with enhanced business rules"""
    
    def __init__(self):
        """Initialize the rule-based scanner"""
        logger.info("Rule-based content scanner initialized")

    def scan_document(self, document_text: str, filename: str = "document", 
                     metadata: DublinCoreMetadata = None) -> EnhancedScanResult:
        """
        Main document scanning function with rule-based business logic
        
        Args:
            document_text (str): Document content
            filename (str): Document filename
            metadata (DublinCoreMetadata): Dublin Core metadata
            
        Returns:
            EnhancedScanResult: Comprehensive scan results
        """
        logger.info(f"Starting rule-based content scan for {filename}")
        
        try:
            # Use provided metadata or create empty one
            if metadata is None:
                metadata = DublinCoreMetadata()
                metadata.file_name = filename
            
            # Enhanced Step 0: Perform content-based copyright detection
            content_copyright_result = ContentCopyrightDetector.detect_copyright_in_content(
                document_text, filename
            )
            
            # PRIORITY RULE 1: Enhanced copyright check - applies to ALL files
            if not self._is_scb_copyright_holder(metadata, content_copyright_result):
                logger.info(f"Non-SCB copyright holder detected: {filename} - REJECTED")
                return self._create_copyright_rejection(filename, metadata, content_copyright_result)
            
            # Step 1: Determine if document belongs to SCB
            is_scb_document = SCBDetectionHelper.detect_scb_comprehensive(
                document_text, filename, metadata
            )
            
            # Step 2: Detect classification keywords with SCB context
            keyword_result = DocumentClassificationKeywordDetector.enhance_classification_detection(
                document_text, filename, metadata.access_level if metadata else "", is_scb_document
            )
            primary_classification = DocumentClassificationKeywordDetector.get_primary_classification(
                keyword_result.keywords_found
            )
            
            # Step 3: Check for personal documents (immediate rejection)
            document_classification = DocumentTypeDetector.detect_personal_document_type(
                document_text, filename
            )
            is_personal = DocumentTypeDetector.is_personal_document(document_classification)
            
            if is_personal:
                logger.info(f"Personal document detected: {filename} - {document_classification.value}")
                return self._create_personal_document_rejection(
                    filename, document_classification, metadata, keyword_result, 
                    primary_classification, is_scb_document, content_copyright_result
                )
            
            # Step 4: Detect PII
            allowed_pii = PIIDetector.detect_allowed_pii(document_text, filename)
            prohibited_pii = PIIDetector.detect_prohibited_pii(document_text, filename)
            
            # Step 5: Apply remaining business rules
            processing_decision, reasoning = self._apply_remaining_business_rules(
                primary_classification, allowed_pii, prohibited_pii, 
                is_scb_document, metadata, filename
            )
            
            # Step 6: Create final result
            final_result = self._create_scan_result(
                processing_decision, reasoning, document_classification, 
                is_scb_document, allowed_pii, prohibited_pii, metadata, 
                keyword_result, primary_classification, filename, content_copyright_result
            )
            
            return final_result
            
        except Exception as e:
            logger.error(f"Error during scanning of {filename}: {str(e)}")
            return self._create_fallback_result(filename, str(e))

    # def _apply_remaining_business_rules(self, primary_classification: str, allowed_pii: typing.List[AllowedPIICategory],
    #                                   prohibited_pii: typing.List[str], is_scb_document: bool, 
    #                                   metadata: DublinCoreMetadata, filename: str) -> typing.Tuple[ProcessingDecision, str]:
    #     """
    #     Apply the remaining business rules after copyright check
        
    #     RULE ORDER (Copyright is RULE 1 - checked first in scan_document):
    #     Rule 1: Enhanced Copyright Check (PRIORITY) - Non-SCB copyright → REJECT  
    #     Rule 2: Classification Check - RESTRICTED or no classification → REJECT
    #     Rule 3: PII Check - Prohibited PII → REJECT, Allowed PII → NEED_APPROVAL
    #     Rule 4: PUBLIC + Non-SCB copyright → REJECT (redundant after Rule 1)
    #     Rule 5: INTERNAL/CONFIDENTIAL + SCB → NEED_APPROVAL
    #     Rule 6: Default → NEED_APPROVAL
    #     """
        
    #     # Rule 2: If RESTRICTED classification or no classification - REJECT
    #     if primary_classification == "RESTRICTED":
    #         return ProcessingDecision.REJECTED, "Document classified as RESTRICTED"
        
    #     if primary_classification == "":
    #         return ProcessingDecision.REJECTED, "No document classification found"
        
    #     # Rule 3: PII/Sensitive information - REJECT
    #     if prohibited_pii:
    #         return ProcessingDecision.REJECTED, f"Prohibited PII detected: {', '.join(prohibited_pii)}"
        
    #     # Rule 3: Any ALLOWED PII Category - NEED_APPROVAL
    #     if allowed_pii and AllowedPIICategory.NONE not in allowed_pii:
    #         return ProcessingDecision.NEEDS_APPROVAL, f"Allowed PII categories detected: {', '.join([pii.value for pii in allowed_pii])}"
        
    #     # Rule 4: If PUBLIC and NON-SCB COPYRIGHT PROTECTED - REJECT
    #     # (Already handled in copyright check, but keeping for completeness)
    #     if primary_classification == "PUBLIC":
    #         if not self._is_scb_copyright_holder_simple(metadata):
    #             return ProcessingDecision.REJECTED, "PUBLIC document with non-SCB copyright holder"
        
    #     # Rule 5: If INTERNAL/CONFIDENTIAL and SCB document - NEED_APPROVAL
    #     if primary_classification in ["INTERNAL", "CONFIDENTIAL"]:
    #         if is_scb_document:
    #             return ProcessingDecision.NEEDS_APPROVAL, f"SCB document with {primary_classification} classification"
    #         else:
    #             return ProcessingDecision.REJECTED, f"Non-SCB document cannot have {primary_classification} classification"
        
    #     # Rule 6: Default - NEED_APPROVAL
    #     return ProcessingDecision.NEEDS_APPROVAL, "Document requires approval per default policy"

    def _apply_remaining_business_rules(self, primary_classification: str, allowed_pii: typing.List[AllowedPIICategory],
                                  prohibited_pii: typing.List[str], is_scb_document: bool, 
                                  metadata: DublinCoreMetadata, filename: str, is_password_protected: bool = False) -> typing.Tuple[ProcessingDecision, str]:
        """
        Modified: Only allow PUBLIC files, reject all others.
        """
        # Reject password-protected files
        if is_password_protected:
            return ProcessingDecision.REJECTED, "Document is password protected (not allowed as PUBLIC)"
        
        # Reject if not PUBLIC
        if primary_classification != "PUBLIC":
            return ProcessingDecision.REJECTED, f"Document classified as {primary_classification or 'UNKNOWN'} (only PUBLIC allowed)"

        # Optionally, you can still check for prohibited PII in PUBLIC files
        if prohibited_pii:
            return ProcessingDecision.REJECTED, f"Prohibited PII detected: {', '.join(prohibited_pii)}"

        # If PUBLIC and no prohibited PII, approve
        return ProcessingDecision.APPROVED, "Document is PUBLIC and passes all checks"

    def _create_copyright_rejection(self, filename: str, metadata: DublinCoreMetadata, 
                                  content_copyright_result: CopyrightDetectionResult) -> EnhancedScanResult:
        """Create rejection result for copyright violations - PRIORITY RULE"""
        # Combine metadata and content copyright holders
        all_copyright_holders = []
        
        if metadata.copyright_holder:
            all_copyright_holders.extend(metadata.copyright_holder)
        
        if content_copyright_result.copyright_holders_from_content:
            all_copyright_holders.extend(content_copyright_result.copyright_holders_from_content)
        
        copyright_holder_text = ''.join(all_copyright_holders) if all_copyright_holders else "Unknown"
        
        # Build detailed copyright concerns
        copyright_concerns = []
        if metadata.copyright_holder:
            copyright_concerns.append(f"Metadata copyright holder: {', '.join(metadata.copyright_holder)}")
        if content_copyright_result.copyright_holders_from_content:
            copyright_concerns.append(f"Content copyright holder: {', '.join(content_copyright_result.copyright_holders_from_content)}")
        if content_copyright_result.copyright_statements:
            copyright_concerns.append(f"Copyright statements found: {len(content_copyright_result.copyright_statements)}")
        
        copyright_concerns.extend([
            "Document violates copyright policy",
            "Only SCB or Unknown copyright holders allowed"
        ])
        
        return EnhancedScanResult(
            processing_decision=ProcessingDecision.REJECTED,
            risk_level=RiskLevel.CRITICAL,
            risk_score=100.0,
            document_classification=DocumentClassification.RESTRICTED,
            is_scb_document=False,
            is_earnings_relevant=False,
            is_personal_document=False,
            copyright_detection_result=content_copyright_result,
            classification_keywords="",
            primary_classification="",
            classification_keyword_confidence=0.0,
            allowed_pii_categories=[AllowedPIICategory.NONE],
            prohibited_pii_found=["Non-SCB copyright holder detected"],
            sensitive_content_found=True,
            copyright_status=CopyrightStatus.COPYRIGHT_INFRINGEMENT,
            copyright_holder=copyright_holder_text,
            copyright_concerns=copyright_concerns,
            earnings_risks=["Copyright infringement risk"],
            compliance_concerns=[
                "Enhanced copyright policy violation",
                "Non-SCB copyrighted content detected in metadata and/or content",
                "Immediate rejection required per copyright rules"
            ],
            dublin_core_metadata=metadata,
            recommendations=[
                "Remove document from system immediately",
                "Only upload documents with SCB or Unknown copyright",
                "Contact legal team for copyright guidance"
            ],
            required_approvals=[],
            redaction_required=False,
            scan_timestamp=datetime.now().isoformat(),
            confidence_score=100.0,
            reasoning=f"PRIORITY RULE 1 VIOLATION: Non-SCB copyright holder detected - {copyright_holder_text}",
            filename=filename
        )

    def _is_scb_copyright_holder(self, metadata: DublinCoreMetadata, 
                                content_copyright_result: CopyrightDetectionResult = None) -> bool:
        """
        Enhanced PRIORITY CHECK: Verify if copyright holder is SCB or Unknown
        This checks both metadata and content-based copyright detection
        """
        # Check metadata copyright holders
        metadata_acceptable = self._is_scb_copyright_holder_simple(metadata)
        
        # If no content copyright result provided, rely on metadata only
        if not content_copyright_result:
            return metadata_acceptable
        
        # If content copyright found, check if it's acceptable
        if content_copyright_result.copyright_found_in_content:
            content_acceptable = self._check_content_copyright_holders(
                content_copyright_result.copyright_holders_from_content
            )
            
            # If both metadata and content have copyright info, both must be acceptable
            if metadata and metadata.copyright_holder and metadata.copyright_holder[0].strip():
                return metadata_acceptable and content_acceptable
            else:
                # If no metadata copyright but content copyright found, check content only
                return content_acceptable
        
        # If no content copyright found, rely on metadata check
        return metadata_acceptable

    def _is_scb_copyright_holder_simple(self, metadata: DublinCoreMetadata) -> bool:
        """
        Simple metadata-only copyright holder check (original logic)
        """
        if not metadata:
            logger.warning("No metadata provided - treating as acceptable (Unknown copyright)")
            return True  # No metadata = Unknown = acceptable
        
        if not metadata.copyright_holder or len(metadata.copyright_holder) == 0:
            logger.info("No copyright holder specified - treating as Unknown (acceptable)")
            return True  # Empty/None = Unknown = acceptable
        
        # Join all copyright holders into a single string for analysis
        copyright_holders_text = ' '.join(metadata.copyright_holder).lower().strip()
        
        # If completely empty after joining, treat as Unknown
        if not copyright_holders_text:
            logger.info("Empty copyright holder after processing - treating as Unknown (acceptable)")
            return True
        
        return self._check_copyright_holder_text(copyright_holders_text)

    def _check_content_copyright_holders(self, content_copyright_holders: typing.List[str]) -> bool:
        """
        Check if content-based copyright holders are acceptable
        """
        if not content_copyright_holders:
            return True  # No content copyright holders = acceptable
        
        for holder in content_copyright_holders:
            holder_text = holder.lower().strip()
            if not self._check_copyright_holder_text(holder_text):
                logger.warning(f"Non-SCB content copyright holder detected: {holder}")
                return False
        
        return True

    def _check_copyright_holder_text(self, copyright_holder_text: str) -> bool:
        """
        Check if a single copyright holder text is acceptable
        """
        # Define acceptable copyright holders (case-insensitive)
        acceptable_holders = [
            'standard chartered',
            'standard chartered bank', 
            'scb',
            'standard chartered plc',
            'standardchartered',
            'standard chartered (singapore)',
            'standard chartered malaysia',
            'standard chartered india',
            'standard chartered hong kong',
            'unknown',
            'not specified',
            'n/a',
            'na'
        ]
        
        # Check if any acceptable holder is found
        for acceptable in acceptable_holders:
            if acceptable in copyright_holder_text:
                logger.info(f"Acceptable copyright holder found: {acceptable}")
                return True
        
        # If we reach here, copyright holder is not acceptable
        logger.warning(f"Non-SCB copyright holder detected: {copyright_holder_text}")
        return False

    def _create_personal_document_rejection(self, filename: str, document_classification: DocumentClassification, 
                                          metadata: DublinCoreMetadata, keyword_result: ClassificationKeywordResult,
                                          primary_classification: str, is_scb_document: bool,
                                          content_copyright_result: CopyrightDetectionResult) -> EnhancedScanResult:
        """Create rejection result for personal documents"""
        return EnhancedScanResult(
            processing_decision=ProcessingDecision.REJECTED,
            risk_level=RiskLevel.HIGH,
            risk_score=95.0,
            document_classification=document_classification,
            is_scb_document=is_scb_document,
            is_earnings_relevant=False,
            is_personal_document=True,
            copyright_detection_result=content_copyright_result,
            classification_keywords=keyword_result.keywords_string,
            primary_classification=primary_classification,
            classification_keyword_confidence=keyword_result.classification_confidence,
            allowed_pii_categories=[AllowedPIICategory.NONE],
            prohibited_pii_found=[f"Personal document detected: {document_classification.value}"],
            sensitive_content_found=True,
            copyright_status=CopyrightStatus.UNKNOWN,
            copyright_holder="Unknown",
            copyright_concerns=["Personal document - processing not allowed"],
            earnings_risks=[],
            compliance_concerns=["Personal document violates data processing policy"],
            dublin_core_metadata=metadata,
            recommendations=["Remove personal document from system"],
            required_approvals=[],
            redaction_required=False,
            scan_timestamp=datetime.now().isoformat(),
            confidence_score=100.0,
            reasoning=f"Personal document rejected: {document_classification.value}",
            filename=filename
        )

    def _create_scan_result(self, processing_decision: ProcessingDecision, reasoning: str,
                          document_classification: DocumentClassification, is_scb_document: bool,
                          allowed_pii: typing.List[AllowedPIICategory], prohibited_pii: typing.List[str],
                          metadata: DublinCoreMetadata, keyword_result: ClassificationKeywordResult,
                          primary_classification: str, filename: str,
                          content_copyright_result: CopyrightDetectionResult) -> EnhancedScanResult:
        """Create comprehensive scan result"""
        
        # Determine risk level based on decision
        if processing_decision == ProcessingDecision.REJECTED:
            risk_level = RiskLevel.HIGH
            risk_score = 85.0
        elif processing_decision == ProcessingDecision.NEEDS_APPROVAL:
            risk_level = RiskLevel.MEDIUM
            risk_score = 60.0
        else:
            risk_level = RiskLevel.LOW
            risk_score = 25.0
        
        # Determine copyright status
        copyright_status = CopyrightStatus.UNKNOWN
        if metadata.copyright_status == "Public Domain":
            copyright_status = CopyrightStatus.PUBLIC_DOMAIN
        elif metadata.copyright_status == "Copyrighted":
            copyright_status = CopyrightStatus.COPYRIGHTED
        
        # Build enhanced copyright holder information
        all_copyright_holders = []
        if metadata.copyright_holder:
            all_copyright_holders.extend(metadata.copyright_holder)
        if content_copyright_result and content_copyright_result.copyright_holders_from_content:
            all_copyright_holders.extend(content_copyright_result.copyright_holders_from_content)
        
        copyright_holder_text = ', '.join(all_copyright_holders) if all_copyright_holders else "Unknown"
        
        # Build recommendations
        recommendations = []
        if processing_decision == ProcessingDecision.NEEDS_APPROVAL:
            recommendations.append("Document requires manual approval")
        if prohibited_pii:
            recommendations.append("Remove or redact prohibited PII")
        
        # Build required approvals
        required_approvals = []
        if processing_decision == ProcessingDecision.NEEDS_APPROVAL:
            if allowed_pii and AllowedPIICategory.NONE not in allowed_pii:
                required_approvals.append("PII Review")
            if not self._is_scb_copyright_holder_simple(metadata):
                required_approvals.append("Copyright Review")
            required_approvals.append("Content Approval")
        
        return EnhancedScanResult(
            processing_decision=processing_decision,
            risk_level=risk_level,
            risk_score=risk_score,
            document_classification=document_classification,
            is_scb_document=is_scb_document,
            is_earnings_relevant=False,  # As requested, always False
            is_personal_document=False,
            copyright_detection_result=content_copyright_result,
            classification_keywords=keyword_result.keywords_string,
            primary_classification=primary_classification,
            classification_keyword_confidence=keyword_result.classification_confidence,
            allowed_pii_categories=allowed_pii,
            prohibited_pii_found=prohibited_pii,
            sensitive_content_found=len(prohibited_pii) > 0,
            copyright_status=copyright_status,
            copyright_holder=copyright_holder_text,
            copyright_concerns=[],
            earnings_risks=[],
            compliance_concerns=[],
            dublin_core_metadata=metadata,
            recommendations=recommendations,
            required_approvals=required_approvals,
            redaction_required=len(prohibited_pii) > 0,
            scan_timestamp=datetime.now().isoformat(),
            confidence_score=100.0,  # Rule-based = high confidence
            reasoning=reasoning,
            filename=filename
        )

    def _create_fallback_result(self, filename: str, error_msg: str) -> EnhancedScanResult:
        """Create fallback result when analysis fails"""
        return EnhancedScanResult(
            processing_decision=ProcessingDecision.REJECTED,
            risk_level=RiskLevel.CRITICAL,
            risk_score=100.0,
            document_classification=DocumentClassification.RESTRICTED,
            is_scb_document=False,
            is_earnings_relevant=False,
            is_personal_document=False,
            copyright_detection_result=None,
            classification_keywords="",
            primary_classification="",
            classification_keyword_confidence=0.0,
            allowed_pii_categories=[AllowedPIICategory.NONE],
            prohibited_pii_found=[f"Analysis failed: {error_msg}"],
            sensitive_content_found=True,
            copyright_status=CopyrightStatus.UNKNOWN,
            copyright_holder="Unknown",
            copyright_concerns=["Unable to assess"],
            earnings_risks=["Analysis failure"],
            compliance_concerns=["Automated scan failed"],
            dublin_core_metadata=DublinCoreMetadata(),
            recommendations=["Manual review required"],
            required_approvals=["Manual Review"],
            redaction_required=True,
            scan_timestamp=datetime.now().isoformat(),
            confidence_score=0.0,
            reasoning=f"Scan failed: {error_msg}",
            filename=filename
        )

# Utility functions for printing and exporting results
def print_enhanced_scan_results(scan_result: EnhancedScanResult) -> None:
    """Pretty print enhanced scan results to console"""
    print(f"\n{'='*80}")
    print(f"🤖 RULE-BASED CONTENT SCAN RESULTS")
    print(f"📄 Document: {scan_result.filename}")
    print(f"🆔 Document ID: {scan_result.dublin_core_metadata.document_id}")
    print(f"{'='*80}")
    
    # Decision and Risk Level
    decision_emoji = {
        ProcessingDecision.APPROVED: "✅",
        ProcessingDecision.NEEDS_APPROVAL: "⚠️",
        ProcessingDecision.REJECTED: "🚫"
    }
    
    risk_emoji = {
        RiskLevel.LOW: "🟢",
        RiskLevel.MEDIUM: "🟡", 
        RiskLevel.HIGH: "🟠",
        RiskLevel.CRITICAL: "🔴"
    }
    
    print(f"🎯 Processing Decision: {decision_emoji.get(scan_result.processing_decision, '❓')} {scan_result.processing_decision.value}")
    print(f"📊 Risk Level: {risk_emoji.get(scan_result.risk_level, '❓')} {scan_result.risk_level.value} (Score: {scan_result.risk_score:.1f}/100)")
    print(f"📋 Document Classification: {scan_result.document_classification.value}")
    print(f"🏦 SCB Document: {'✅ YES' if scan_result.is_scb_document else '❌ NO'}")
    print(f"👤 Personal Document: {'⚠️ YES' if scan_result.is_personal_document else '✅ NO'}")
    print(f"📜 Copyright Status: {scan_result.copyright_status.value}")
    print(f"⏰ Scan Time: {scan_result.scan_timestamp}")
    
    # PRIORITY: Enhanced Copyright Information (Rule 1)
    print(f"\n©️ ENHANCED COPYRIGHT ANALYSIS (PRIORITY RULE 1):")
    print(f"   📋 Copyright Holder: {scan_result.copyright_holder}")
    print(f"   🎯 SCB Copyright: {'✅ VALID' if scan_result.copyright_status != CopyrightStatus.COPYRIGHT_INFRINGEMENT else '🚫 INVALID'}")
    
    # Content-based copyright detection results
    if scan_result.copyright_detection_result:
        cr = scan_result.copyright_detection_result
        print(f"   🔍 Content Copyright Found: {'✅ YES' if cr.copyright_found_in_content else '❌ NO'}")
        if cr.copyright_holders_from_content:
            print(f"   📄 Content Copyright Holders: {', '.join(cr.copyright_holders_from_content)}")
        if cr.copyright_statements:
            print(f"   📝 Copyright Statements Found: {len(cr.copyright_statements)}")
            for i, stmt in enumerate(cr.copyright_statements[:3], 1):  # Show first 3
                print(f"      {i}. {stmt[:100]}...")
        print(f"   📊 Content Copyright Confidence: {cr.content_copyright_confidence:.1f}%")
    
    if scan_result.copyright_concerns:
        print(f"   ⚠️ Copyright Concerns:")
        for concern in scan_result.copyright_concerns:
            print(f"      • {concern}")
    
    # Classification Keywords section
    print(f"\n🏷️  CLASSIFICATION KEYWORDS:")
    if scan_result.classification_keywords:
        print(f"   📋 Keywords Found: {scan_result.classification_keywords}")
        print(f"   🎯 Primary Classification: {scan_result.primary_classification}")
        print(f"   📊 Keyword Confidence: {scan_result.classification_keyword_confidence:.1f}%")
    else:
        print(f"   ❌ No classification keywords detected")
    
    # Metadata Information
    print(f"\n📋 DUBLIN CORE METADATA:")
    print(f"   • Access Level: {scan_result.dublin_core_metadata.access_level}")
    print(f"   • Creator(s): {', '.join(scan_result.dublin_core_metadata.creator) if scan_result.dublin_core_metadata.creator else 'Unknown'}")
    print(f"   • Publisher: {scan_result.dublin_core_metadata.publisher or 'Unknown'}")
    
    # PII Information
    print(f"\n🆔 PII ANALYSIS:")
    print(f"   ✅ Allowed PII Categories:")
    for category in scan_result.allowed_pii_categories:
        print(f"      • {category.value}")
    
    if scan_result.prohibited_pii_found:
        print(f"   🚫 Prohibited PII Found:")
        for pii in scan_result.prohibited_pii_found:
            print(f"      • {pii}")
    
    # Required approvals
    if scan_result.required_approvals:
        print(f"\n📝 REQUIRED APPROVALS:")
        for approval in scan_result.required_approvals:
            print(f"   • {approval}")
    
    # Recommendations
    if scan_result.recommendations:
        print(f"\n💡 RECOMMENDATIONS:")
        for recommendation in scan_result.recommendations:
            print(f"   • {recommendation}")
    
    # Analysis reasoning
    print(f"\n🧠 REASONING:")
    print(f"   {scan_result.reasoning}")
    
    print(f"{'='*80}\n")

def integrate_enhanced_content_scanning(document_text: str, filename: str, 
                                      metadata_file_path: str = None, 
                                      metadata_dict: dict = None) -> typing.Tuple[bool, EnhancedScanResult]:
    """
    Integration function for rule-based content scanning
    
    Args:
        document_text (str): Document content to scan
        filename (str): Document filename
        metadata_file_path (str): Path to Dublin Core metadata JSON file
        metadata_dict (dict): Alternative - metadata as dictionary
        
    Returns:
        Tuple[bool, EnhancedScanResult]: (should_proceed, scan_result)
    """
    try:
        # Initialize rule-based scanner
        scanner = EnhancedEarningsContentScanner()
        
        # Load metadata from file or dict
        if metadata_dict:
            # Update metadata_dict to include the filename if not present
            if 'file_info' not in metadata_dict:
                metadata_dict['file_info'] = {}
            if 'file_name' not in metadata_dict['file_info']:
                metadata_dict['file_info']['file_name'] = filename
                
            metadata = DublinCoreMetadataLoader.load_metadata_from_dict(metadata_dict)
        else:
            metadata = DublinCoreMetadataLoader.load_metadata(metadata_file_path) if metadata_file_path else DublinCoreMetadata()
            if not metadata.file_name:
                metadata.file_name = filename
        
        # Perform rule-based scan
        scan_result = scanner.scan_document(document_text, filename, metadata)
        
        # Print results to console
        print_enhanced_scan_results(scan_result)
        
        # Determine if processing should proceed automatically
        should_proceed = scan_result.processing_decision == ProcessingDecision.APPROVED
        
        # Enhanced logging
        logger.info(f"Rule-based scan completed for {filename}:")
        logger.info(f"  - Decision: {scan_result.processing_decision.value}")
        logger.info(f"  - Copyright Holder: {scan_result.copyright_holder}")
        logger.info(f"  - Copyright Valid: {scan_result.copyright_status != CopyrightStatus.COPYRIGHT_INFRINGEMENT}")
        logger.info(f"  - Content Copyright Found: {scan_result.copyright_detection_result.copyright_found_in_content if scan_result.copyright_detection_result else 'N/A'}")
        logger.info(f"  - Classification Keywords: {scan_result.classification_keywords}")
        logger.info(f"  - Primary Classification: {scan_result.primary_classification}")
        logger.info(f"  - SCB Document: {scan_result.is_scb_document}")
        logger.info(f"  - Personal Document: {scan_result.is_personal_document}")
        logger.info(f"  - Reasoning: {scan_result.reasoning}")
        
        return should_proceed, scan_result
    
    except Exception as e:
        logger.error(f"Rule-based content scanning failed for {filename}: {str(e)}")
        raise Exception(f"Rule-based content scanning failed: {str(e)}")

def get_classification_keywords_for_database(scan_result: EnhancedScanResult) -> typing.Tuple[str, str, float]:
    """Extract classification keyword data for database storage"""
    return (
        scan_result.classification_keywords or "",
        scan_result.primary_classification or "", 
        scan_result.classification_keyword_confidence or 0.0
    )

def export_enhanced_scan_results(scan_result: EnhancedScanResult, output_file: str = None) -> str:
    """Export enhanced scan results to JSON file for audit/compliance purposes"""
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = scan_result.filename.replace('.', '_').replace('/', '_')
        output_file = f"rule_based_scan_results_{safe_filename}_{timestamp}.json"
    
    # Convert to dictionary and handle enums
    result_dict = asdict(scan_result)
    result_dict['processing_decision'] = scan_result.processing_decision.value
    result_dict['risk_level'] = scan_result.risk_level.value
    result_dict['document_classification'] = scan_result.document_classification.value
    result_dict['copyright_status'] = scan_result.copyright_status.value
    result_dict['allowed_pii_categories'] = [cat.value for cat in scan_result.allowed_pii_categories]
    
    # Add classification keywords data for database integration
    keywords_str, primary_classification, confidence = get_classification_keywords_for_database(scan_result)
    result_dict['database_fields'] = {
        'DC_CLASSIFICATION': keywords_str,
        'DC_PRIMARY_CLASSIFICATION': primary_classification,
        'DC_CLASSIFICATION_CONFIDENCE': confidence
    }
    
    json_result = json.dumps(result_dict, indent=2, ensure_ascii=False)
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json_result)
        logger.info(f"Rule-based scan results exported to {output_file}")
    except Exception as e:
        logger.error(f"Failed to export scan results: {str(e)}")
    
    return json_result