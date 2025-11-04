from logger_setup import get_logger
from typing import Tuple, List
import re
from datetime import datetime

logger = get_logger()

def format_documents(docs):
    """Format retrieved documents into a single string with metadata."""
    logger.info(f"Formatting {len(docs)} documents")
    formatted = "\n\n".join(
        f"{doc.page_content} (Source: {doc.metadata.get('file_name', 'Unknown')}, Page: {doc.metadata.get('Page', 'Unknown')})"
        for doc in docs
    )
    logger.debug(f"Documents formatted, total length: {len(formatted)} characters")
    return formatted


def normalize_quarters(query: str) -> Tuple[str, List[int]]:
    """
    Normalize quarter-year expressions like 'Q12222' or 'Q1 22' into 'Q1 2022'.
    Also return a list of suspicious (future) years if any are found.
    """
    suspicious_years = []

    def replacer(match):
        q = match.group(1).upper()
        y = match.group(2)
        try:
            year = int(y)
            # if year < 100:
            #     year += 2000
            # if year > datetime.now().year + 1:
            # Only allow 4-digit years in a valid range (e.g., 2010 to current year + 1)
            current_year = datetime.now().year
            if len(y) == 2:
                year += 2000
            if year < 2010 or year > current_year + 1:
                logger.warning(f"Suspicious year detected: {year} in '{match.group(0)}'")
                suspicious_years.append(year)
                return match.group(0)  # Don't normalize, just record
            return f"{q} {year}"
        except Exception as e:
            logger.warning(f"Failed to normalize '{match.group(0)}': {e}")
            return match.group(0)

    # query = re.sub(r"(Q[1-4])([0-9]{2,4})", replacer, query, flags=re.IGNORECASE)
    # query = re.sub(r"\b(Q[1-4])\s+([0-9]{2,4})\b", replacer, query, flags=re.IGNORECASE)
    # return query, suspicious_years
        # Step 1: Convert 1Q -> Q1 format for consistency
    query = re.sub(r"\b([1-4])Q\s*([0-9]{2,})\b", lambda m: f"Q{m.group(1)} {m.group(2)}", query, flags=re.IGNORECASE)
    query = re.sub(r"\b([1-4])Q([0-9]{2,})\b", lambda m: f"Q{m.group(1)} {m.group(2)}", query, flags=re.IGNORECASE)

    # Step 2: Normalize Q1-style quarters
    query = re.sub(r"\b(Q[1-4])\s*([0-9]{2,})\b", replacer, query, flags=re.IGNORECASE)

    return query, suspicious_years


def parse_query(query: str) -> Tuple[str, List[str], List[int]]:
    """Identify analysis types and clean the query."""
    logger.info(f"Parsing analysis request: '{query}'")
    normalized_query, suspicious_years = normalize_quarters(query)
    query_lower = normalized_query.lower()

    analysis_terms = {
        "general": ["summarize", "summary", "summarization"],
        "financial": ["finance", "financial", "revenue", "profit", "earnings", "income",
                      "balance sheet", "impairments", "highlights"],
        "trend": ["trend", "trends", "growth", "decline", "change over time", "outlook"],
        "topics": ["topics", "themes", "breakdown", "categorize", "categorization",
                   "topic breakdown", "topic analysis"],
        "quotes": ["quote", "quotes", "statement", "statements"],
        "callouts": ["callouts", "major callouts"],
        "consensus": ["consensus"],
        "stock": ["stock", "share price analysis"]
    }

    detected_types = []
    for analysis_type, terms in analysis_terms.items():
        for term in terms:
            if term in query_lower:
                if analysis_type not in detected_types:
                    detected_types.append(analysis_type)

    if not detected_types:
        logger.info("No specific analysis type detected, defaulting to 'general'")
        detected_types = ["general"]

    # ✅ Do not strip keywords; just clean spaces
    cleaned_query = re.sub(r"\s+", " ", normalized_query).strip()

    logger.info(f"Detected analysis types: {detected_types}, cleaned query='{cleaned_query}'")
    logger.debug(f"Normalized query for analysis: '{query}' → '{cleaned_query}'")
    return cleaned_query, detected_types, suspicious_years
    
# def parse_query(query: str) -> Tuple[str, List[str], List[int]]:
#     """Identify analysis types and clean the query."""
#     logger.info(f"Parsing analysis request: '{query}'")
#     query, suspicious_years = normalize_quarters(query)
#     query_lower = query.lower()
#     # query_lower = query.lower()
#     analysis_terms = {
#         "general": ["summarize", "summary", "summarization"],
#         "financial": ["finance", "financial", "revenue", "profit", "earnings", "income", "balance sheet", "impairments", "highlights"],
#         "trend": ["trend", "trends", "growth", "decline", "change over time", "outlook"],
#         "topics": ["topics", "themes", "breakdown", "categorize", "categorization", "topic breakdown", "topic analysis"],
#         "quotes": ["quote", "quotes", "statement", "statements"],
#         "callouts": ["callouts", "major callouts"],
#         "consensus": ["consensus"],
#         "Stock": ["Stock, Share Price Analysis"]
#     }
#     detected_types = []
#     for analysis_type, terms in analysis_terms.items():
#         for term in terms:
#             if term in query_lower and len(term.split()) > 1:
#                 if analysis_type not in detected_types:
#                     detected_types.append(analysis_type)
#     if not detected_types:
#         for analysis_type, terms in analysis_terms.items():
#             if any(term in query_lower.split() for term in terms if len(term.split()) == 1):
#                 if analysis_type not in detected_types:
#                     detected_types.append(analysis_type)
#     if not detected_types:
#         logger.info("No specific analysis type detected, defaulting to 'general'")
#         return query, ["general"], suspicious_years
#     cleaned_query = query
#     for term in sum(analysis_terms.values(), []):
#         cleaned_query = cleaned_query.replace(term, "").strip()
#     logger.info(f"Detected analysis types: {detected_types}, cleaned query='{cleaned_query}'")
#     logger.debug(f"Normalized query for analysis: '{query}' → '{cleaned_query}'")
#     return cleaned_query, detected_types, suspicious_years
