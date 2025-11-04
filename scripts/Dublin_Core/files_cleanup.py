import os
import shutil
import logging
from pathlib import Path
from typing import List, Optional, Union

logger = logging.getLogger(__name__)

def cleanup_intermediary_files(output_folder: str = "./output", 
                             specific_files: Optional[List[str]] = None,
                             file_patterns: Optional[List[str]] = None,
                             keep_summary: bool = True,
                             dry_run: bool = False) -> dict[str, any]:
    """
    Clean up intermediary files generated during document processing.
    
    Args:
        output_folder (str): Path to output folder to clean (default: "./output")
        specific_files (List[str], optional): List of specific file paths to delete
        file_patterns (List[str], optional): List of file patterns to match for deletion
                                           (e.g., ["*_metadata.json", "*_scan_results.json"])
        keep_summary (bool): Whether to keep summary report files (default: True)
        dry_run (bool): If True, only show what would be deleted without actually deleting
        
    Returns:
        Dict with cleanup results
    """
    cleanup_result = {
        "status": "SUCCESS",
        "files_deleted": [],
        "files_kept": [],
        "errors": [],
        "total_deleted": 0,
        "total_kept": 0,
        "space_freed": 0
    }
    
    try:
        output_path = Path(output_folder)
        
        if not output_path.exists():
            cleanup_result["status"] = "SKIPPED"
            cleanup_result["errors"].append(f"Output folder does not exist: {output_folder}")
            return cleanup_result
        
        # Default patterns for intermediary files
        default_patterns = [
            "*_metadata.json",
            "*_metadata.ttl", 
            "*_scan_results.json"
        ]
        
        # Use provided patterns or default ones
        patterns_to_delete = file_patterns or default_patterns
        
        # Files to keep patterns (when keep_summary is True)
        keep_patterns = ["*_summary_report.json"] if keep_summary else []
        
        logger.info(f"Starting cleanup of {output_folder}")
        if dry_run:
            logger.info("DRY RUN MODE - No files will be actually deleted")
        
        # Process specific files if provided
        if specific_files:
            for file_path in specific_files:
                file_obj = Path(file_path)
                if file_obj.exists() and file_obj.is_file():
                    try:
                        file_size = file_obj.stat().st_size
                        
                        # Check if file should be kept
                        should_keep = False
                        if keep_summary:
                            for keep_pattern in keep_patterns:
                                if file_obj.match(keep_pattern):
                                    should_keep = True
                                    break
                        
                        if should_keep:
                            cleanup_result["files_kept"].append(str(file_path))
                            cleanup_result["total_kept"] += 1
                            logger.info(f"Keeping file: {file_path}")
                        else:
                            if not dry_run:
                                file_obj.unlink()
                            cleanup_result["files_deleted"].append(str(file_path))
                            cleanup_result["total_deleted"] += 1
                            cleanup_result["space_freed"] += file_size
                            logger.info(f"{'Would delete' if dry_run else 'Deleted'} file: {file_path}")
                            
                    except Exception as e:
                        error_msg = f"Error deleting {file_path}: {str(e)}"
                        cleanup_result["errors"].append(error_msg)
                        logger.error(error_msg)
        
        # Process files by patterns
        for pattern in patterns_to_delete:
            for file_path in output_path.glob(pattern):
                if file_path.is_file():
                    try:
                        file_size = file_path.stat().st_size
                        
                        # Check if file should be kept
                        should_keep = False
                        if keep_summary:
                            for keep_pattern in keep_patterns:
                                if file_path.match(keep_pattern):
                                    should_keep = True
                                    break
                        
                        if should_keep:
                            cleanup_result["files_kept"].append(str(file_path))
                            cleanup_result["total_kept"] += 1
                            logger.info(f"Keeping file: {file_path}")
                        else:
                            if not dry_run:
                                file_path.unlink()
                            cleanup_result["files_deleted"].append(str(file_path))
                            cleanup_result["total_deleted"] += 1
                            cleanup_result["space_freed"] += file_size
                            logger.info(f"{'Would delete' if dry_run else 'Deleted'} file: {file_path}")
                            
                    except Exception as e:
                        error_msg = f"Error deleting {file_path}: {str(e)}"
                        cleanup_result["errors"].append(error_msg)
                        logger.error(error_msg)
        
        # Summary
        if cleanup_result["errors"]:
            cleanup_result["status"] = "PARTIAL_SUCCESS"
        
        space_freed_mb = cleanup_result["space_freed"] / (1024 * 1024)
        logger.info(f"Cleanup completed - {'Would delete' if dry_run else 'Deleted'}: {cleanup_result['total_deleted']} files, "
                   f"Kept: {cleanup_result['total_kept']} files, "
                   f"Space freed: {space_freed_mb:.2f} MB")
        
        # Print summary
        _print_cleanup_summary(cleanup_result, dry_run)
        
    except Exception as e:
        cleanup_result["status"] = "FAILED"
        cleanup_result["errors"].append(f"Cleanup failed: {str(e)}")
        logger.error(f"Cleanup failed: {str(e)}")
    
    return cleanup_result

def cleanup_specific_document_files(filename: str, 
                                  output_folder: str = "./output",
                                  keep_summary: bool = True,
                                  dry_run: bool = False) -> dict[str, any]:
    """
    Clean up files generated for a specific document.
    
    Args:
        filename (str): Original filename to clean up files for
        output_folder (str): Path to output folder (default: "./output")
        keep_summary (bool): Whether to keep summary report files (default: True)
        dry_run (bool): If True, only show what would be deleted without actually deleting
        
    Returns:
        Dict with cleanup results
    """
    # Get base filename without extension
    base_name = Path(filename).stem
    
    # Generate patterns for this specific document
    patterns = [
        f"{base_name}_metadata.json",
        f"{base_name}_metadata.ttl",
        f"{base_name}_scan_results.json"
    ]
    
    if not keep_summary:
        patterns.append(f"{base_name}_summary_report.json")
    
    return cleanup_intermediary_files(
        output_folder=output_folder,
        file_patterns=patterns,
        keep_summary=keep_summary,
        dry_run=dry_run
    )

def cleanup_all_output_files(output_folder: str = "./output", 
                           keep_summary: bool = False,
                           dry_run: bool = False) -> dict[str, any]:
    """
    Clean up ALL files in the output folder.
    
    Args:
        output_folder (str): Path to output folder (default: "./output")
        keep_summary (bool): Whether to keep summary report files (default: False)
        dry_run (bool): If True, only show what would be deleted without actually deleting
        
    Returns:
        Dict with cleanup results
    """
    cleanup_result = {
        "status": "SUCCESS",
        "files_deleted": [],
        "files_kept": [],
        "errors": [],
        "total_deleted": 0,
        "total_kept": 0,
        "space_freed": 0
    }
    
    try:
        output_path = Path(output_folder)
        
        if not output_path.exists():
            cleanup_result["status"] = "SKIPPED"
            cleanup_result["errors"].append(f"Output folder does not exist: {output_folder}")
            return cleanup_result
        
        # Keep patterns (when keep_summary is True)
        keep_patterns = ["*_summary_report.json"] if keep_summary else []
        
        logger.info(f"Starting complete cleanup of {output_folder}")
        if dry_run:
            logger.info("DRY RUN MODE - No files will be actually deleted")
        
        # Process all files in output folder
        for file_path in output_path.iterdir():
            if file_path.is_file():
                try:
                    file_size = file_path.stat().st_size
                    
                    # Check if file should be kept
                    should_keep = False
                    if keep_summary:
                        for keep_pattern in keep_patterns:
                            if file_path.match(keep_pattern):
                                should_keep = True
                                break
                    
                    if should_keep:
                        cleanup_result["files_kept"].append(str(file_path))
                        cleanup_result["total_kept"] += 1
                        logger.info(f"Keeping file: {file_path}")
                    else:
                        if not dry_run:
                            file_path.unlink()
                        cleanup_result["files_deleted"].append(str(file_path))
                        cleanup_result["total_deleted"] += 1
                        cleanup_result["space_freed"] += file_size
                        logger.info(f"{'Would delete' if dry_run else 'Deleted'} file: {file_path}")
                        
                except Exception as e:
                    error_msg = f"Error deleting {file_path}: {str(e)}"
                    cleanup_result["errors"].append(error_msg)
                    logger.error(error_msg)
        
        # Summary
        if cleanup_result["errors"]:
            cleanup_result["status"] = "PARTIAL_SUCCESS"
        
        space_freed_mb = cleanup_result["space_freed"] / (1024 * 1024)
        logger.info(f"Complete cleanup finished - {'Would delete' if dry_run else 'Deleted'}: {cleanup_result['total_deleted']} files, "
                   f"Kept: {cleanup_result['total_kept']} files, "
                   f"Space freed: {space_freed_mb:.2f} MB")
        
        # Print summary
        _print_cleanup_summary(cleanup_result, dry_run)
        
    except Exception as e:
        cleanup_result["status"] = "FAILED"
        cleanup_result["errors"].append(f"Complete cleanup failed: {str(e)}")
        logger.error(f"Complete cleanup failed: {str(e)}")
    
    return cleanup_result

def _print_cleanup_summary(cleanup_result: dict[str, any], dry_run: bool = False) -> None:
    """Print cleanup summary"""
    print(f"\n{'='*50}")
    print(f"🧹 CLEANUP SUMMARY {'(DRY RUN)' if dry_run else ''}")
    print(f"{'='*50}")
    
    status_emoji = {
        "SUCCESS": "✅",
        "PARTIAL_SUCCESS": "⚠️",
        "FAILED": "❌",
        "SKIPPED": "⏭️"
    }
    
    print(f"{status_emoji.get(cleanup_result['status'], '❓')} Status: {cleanup_result['status']}")
    print(f"🗑️  Files {'to delete' if dry_run else 'deleted'}: {cleanup_result['total_deleted']}")
    print(f"📄 Files kept: {cleanup_result['total_kept']}")
    
    if cleanup_result['space_freed'] > 0:
        space_mb = cleanup_result['space_freed'] / (1024 * 1024)
        print(f"💾 Space {'to free' if dry_run else 'freed'}: {space_mb:.2f} MB")
    
    if cleanup_result['errors']:
        print(f"⚠️  Errors: {len(cleanup_result['errors'])}")
        for error in cleanup_result['errors'][:3]:  # Show first 3 errors
            print(f"   • {error}")
        if len(cleanup_result['errors']) > 3:
            print(f"   ... and {len(cleanup_result['errors']) - 3} more errors")
    
    print(f"{'='*50}\n")