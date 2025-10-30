# AI Fix Tool - Generates patches for IaC security issues

import os
import re
import logging
from pathlib import Path
from typing import List, Optional

from ..schemas import AIFixInput, AIFixResponse, PatchSpec, PatchOperation

logger = logging.getLogger(__name__)

def generate_patch_for_overly_permissive_sg(content: str, file_path: str) -> Optional[PatchSpec]:
    """Generate patch to fix overly permissive security group CIDR blocks"""
    if "0.0.0.0/0" not in content:
        return None

    # Simple regex to find and replace 0.0.0.0/0 with a safer CIDR
    # This is a basic example - in production, you might want more sophisticated logic
    old_content = content
    new_content = content.replace('"0.0.0.0/0"', '"10.0.0.0/8"')  # Replace with private network range

    if new_content != old_content:
        return PatchSpec(
            file_path=file_path,
            description="Replace overly permissive security group CIDR with safer private network range",
            operations=[],
            new_content=new_content
        )

    return None

def generate_patch_for_missing_tags(content: str, file_path: str) -> Optional[PatchSpec]:
    """Generate patch to add missing tags to resources"""
    if "tags =" in content:
        return None  # Tags already exist

    # Simple heuristic: add tags block to EC2 instances and security groups
    # Find resource blocks
    resource_pattern = r'resource\s+"(aws_instance|aws_security_group)"\s+"[^"]+"\s+{([^}]*)}'

    def add_tags(match):
        resource_type = match.group(1)
        resource_body = match.group(2)

        # Add tags at the end of the resource block
        tags_block = '''\n  tags = {
    Environment = "dev"
    Project     = "demo"
  }'''

        return f'resource "{resource_type}" "{match.group(2)}" {{{resource_body}{tags_block}\n}}'

    # This regex replacement is overly simplified - it's very hard to do robust
    # Terraform parsing with regex. In a real implementation, you'd want to use
    # a proper Terraform parser or HCL parser.

    # For demo purposes, we'll do a simpler approach
    if 'resource "aws_instance"' in content and 'tags =' not in content:
        # Just add a comment for now - real implementation would need proper AST parsing
        comment_patch = "  # TODO: Add tags block with Environment and Project\n"
        new_content = content + comment_patch

        return PatchSpec(
            file_path=file_path,
            description="Add mandatory tags to EC2 instance resource",
            operations=[],
            new_content=new_content
        )

    return None

def generate_patch_for_s3_encryption(content: str, file_path: str) -> Optional[PatchSpec]:
    """Generate patch to enable S3 server-side encryption"""
    if "aws_s3_bucket" not in content or "server_side_encryption_configuration" in content:
        return None

    # Add encryption configuration
    encryption_block = '''
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }'''

    # Simple string addition - again, this is very basic
    new_content = content + encryption_block

    return PatchSpec(
        file_path=file_path,
        description="Enable server-side encryption for S3 bucket",
        operations=[],
        new_content=new_content
    )

async def run_ai_fix(fix_input: AIFixInput) -> AIFixResponse:
    """
    Generate patches for security findings

    For MVP, uses template-based fixes rather than true AI
    """
    logger.info(f"Generating AI fixes for {len(fix_input.findings)} findings")

    patches = []

    # Group findings by file
    findings_by_file = {}
    for finding in fix_input.findings:
        file_path = finding.file_path
        if file_path not in findings_by_file:
            findings_by_file[file_path] = []
        findings_by_file[file_path].append(finding)

    # Process each file
    for file_path, file_findings in findings_by_file.items():
        try:
            with open(file_path, 'r') as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")
            continue

        # Apply template fixes based on findings
        for finding in file_findings:
            patch = None

            if "security group" in finding.check_name.lower() and "0.0.0.0/0" in finding.description:
                patch = generate_patch_for_overly_permissive_sg(content, file_path)

            elif "tags" in finding.check_name.lower():
                patch = generate_patch_for_missing_tags(content, file_path)

            elif "s3" in finding.check_name.lower() and "encryption" in finding.check_name.lower():
                patch = generate_patch_for_s3_encryption(content, file_path)

            if patch:
                patches.append(patch)
                logger.info(f"Generated patch for {finding.check_name} in {file_path}")
            else:
                logger.info(f"No automatic patch available for {finding.check_name}")

    return AIFixResponse(
        success=True,
        message=f"Generated {len(patches)} patches for {len(fix_input.findings)} findings",
        patches=patches
    )
